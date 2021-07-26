#ifndef TAINT_TRACKING_INL_H
#define TAINT_TRACKING_INL_H

#include "v8/ast.capnp.h"
#include "v8/logrecord.capnp.h"

#include "src/taint_tracking.h"
#include "src/taint_tracking/ast_serialization.h"
#include "src/taint_tracking/object_versioner.h"

#include "src/base/platform/elapsed-timer.h"

// For the capnp library
#include <capnp/message.h>
#include <kj/std/iostream.h>

#include <memory>

/* Need to declare this for files that need to know the size of the Impl */
namespace tainttracking {


enum CheckType;
class ConcolicExecutor;
class ObjectVersioner;

enum FlushConfig {
  FORCE_FLUSH,
  LAZY_FLUSH
};

std::vector<std::tuple<TaintType, int>> InitTaintRanges(
    v8::internal::Handle<v8::internal::String> target);

void InitTaintInfo(
    const std::vector<std::tuple<TaintType, int>>& range_data,
    TaintLogRecord::TaintInformation::Builder* builder);

std::string Sha256StringAsHex(v8::internal::Handle<v8::internal::String> value);


class ObjectSnapshot {
public:

  static const int NO_SNAPSHOT = -1;

  ObjectSnapshot(v8::internal::Handle<v8::internal::Object> obj);
  ObjectSnapshot(
      int revision,
      v8::internal::Handle<v8::internal::Object> obj);

  int GetCurrentRevision() const;
  v8::internal::Handle<v8::internal::Object> GetObj() const;

private:
  int current_revision_;
  v8::internal::Handle<v8::internal::Object> obj_;
};


class TaggedObject {
public:

  const static int NO_ID = -1;

  TaggedObject(v8::internal::Handle<v8::internal::Object> sn, int uniqueid);

  int GetUniqueId() const;
  v8::internal::Handle<v8::internal::Object> GetObj() const;

private:
  v8::internal::Handle<v8::internal::Object> obj_;
  int unique_id_;
};


class RevisionDictionary {
public:

  RevisionDictionary();
  RevisionDictionary(
      v8::internal::Handle<v8::internal::NameDictionary> dict);
  RevisionDictionary(v8::internal::Isolate* isolate, int size);

  v8::internal::MaybeHandle<v8::internal::Object> Lookup(
      v8::internal::Handle<v8::internal::Name> key);

  void Put(v8::internal::Handle<v8::internal::Name>,
           v8::internal::Handle<v8::internal::Object>);

  bool IsValid();

private:
  v8::internal::Handle<v8::internal::NameDictionary> dict_;
};

class TaggedRevisedObject {
public:
  static const int NO_OBJECT_ID = -1;

  TaggedRevisedObject() = delete;
  TaggedRevisedObject(
      v8::internal::Handle<v8::internal::JSReceiver> rec,
      int unique_id,
      int revision,
      RevisionDictionary revisions);

  v8::internal::Handle<v8::internal::JSReceiver> GetTarget() const;
  int GetId() const;
  int GetVersion() const;
  const RevisionDictionary& GetRevisions() const;


private:
  v8::internal::Handle<v8::internal::JSReceiver> obj_;
  int unique_id_;
  int revision_;
  RevisionDictionary revisions_;
};


// This class exists to manage the lifetime of logged messages. Anything that
// needs to be allocated and destroyed with the message should be in a subclass
// of a message holder. Strings can be copied in and out of a
// StringCopierMessageHolder. This is necessary because the lifetime of the
// ::capnp::MallocMessageBuilder may require v8 objects or webkit objects that
// might be garbage collected or reclaimed by the time the actual logging
// happens.
class MessageHolder {
public:
  static const int NO_UNIQUE_ID = -1;

  MessageHolder();
  virtual ~MessageHolder();

  void DoSynchronousWrite(::kj::OutputStream& stream);

  ::TaintLogRecord::Builder GetRoot();
  ::TaintLogRecord::Builder InitRoot();

  template <typename T> typename T::Builder InitRootAs();
  template <typename T> typename T::Builder GetRootAs();

  // Cached methods
  template <typename Char>
  void CopyBuffer(::Ast::JsString::Builder builder,
                  const Char* str,
                  int length);

  Status WriteConcreteObject(
      ::Ast::JsObjectValue::Builder builder,
      ObjectSnapshot snapshot);

  Status WriteConcreteSmi(
      ::Ast::JsObjectValue::Builder builder,
      int value);

  void CopyJsObjectToStringSlow(
      ::Ast::JsString::Builder builder,
      v8::internal::Handle<v8::internal::Object> obj);


  // Non-cached methods
  void CopyJsStringSlow(
      ::Ast::JsString::Builder builder,
      v8::internal::Handle<v8::internal::String> str);

  void CopyJsStringSlow(
      ::Ast::JsString::Builder builder,
      v8::internal::String* str);

  Status WriteConcreteImmutableObjectSlow(
      ::Ast::JsObjectValue::Builder builder,
      TaggedObject snapshot);

  Status WriteConcreteReceiverSlow(
      ::Ast::JsObjectValue::Builder builder,
      TaggedRevisedObject snapshot);

  int GetDepth();

private:
  Status WriteReceiverSlow(
      ::Ast::JsObjectValue::Builder builder,
      TaggedRevisedObject value);

  ::capnp::MallocMessageBuilder builder_;
  int depth_;
};


template <class T> TaintFlag CheckTaint(T* object);

class TaintTracker::Impl {
  friend class TaintTracker;

public:

  void Initialize(v8::internal::Isolate* isolate);

  InstanceCounter NewInstance();
  int CountFullPage();

  bool IsLogging() const;
  bool HasHeartbeat() const;

  void OnRuntimeHook(
      v8::internal::Handle<v8::internal::Object> branch_condition,
      uint64_t label_const,
      int uid,
      CheckType check);

  static int64_t LogToFile(
    v8::internal::Isolate* isolate,
    MessageHolder& builder,
    FlushConfig conf = FlushConfig::LAZY_FLUSH);

  ConcolicExecutor& Exec();
  ObjectVersioner& Versioner();
  void DoFlushLog();

  virtual ~Impl();

  void PutCrossOriginMessageTable(
      v8::internal::Isolate* isolate,
      v8::internal::Handle<v8::internal::String> origin_taint,
      v8::internal::Handle<v8::internal::String> compare);

  v8::internal::MaybeHandle<v8::internal::FixedArray>
  GetCrossOriginMessageTable(
      v8::internal::Handle<v8::internal::String> ref);

private:

  // Public so that it can be read from ASM
  uint64_t message_counter_;

  Impl(bool enable_serializer, v8::internal::Isolate* isolate);

  ::kj::OutputStream& Log();
  std::ofstream& StdLog();

  int64_t LogToFileImpl(
      v8::internal::Isolate* isolate,
      MessageHolder& builder,
      FlushConfig conf);

  void ScheduleFlushLog(v8::internal::Isolate* isolate);

  void RegisterTaintListener(TaintListener* listener);
  void Trigger(const TaintInstanceInfo& info, v8::internal::Isolate* isolate);
  static std::string LogFileName();

  InstanceCounter symbolic_elem_counter_;

  std::ofstream log_;
  std::unique_ptr<::kj::std::StdOutputStream> kj_log_;
  std::unique_ptr<::kj::BufferedOutputStreamWrapper> buffered_log_;
  ::kj::Array<uint8_t> buffer_log_storage_;
  v8::base::ElapsedTimer last_message_flushed_;

  std::vector<std::unique_ptr<TaintListener>> listeners_;

  bool is_logging_;
  bool log_flush_scheduled_;
  bool has_heartbeat_;
  int unsent_messages_;
  std::mutex log_mutex_;

  static std::mutex isolate_counter_mutex_;
  static int isolate_counter_;

  ConcolicExecutor exec_;
  std::unique_ptr<ObjectVersioner> versioner_;
  v8::internal::Handle<v8::internal::ObjectHashTable>
  cross_origin_message_table_;
};

}

#endif

// Local Variables:
// mode: c++
// End:

