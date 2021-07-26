// This file has the main logic for taint tracking

// Taint tracking imports
#include "src/taint_tracking.h"
#include "src/taint_tracking-inl.h"
#include "src/taint_tracking/ast_serialization.h"
#include "src/taint_tracking/log_listener.h"
#include "src/taint_tracking/object_versioner.h"
#include "src/taint_tracking/picosha2.h"
#include "v8/logrecord.capnp.h"

// Other V8 imports
#include "src/ast/ast-expression-rewriter.h"
#include "src/ast/ast.h"
#include "src/base/bits.h"
#include "src/base/platform/platform.h"
#include "src/cancelable-task.h"
#include "src/factory.h"
#include "src/heap/heap.h"
#include "src/isolate.h"
#include "src/objects-inl.h"
#include "src/parsing/parser.h"
#include "src/string-stream.h"
#include "src/utils.h"
#include "src/v8.h"


#include <array>
#include <limits>
#include <memory>
#include <random>
#include <stdio.h>
#include <string.h>
#include <tuple>

// For the capnp library
#include <capnp/message.h>
#include <capnp/serialize.h>
#include <kj/std/iostream.h>



namespace v8 {
namespace internal {
const int64_t Name::DEFAULT_TAINT_INFO;
}
}

using namespace v8::internal;

namespace tainttracking {

// Increment this when changing memory layout for the effect to propagate to
// deserialized code
const int kTaintTrackingVersion = 15;

const int kPointerStrSize = 64;
const int kBitsPerByte = 8;
const int kStackTraceInfoSize = 4000;
const char kEnableHeaderLoggingName[] = "enableHeaderLogging";
const char kEnableBodyLoggingName[] = "enableBodyLogging";
const char kLoggingFilenamePrefix[] = "loggingFilenamePrefix";
const char kJobIdName[] = "jobId";
const char kJsTaintProperty[] = "taintStatus";
const char kJsIdProperty[] = "id";
const InstanceCounter kMaxCounterSnapshot = 1 << 16;

const v8::base::TimeDelta kMaxTimeBetweenFlushes =
    v8::base::TimeDelta::FromSeconds(10);

// Number of messages to queue before flushing the log stream.
const int kFlushMessageMax = 1000;
const int kLogBufferSize = 64 * MB;

int TaintTracker::Impl::isolate_counter_ = 0;
std::mutex TaintTracker::Impl::isolate_counter_mutex_;

std::unique_ptr<LogListener> global_log_listener;

class IsTaintedVisitor;
void InitTaintInfo(const std::vector<std::tuple<TaintType, int>>&,
                   TaintLogRecord::TaintInformation::Builder*);

void RegisterLogListener(std::unique_ptr<LogListener> listener) {
  global_log_listener = std::move(listener);
}

inline bool IsValidTaintType(TaintType type) {
  return (static_cast<uint8_t>(type) & TaintType::TAINT_TYPE_MASK) <=
    static_cast<uint8_t>(TaintType::MAX_TAINT_TYPE);
}

inline void CheckTaintError(TaintType type, String* object) {
#ifdef DEBUG
  if (!IsValidTaintType(type)) {
    Isolate* isolate = object->GetIsolate();

    std::unique_ptr<char[]> strval = object->ToCString();
    char stack_trace [kStackTraceInfoSize];
    FixedStringAllocator alloc(stack_trace, sizeof(stack_trace));
    StringStream stream(
        &alloc, StringStream::ObjectPrintMode::kPrintObjectConcise);
    isolate->PrintStack(&stream);

    std::cerr << "Taint tracking memory error: "
              << std::to_string(static_cast<uint8_t>(type)).c_str()
              << std::endl;
    std::cerr << "String length: " << object->length() << std::endl;
    std::cerr << "String type: " << object->map()->instance_type()
              << std::endl;
    std::cerr << "String value: " << strval.get() << std::endl;
    std::cerr << "JS Stack trace: " << stack_trace << std::endl;
    std::cerr << "String address: " << ((void*) object) << std::endl;
    FATAL("Taint Tracking Memory Error");
  }
#endif
}


class TaintVisitor {
public:
  TaintVisitor() : visitee_(nullptr), writeable_(false) {};
  TaintVisitor(bool writeable) : visitee_(nullptr), writeable_(writeable) {};

  virtual void Visit(const uint8_t* visitee,
                     TaintData* taint_info,
                     int offset,
                     int size) = 0;
  virtual void Visit(const uint16_t* visitee,
                     TaintData* taint_info,
                     int offset,
                     int size) = 0;

  template <class T>
  void run(T* source, int start, int len) {
    visitee_ = source;
    VisitIntoStringTemplate(source, start, len);
    // We don't want to recurse because the stack could overflow if there are
    // many ConsString's
    while (!visitee_stack_.empty()) {
      std::tuple<String*, int, int> back = visitee_stack_.back();
      visitee_stack_.pop_back();
      VisitIntoStringTemplate(
          std::get<0>(back), std::get<1>(back), std::get<2>(back));
    }
  }
protected:
  String* GetVisitee() { return visitee_; }

private:

  template <typename Char>
  void DoVisit(Char* visitee, TaintData* taint_info, int offset, int size) {
#ifdef DEBUG
    if (taint_info != nullptr && !writeable_) {
      for (int i = 0; i < size; i++) {
        CheckTaintError(
            static_cast<TaintType>(*(taint_info + offset + i)),
            GetVisitee());
      }
    }
#endif
    Visit(visitee, taint_info, offset, size);
  }

  template <class T>
  void VisitIntoStringTemplate(T* source, int from, int len);

  std::vector<std::tuple<String*, int, int>> visitee_stack_;
  String* visitee_;
  bool writeable_;
};

MessageHolder::MessageHolder() : builder_(), depth_(0) {};
MessageHolder::~MessageHolder() {}
::TaintLogRecord::Builder MessageHolder::GetRoot() {
  return builder_.getRoot<TaintLogRecord>();
}
::TaintLogRecord::Builder MessageHolder::InitRoot() {
  return builder_.initRoot<TaintLogRecord>();
}

void MessageHolder::DoSynchronousWrite(::kj::OutputStream& stream) {
  capnp::writeMessage(stream, builder_);
}

template <typename Char>
void MessageHolder::CopyBuffer(::Ast::JsString::Builder builder,
                               const Char* str,
                               int length) {
  if (FLAG_taint_tracking_enable_concolic_no_marshalling) {
    return;
  }

  auto segments = builder.initSegments(1);
  auto flat = segments[0];
  flat.setContent(::capnp::Data::Reader(
                      reinterpret_cast<const uint8_t*>(str),
                      sizeof(Char) * length));
  flat.setIsOneByte(sizeof(Char) == 1);
}

template void MessageHolder::CopyBuffer<uint8_t>(
    ::Ast::JsString::Builder builder, const uint8_t* str, int length);
template void MessageHolder::CopyBuffer<uint16_t>(
    ::Ast::JsString::Builder builder, const uint16_t* str, int length);

class StringCopier : public TaintVisitor {
public:
  void Visit(const uint8_t* visitee,
             TaintData* taint_info,
             int offset,
             int size) override {
    segments_.push_back(std::make_tuple(visitee + offset, true, size));
  };
  void Visit(const uint16_t* visitee,
             TaintData* taint_info,
             int offset,
             int size) override {
    segments_.push_back(
        std::make_tuple(reinterpret_cast<const uint8_t*>(visitee + offset),
                        false,
                        size * sizeof(uint16_t)));
  };

  void Build(::Ast::JsString::Builder builder) {
    auto contents = builder.initSegments(segments_.size());
    for (int i = 0; i < segments_.size(); i++) {
      auto& segment = segments_[i];
      auto out_content = contents[i];
      out_content.setContent(::capnp::Data::Reader(
                                 std::get<0>(segment), std::get<2>(segment)));
      out_content.setIsOneByte(std::get<1>(segment));
    }
  }

private:
  std::vector<std::tuple<const uint8_t*, bool, int>> segments_;
};

void MessageHolder::CopyJsStringSlow(
    ::Ast::JsString::Builder builder,
    v8::internal::Handle<v8::internal::String> str) {
  if (FLAG_taint_tracking_enable_concolic_no_marshalling) {
    return;
  }

  StringCopier copier;
  {
    DisallowHeapAllocation no_gc;
    copier.run(*str, 0, str->length());
  }
  copier.Build(builder);
}

void MessageHolder::CopyJsStringSlow(
    ::Ast::JsString::Builder builder,
    v8::internal::String* str) {
  if (FLAG_taint_tracking_enable_concolic_no_marshalling) {
    return;
  }

  StringCopier copier;
  copier.run(str, 0, str->length());
  copier.Build(builder);
}

void MessageHolder::CopyJsObjectToStringSlow(
    ::Ast::JsString::Builder obj_builder,
    Handle<Object> obj) {
  if (FLAG_taint_tracking_enable_concolic_no_marshalling) {
    return;
  }

  if (obj->IsHeapObject()) {
    CopyJsStringSlow(
        obj_builder,
        Object::ToString(
            Handle<HeapObject>::cast(obj)->GetIsolate(), obj)
        .ToHandleChecked());
  } else {
    DCHECK(obj->IsSmi());
    auto out_content = obj_builder.initSegments(1)[0];
    std::string as_str = std::to_string(Smi::cast(*obj)->value());
    out_content.setContent(
        ::capnp::Data::Reader(
            reinterpret_cast<const uint8_t*>(as_str.c_str()), as_str.size()));
    out_content.setIsOneByte(true);
  }
}

int MessageHolder::GetDepth() {
  return depth_;
}

template <typename T>
typename T::Builder MessageHolder::InitRootAs() {
  return builder_.initRoot<T>();
}

template <typename T>
typename T::Builder MessageHolder::GetRootAs() {
  return builder_.getRoot<T>();
}

template ::TaintLogRecord::SymbolicValue::Builder MessageHolder::InitRootAs<::TaintLogRecord::SymbolicValue>();
template ::TaintLogRecord::SymbolicValue::Builder MessageHolder::GetRootAs<::TaintLogRecord::SymbolicValue>();


class LogTaintTask : public v8::Task {
public:
  LogTaintTask(Isolate* isolate) :
    isolate_(isolate) {}

  void Run() override {
    TaintTracker::FromIsolate(isolate_)->Get()->DoFlushLog();
  }

private:
  Isolate* isolate_;
};


class JsObjectSerializer : public ObjectOwnPropertiesVisitor {
public:
  JsObjectSerializer(::Ast::JsReceiver::Builder builder,
                     MessageHolder& holder) :
    builder_(builder), holder_(holder) {}

  virtual bool VisitKeyValue(Handle<String> key, Handle<Object> value) {
    keys_ = ArrayList::Add(keys_, key);
    values_ = ArrayList::Add(values_, value);
    return false;
  }

  void Run(Handle<JSReceiver> value) {
    Isolate* isolate = value->GetIsolate();
    keys_ = Handle<ArrayList>::cast(isolate->factory()->NewFixedArray(0));
    values_ = Handle<ArrayList>::cast(isolate->factory()->NewFixedArray(0));
    builder_.setType(value->IsJSArray()
                     ? Ast::JsReceiver::Type::ARRAY
                     : Ast::JsReceiver::Type::OBJECT);
    Visit(value);
    PostProcess();
  }

  void PostProcess() {
    static const int MAX_RECURSION_DEPTH = 0;

    int size = keys_->Length();
    DCHECK_EQ(keys_->Length(), values_->Length());
    auto keyvals_list = builder_.initKeyValues(size);

    for (int i = 0; i < size; i++) {
      auto kv_builder = keyvals_list[i];
      String* key = String::cast(keys_->Get(i));
      DCHECK(key->IsString());
      Isolate* isolate = key->GetIsolate();
      Handle<String> key_handle (key, isolate);
      holder_.WriteConcreteObject(
          kv_builder.initKey(), ObjectSnapshot(key_handle));

      auto value_builder = kv_builder.initValue();
      Handle<Object> value = handle(values_->Get(i), isolate);
      if (holder_.GetDepth() > MAX_RECURSION_DEPTH &&
          value->IsJSReceiver()) {
        value_builder.getValue().setUnserializedObject();
      } else {
        if (!holder_.WriteConcreteObject(value_builder, value)) {
          value_builder.getValue().setUnknown();
        }
      }
    }
  }

private:
  ::Ast::JsReceiver::Builder builder_;
  MessageHolder& holder_;
  Handle<ArrayList> keys_;     // Array of keys of type String
  Handle<ArrayList> values_;   // Array of values of type Object
};


Status MessageHolder::WriteReceiverSlow(
    ::Ast::JsObjectValue::Builder builder,
    TaggedRevisedObject value) {
  static const int INITIAL_OBJECT_PROPERTY_MAP_SIZE = 10;

  Handle<JSReceiver> as_receiver = value.GetTarget();
  Isolate* isolate = as_receiver->GetIsolate();
  auto which_value = builder.getValue();

  depth_ += 1;
  JsObjectSerializer serializer (which_value.initReceiver(), *this);
  serializer.Run(as_receiver);
  builder.setUniqueId(value.GetId());
  depth_ -= 1;

  return Status::OK;
}


Status MessageHolder::WriteConcreteObject(
    ::Ast::JsObjectValue::Builder builder,
    ObjectSnapshot snapshot) {
  if (FLAG_taint_tracking_enable_concolic_no_marshalling) {
    return Status::OK;
  }

  auto obj = snapshot.GetObj();
  if (obj->IsHeapObject()) {
    return ObjectVersioner::FromIsolate(
        Handle<HeapObject>::cast(obj)->GetIsolate()).MaybeSerialize(
            snapshot, builder, *this);
  } else {
    return WriteConcreteSmi(builder, Smi::cast(*obj)->value());
  }
}


Status MessageHolder::WriteConcreteReceiverSlow(
    ::Ast::JsObjectValue::Builder builder,
    TaggedRevisedObject snapshot) {
  auto obj = snapshot.GetTarget();

  InstanceType type = obj->map()->instance_type();
  switch (type) {
    case JS_REGEXP_TYPE: {
      builder.setUniqueId(snapshot.GetId());

      Handle<JSRegExp> as_regex = Handle<JSRegExp>::cast(obj);
      auto out_reg = builder.getValue().initRegexp();
      {
        DisallowHeapAllocation no_gc;
        Object* source = as_regex->source();
        if (source->IsString()) {
          CopyJsStringSlow(out_reg.initSource(), String::cast(source));
        }
      }
      if (as_regex->data()->IsFixedArray()) {
        std::vector<::Ast::RegExp::Flag> cp_flags;
        JSRegExp::Flags flags = as_regex->GetFlags();
        if (flags & JSRegExp::Flag::kGlobal) {
          cp_flags.push_back(::Ast::RegExp::Flag::GLOBAL);
        }
        if (flags & JSRegExp::Flag::kIgnoreCase) {
          cp_flags.push_back(::Ast::RegExp::Flag::IGNORE_CASE);
        }
        if (flags & JSRegExp::Flag::kMultiline) {
          cp_flags.push_back(::Ast::RegExp::Flag::MULTILINE);
        }
        if (flags & JSRegExp::Flag::kSticky) {
          cp_flags.push_back(::Ast::RegExp::Flag::STICKY);
        }
        if (flags & JSRegExp::Flag::kUnicode) {
          cp_flags.push_back(::Ast::RegExp::Flag::UNICODE);
        }

        auto out_flags = out_reg.initFlags(cp_flags.size());
        for (int i = 0; i < cp_flags.size(); i++) {
          out_flags.set(i, cp_flags[i]);
        }
      }

      return WriteReceiverSlow(out_reg.initReceiver(), snapshot);
    }
      break;

    case JS_FUNCTION_TYPE: {
      Handle<JSFunction> as_function = Handle<JSFunction>::cast(obj);
      Isolate* isolate = as_function->GetIsolate();
      builder.setUniqueId(snapshot.GetId());
      auto fn = builder.getValue().initFunction();
      Handle<SharedFunctionInfo> shared = handle(
          as_function->shared(), isolate);
      CopyJsStringSlow(fn.initName(), shared->DebugName());
      fn.setStartPosition(shared->start_position());
      fn.setEndPosition(shared->end_position());
      Handle<Object> maybe_script (shared->script(), isolate);
      if (maybe_script->IsScript()) {
        Handle<Script> script = Handle<Script>::cast(maybe_script);
        if (!WriteConcreteObject(fn.initScriptName(),
                                 handle(script->name(), isolate))) {
          return Status::FAILURE;
        }
        fn.setScriptId(script->id());
      }

      auto fn_type = fn.getType();
      Handle<Code> code = handle(shared->code(), isolate);
      if (!shared->taint_node_label()->IsUndefined(isolate)) {
        V8NodeLabelSerializer dser(isolate);
        NodeLabel label;
        DCHECK(dser.Deserialize(shared->taint_node_label(), &label));
        BuilderSerializer ser;
        DCHECK(ser.Serialize(fn.initFnLabel(), label));
      }

      if (code->kind() == Code::Kind::BUILTIN) {
        int builtin_idx = code->builtin_index();
        DCHECK(builtin_idx < Builtins::Name::builtin_count &&
               builtin_idx >= 0 &&
               (Code::cast(
                   isolate->builtins()->builtin(
                       static_cast<Builtins::Name>(builtin_idx))) ==
                *code) &&
               code->kind() == Code::Kind::BUILTIN);
        auto builtin_builder = fn_type.initBuiltinFunction();
        builtin_builder.setId(code->builtin_index());
        builtin_builder.setName(isolate->builtins()->name(builtin_idx));
      } else if (shared->IsApiFunction()) {
        auto api_builder = fn_type.initApiFunction();
        Handle<Object> serial_num = handle(
            shared->get_api_func_data()->serial_number(), isolate);
        DCHECK(serial_num->IsSmi());
        api_builder.setSerialNumber(Smi::cast(*serial_num)->value());
        // TODO: init via api?
      }

      return WriteReceiverSlow(fn.initReceiver(), snapshot);
    }
      break;

    default:
      return WriteReceiverSlow(builder, snapshot);
  }
}


Status MessageHolder::WriteConcreteImmutableObjectSlow(
    ::Ast::JsObjectValue::Builder builder,
    TaggedObject snapshot) {

  Handle<Object> value = snapshot.GetObj();
  DCHECK(value->IsHeapObject() && !value->IsJSReceiver());

  auto out_val = builder.getValue();
  Handle<HeapObject> as_heap_obj = Handle<HeapObject>::cast(value);
  InstanceType type = as_heap_obj->map()->instance_type();
  builder.setUniqueId(snapshot.GetUniqueId());
  if (type < FIRST_NONSTRING_TYPE) {
    CopyJsStringSlow(out_val.initString(), Handle<String>::cast(value));
  } else {
    switch (type) {
      case HEAP_NUMBER_TYPE:
        out_val.setNumber(Handle<HeapNumber>::cast(value)->value());
        break;

      case ODDBALL_TYPE: {
        Isolate* isolate = as_heap_obj->GetIsolate();
        if (value->IsFalse(isolate)) {
          out_val.setBoolean(false);
        } else if (value->IsTrue(isolate)) {
          out_val.setBoolean(true);
        } else if (value->IsUndefined(isolate)) {
          out_val.setUndefined();
        } else if (value->IsNull(isolate)) {
          out_val.setNullObject();
        } else {
          out_val.setUnknown();
          return Status::FAILURE;
        }
      }
        break;

      case SYMBOL_TYPE: {
        Isolate* isolate = as_heap_obj->GetIsolate();
        Handle<String> to_str = Object::ToString(
            isolate,
            handle(Handle<Symbol>::cast(value)->name(), isolate)).
          ToHandleChecked();
        CopyJsStringSlow(out_val.initSymbol(), to_str);
      }
        break;

      default:
        out_val.setUnknown();
        return Status::FAILURE;
    }
  }
  return Status::OK;
}


Status MessageHolder::WriteConcreteSmi(
    Ast::JsObjectValue::Builder builder, int value) {
  builder.getValue().setSmi(value);
  builder.setUniqueId(NO_UNIQUE_ID);
  return Status::OK;
}


// static
int64_t TaintTracker::Impl::LogToFile(
    Isolate* isolate,
    MessageHolder& builder,
    FlushConfig conf) {
  TaintTracker::Impl* impl = TaintTracker::FromIsolate(isolate)->Get();
  auto log_message = builder.GetRoot();
  if (global_log_listener) {
    global_log_listener->OnLog(log_message.asReader());
  }
  log_message.setIsolate(reinterpret_cast<uint64_t>(isolate));
  builder.WriteConcreteObject(
      log_message.initContextId(),
      ObjectSnapshot(
          handle(
              isolate->context()->native_context()->taint_tracking_context_id(),
              isolate)));
  return impl->LogToFileImpl(isolate, builder, conf);
}

int64_t TaintTracker::Impl::LogToFileImpl(
    Isolate* isolate,
    MessageHolder& builder,
    FlushConfig conf) {
  if (!IsLogging()) {
    return NO_MESSAGE;
  }
  auto log_message = builder.GetRoot();
  uint64_t msg_id = message_counter_++;
  log_message.setMessageId(msg_id);

  {
    std::lock_guard<std::mutex> guard(log_mutex_);
    builder.DoSynchronousWrite(*buffered_log_);
  }

  if (unsent_messages_ > kFlushMessageMax ||
      conf == FORCE_FLUSH ||
      last_message_flushed_.HasExpired(kMaxTimeBetweenFlushes)) {
    ScheduleFlushLog(isolate);
    last_message_flushed_.Restart();
  } else {
    unsent_messages_ += 1;
  }

  return msg_id;
}


void TaintTracker::Impl::ScheduleFlushLog(v8::internal::Isolate* isolate) {
  std::lock_guard<std::mutex> guard(log_mutex_);
  if (!log_flush_scheduled_) {
    V8::GetCurrentPlatform()->CallOnBackgroundThread(
        new LogTaintTask(isolate), v8::Platform::kShortRunningTask);
    log_flush_scheduled_ = true;
  }
}

void TaintTracker::Impl::DoFlushLog() {
  std::lock_guard<std::mutex> guard(log_mutex_);
  DCHECK(IsLogging());
  buffered_log_->flush();
  log_.flush();
  log_flush_scheduled_ = false;
}

bool AllowDeserializingCode() {
  return !FLAG_taint_tracking_enable_ast_modification;
}

uint32_t LayoutVersionHash() {
  return (kTaintTrackingVersion);
}

inline TaintFlag MaskForType(TaintType type) {
  return (type & TaintType::TAINT_TYPE_MASK) == TaintType::UNTAINTED ?
    kTaintFlagUntainted :
    static_cast<TaintFlag>(1 << static_cast<uint8_t>(type - 1));
}

TaintFlag AddFlag(
    TaintFlag current, TaintType new_value, String* object) {
  CheckTaintError(new_value, object);
  return current | MaskForType(new_value);
}

bool TestFlag(TaintFlag flag, TaintType type) {
  return (MaskForType(type) & flag) != 0;
}

TaintType TaintFlagToType(TaintFlag flag) {
  if (flag == kTaintFlagUntainted) {
    return TaintType::UNTAINTED;
  }
  return v8::base::bits::IsPowerOfTwo32(flag) ?
    static_cast<TaintType>(WhichPowerOf2(flag) + 1) :
    TaintType::MULTIPLE_TAINTS;
}

std::string TaintTypeToString(TaintType type) {
  switch (type){
    case TaintType::UNTAINTED:
      return "Untainted";
    case TaintType::TAINTED:
      return "Tainted";
    case TaintType::COOKIE:
      return "Cookie";
    case TaintType::MESSAGE:
      return "Message";
    case TaintType::URL:
      return "Url";
    case TaintType::DOM:
      return "Dom";
    case TaintType::REFERRER:
      return "Referrer";
    case TaintType::WINDOWNAME:
      return "WindowName";
    case TaintType::STORAGE:
      return "Storage";
    case TaintType::NETWORK:
      return "Network";
    case TaintType::MULTIPLE_TAINTS:
      return "MultipleTaints";
    case TaintType::MAX_TAINT_TYPE:
    default:
      return "UnknownTaintError:" + std::to_string(
          static_cast<uint8_t>(type));
  }
}

::TaintLogRecord::TaintEncoding TaintTypeToRecordEncoding(TaintType type) {
  switch (type & TaintType::ENCODING_TYPE_MASK) {
    case TaintType::NO_ENCODING:
      return TaintLogRecord::TaintEncoding::NONE;
    case TaintType::URL_ENCODED:
      return TaintLogRecord::TaintEncoding::URL_ENCODED;
    case TaintType::URL_COMPONENT_ENCODED:
      return TaintLogRecord::TaintEncoding::URL_COMPONENT_ENCODED;
    case TaintType::ESCAPE_ENCODED:
      return TaintLogRecord::TaintEncoding::ESCAPE_ENCODED;
    case TaintType::MULTIPLE_ENCODINGS:
      return TaintLogRecord::TaintEncoding::MULTIPLE_ENCODINGS;
    case TaintType::URL_DECODED:
      return TaintLogRecord::TaintEncoding::URL_DECODED;
    case TaintType::URL_COMPONENT_DECODED:
      return TaintLogRecord::TaintEncoding::URL_COMPONENT_DECODED;
    case TaintType::ESCAPE_DECODED:
      return TaintLogRecord::TaintEncoding::ESCAPE_DECODED;
    default:
      return TaintLogRecord::TaintEncoding::UNKNOWN;
  }
}

::TaintLogRecord::TaintType TaintTypeToRecordEnum(TaintType type) {
  switch (type & TaintType::TAINT_TYPE_MASK) {
    case TaintType::UNTAINTED:
      return TaintLogRecord::TaintType::UNTAINTED;
    case TaintType::TAINTED:
      return TaintLogRecord::TaintType::TAINTED;
    case TaintType::COOKIE:
      return TaintLogRecord::TaintType::COOKIE;
    case TaintType::MESSAGE:
      return TaintLogRecord::TaintType::MESSAGE;
    case TaintType::URL:
      return TaintLogRecord::TaintType::URL;
    case TaintType::URL_HASH:
      return TaintLogRecord::TaintType::URL_HASH;
    case TaintType::URL_PROTOCOL:
      return TaintLogRecord::TaintType::URL_PROTOCOL;
    case TaintType::URL_HOST:
      return TaintLogRecord::TaintType::URL_HOST;
    case TaintType::URL_HOSTNAME:
      return TaintLogRecord::TaintType::URL_HOSTNAME;
    case TaintType::URL_ORIGIN:
      return TaintLogRecord::TaintType::URL_ORIGIN;
    case TaintType::URL_PORT:
      return TaintLogRecord::TaintType::URL_PORT;
    case TaintType::URL_PATHNAME:
      return TaintLogRecord::TaintType::URL_PATHNAME;
    case TaintType::URL_SEARCH:
      return TaintLogRecord::TaintType::URL_SEARCH;
    case TaintType::DOM:
      return TaintLogRecord::TaintType::DOM;
    case TaintType::REFERRER:
      return TaintLogRecord::TaintType::REFERRER;
    case TaintType::WINDOWNAME:
      return TaintLogRecord::TaintType::WINDOWNAME;
    case TaintType::STORAGE:
      return TaintLogRecord::TaintType::STORAGE;
    case TaintType::NETWORK:
      return TaintLogRecord::TaintType::NETWORK;
    case TaintType::MULTIPLE_TAINTS:
      return TaintLogRecord::TaintType::MULTIPLE_TAINTS;


    case TaintType::MAX_TAINT_TYPE:
    default:
      return TaintLogRecord::TaintType::ERROR;
  }
}

TaintLogRecord::SymbolicOperation
SymbolicTypeToEnum(SymbolicType type) {
  switch(type) {
    case CONCAT:
      return TaintLogRecord::SymbolicOperation::CONCAT;
    case SLICE:
      return TaintLogRecord::SymbolicOperation::SLICE;
    case LITERAL:
      return TaintLogRecord::SymbolicOperation::LITERAL;
    case EXTERNAL:
      return TaintLogRecord::SymbolicOperation::EXTERNAL;
    case PARSED_JSON:
      return TaintLogRecord::SymbolicOperation::PARSED_JSON;
    case STRINGIFIED_JSON:
      return TaintLogRecord::SymbolicOperation::STRINGIFIED_JSON;
    case REGEXP:
      return TaintLogRecord::SymbolicOperation::REGEXP;
    case JOIN:
      return TaintLogRecord::SymbolicOperation::JOIN;
    case CASE_CHANGE:
      return TaintLogRecord::SymbolicOperation::CASE_CHANGE;
    case URI_ENCODE:
      return TaintLogRecord::SymbolicOperation::URI_ENCODE;
    case URI_DECODE:
      return TaintLogRecord::SymbolicOperation::URI_DECODE;
    case URI_ESCAPE:
      return TaintLogRecord::SymbolicOperation::URI_ESCAPE;
    case URI_UNESCAPE:
      return TaintLogRecord::SymbolicOperation::URI_UNESCAPE;
    case INCREMENTAL_BUILD:
      return TaintLogRecord::SymbolicOperation::INCREMENTAL_BUILD;
    case URI_COMPONENT_DECODE:
      return TaintLogRecord::SymbolicOperation::URI_COMPONENT_DECODE;
    case URI_COMPONENT_ENCODE:
      return TaintLogRecord::SymbolicOperation::URI_COMPONENT_ENCODE;
  }
}

std::string TaintFlagToString(TaintFlag flag) {
  std::ostringstream output;
  bool started = false;
  int found = 0;
  for (int i = TaintType::TAINTED;
       i < static_cast<uint8_t>(TaintType::MAX_TAINT_TYPE); i++) {
    TaintType type = static_cast<TaintType>(i);
    if (TestFlag(flag, type)) {
      if (started) {
        output << "&";
      } else {
        started = true;
      }
      output << TaintTypeToString(type);
      found += 1;
    }
  }
  if (found == 0) {
    return TaintTypeToString(TaintType::UNTAINTED);
  }
  return output.str();
}

template <class T>
TaintData* StringTaintData(T* str);
template <> TaintData* StringTaintData<SeqOneByteString>(
    SeqOneByteString* str) {
  return str->GetTaintChars();
}
template <> TaintData* StringTaintData<SeqTwoByteString>(
    SeqTwoByteString* str) {
  return str->GetTaintChars();
}
template <> TaintData* StringTaintData<ExternalOneByteString>(
    ExternalOneByteString* str) {
  return str->resource()->GetTaintChars();
}
template <> TaintData* StringTaintData<ExternalTwoByteString>(
    ExternalTwoByteString* str) {
  return str->resource()->GetTaintChars();
}

template <class T>
TaintData* StringTaintData_TryAllocate(T* str) {
  TaintData* answer = StringTaintData(str);
  if (answer == nullptr) {
    int len = str->length();
    answer = str->resource()->InitTaintChars(len);
    memset(answer, TaintType::UNTAINTED, len);
  }
  return answer;
}

template<> TaintData* GetWriteableStringTaintData<SeqOneByteString>(
    SeqOneByteString* str) {
  return StringTaintData(str);
}
template<> TaintData* GetWriteableStringTaintData<SeqTwoByteString>(
    SeqTwoByteString* str) {
  return StringTaintData(str);
}
template<> TaintData* GetWriteableStringTaintData<ExternalOneByteString>(
    ExternalOneByteString* str) {
  return StringTaintData_TryAllocate(str);
}
template<> TaintData* GetWriteableStringTaintData<ExternalTwoByteString>(
    ExternalTwoByteString* str) {
  return StringTaintData_TryAllocate(str);
}
template<> TaintData* GetWriteableStringTaintData<SeqString>(SeqString* str) {
  if (str->IsSeqOneByteString()) {
    return GetWriteableStringTaintData(SeqOneByteString::cast(str));
  } else {
    return GetWriteableStringTaintData(SeqTwoByteString::cast(str));
  }
}

void MarkNewString(String* str) {
  Isolate* isolate = str->GetIsolate();
  str->set_taint_info(0);
}

template <class T> void InitTaintSeqByteString(T* str, TaintType type) {
  TaintData* data = StringTaintData(str);
  memset(data, type, str->length());
  MarkNewString(str);
}

template<> void InitTaintData<SeqOneByteString>(
    SeqOneByteString* str, TaintType type) {
  InitTaintSeqByteString(str, type);
}
template<> void InitTaintData<SeqTwoByteString>(
    SeqTwoByteString* str, TaintType type) {
  InitTaintSeqByteString(str, type);
}
template<> void InitTaintData<SeqString>(SeqString* str, TaintType type) {
  if (str->IsSeqOneByteString()) {
    InitTaintData(SeqOneByteString::cast(str), type);
  } else {
    InitTaintData(SeqTwoByteString::cast(str), type);
  }
}

template <> void TaintVisitor::VisitIntoStringTemplate<ConsString>(
    ConsString* source, int from_offset, int from_len) {
  String* first = source->first();
  int first_len = first->length();
  if (from_offset < first_len) {
    if (from_len + from_offset <= first_len) {
      visitee_stack_.push_back(std::make_tuple(
                                   first, from_offset, from_len));
    } else {
      int copy_first = first_len - from_offset;
      // Make sure that the second element is pushed first so that the
      // first element will be the first to execute.
      visitee_stack_.push_back(
          std::make_tuple(
              source->second(), 0, from_len - copy_first));
      visitee_stack_.push_back(std::make_tuple(
                                   first, from_offset, copy_first));
    }
  } else {
    visitee_stack_.push_back(
        std::make_tuple(
            source->second(), from_offset - first_len, from_len));
  }
}

template <> void TaintVisitor::VisitIntoStringTemplate<SlicedString>(
    SlicedString* source, int from_offset, int from_len) {
  visitee_stack_.push_back(
      std::make_tuple(
          source->parent(), from_offset + source->offset(), from_len));
}

template <> void TaintVisitor::VisitIntoStringTemplate<SeqOneByteString>(
    SeqOneByteString* source, int from, int len) {
  DCHECK_GE(from, 0);
  DCHECK_GE(len, 0);
  DCHECK_LE(from + len, source->length());
  DoVisit(source->GetChars(), StringTaintData(source), from, len);
}

template <> void TaintVisitor::VisitIntoStringTemplate<SeqTwoByteString>(
    SeqTwoByteString* source, int from, int len) {
  DCHECK_GE(from, 0);
  DCHECK_GE(len, 0);
  DCHECK_LE(from + len, source->length());
  DoVisit(source->GetChars(), StringTaintData(source), from, len);
}

template <> void TaintVisitor::VisitIntoStringTemplate<ExternalOneByteString>(
    ExternalOneByteString* source, int from, int len) {
  DCHECK_GE(from, 0);
  DCHECK_GE(len, 0);
  DCHECK_LE(from + len, source->length());
  TaintData* data;
  if (writeable_) {
    data = StringTaintData_TryAllocate(source);
  } else {
    data = StringTaintData(source);
  }
  DoVisit(source->GetChars(), data, from, len);
}

template <> void TaintVisitor::VisitIntoStringTemplate<ExternalTwoByteString>(
    ExternalTwoByteString* source, int from, int len) {
  DCHECK_GE(from, 0);
  DCHECK_GE(len, 0);
  DCHECK_LE(from + len, source->length());
  TaintData* data;
  if (writeable_) {
    data = StringTaintData_TryAllocate(source);
  } else {
    data = StringTaintData(source);
  }
  DoVisit(source->GetChars(), data, from, len);
}

template <> void TaintVisitor::VisitIntoStringTemplate<ExternalString>(
    ExternalString* source, int from, int len) {
  if (source->IsExternalOneByteString()) {
    return VisitIntoStringTemplate(
        ExternalOneByteString::cast(source), from, len);
  } else {
    DCHECK(source->IsExternalTwoByteString());
    return VisitIntoStringTemplate(
        ExternalTwoByteString::cast(source), from, len);
  }
}

template <> void TaintVisitor::VisitIntoStringTemplate<SeqString>(
    SeqString* source, int from, int len) {
  if (source->IsSeqOneByteString()) {
    return VisitIntoStringTemplate(
        SeqOneByteString::cast(source), from, len);
  } else {
    DCHECK(source->IsSeqTwoByteString());
    return VisitIntoStringTemplate(
        SeqTwoByteString::cast(source), from, len);
  }
}

template <> void TaintVisitor::VisitIntoStringTemplate<String>(
    String* source, int from_offset, int from_len) {
  StringShape shape(source);
  if (shape.IsCons()) {
    VisitIntoStringTemplate(
        ConsString::cast(source), from_offset, from_len);
  } else if (shape.IsSliced()) {
    VisitIntoStringTemplate(
        SlicedString::cast(source), from_offset, from_len);
  } else if (shape.IsExternalOneByte()) {
    VisitIntoStringTemplate(
        ExternalOneByteString::cast(source), from_offset, from_len);
  } else if (shape.IsExternalTwoByte()) {
    VisitIntoStringTemplate(
        ExternalTwoByteString::cast(source), from_offset, from_len);
  } else if (shape.IsSequentialOneByte()) {
    VisitIntoStringTemplate(
        SeqOneByteString::cast(source), from_offset, from_len);
  } else if (shape.IsSequentialTwoByte()) {
    VisitIntoStringTemplate(
        SeqTwoByteString::cast(source), from_offset, from_len);
  } else {
    FATAL("Taint Tracking Unreachable");
  }
}

class Sha256Visitor : public TaintVisitor {
public:
  Sha256Visitor() {}

  void Visit(const uint8_t* visitee,
             TaintData* taint_info,
             int offset,
             int size) override {
    const uint8_t* start = visitee + offset;
    hasher_.process(start, start + size);
  }

  void Visit(const uint16_t* visitee,
             TaintData* taint_info,
             int offset,
             int size) override {
    const uint16_t* start = visitee + offset;
    hasher_.process(reinterpret_cast<const uint8_t*>(start),
                    reinterpret_cast<const uint8_t*>(start + size));
  }

  std::string GetResult() {
    hasher_.finish();
    return picosha2::get_hash_hex_string(hasher_);
  }

private:
  picosha2::hash256_one_by_one hasher_;
};


std::string Sha256StringAsHex(Handle<String> value) {
  Sha256Visitor visitor;
  {
    DisallowHeapAllocation no_gc;
    visitor.run(*value, 0, value->length());
  }
  return visitor.GetResult();
}


class CopyVisitor : public TaintVisitor {
public:
  CopyVisitor(TaintData* dest) : already_copied_(0), dest_(dest) {};

  void Visit(const uint8_t* visitee,
             TaintData* taint_info,
             int offset,
             int size) override {
    VisitInline(taint_info, offset, size);
  }
  void Visit(const uint16_t* visitee,
             TaintData* taint_info,
             int offset,
             int size) override {
    VisitInline(taint_info, offset, size);
  }

private:
  inline void VisitInline(TaintData* taint_info, int offset, int size) {
    if (taint_info) {
      MemCopy(dest_ + already_copied_, taint_info + offset, size);
    } else {
      memset(dest_ + already_copied_,
             static_cast<TaintData>(TaintType::UNTAINTED), size);
    }
    already_copied_ += size;
  }

  int already_copied_;
  TaintData* dest_;
};

class IsTaintedVisitor : public TaintVisitor {
public:
  IsTaintedVisitor() :
    flag_(static_cast<TaintFlag>(TaintType::UNTAINTED)),
    prev_type_(TaintType::UNTAINTED),
    already_written_(0) {};

  void Visit(const uint8_t* visitee,
             TaintData* taint_info,
             int offset,
             int size) override {
    VisitInline(taint_info, offset, size);
  }
  void Visit(const uint16_t* visitee,
             TaintData* taint_info,
             int offset,
             int size) override {
    VisitInline(taint_info, offset, size);
  }

  int Size() const {
    return already_written_;
  }

  TaintFlag GetFlag() const {
    return flag_;
  }

  std::vector<std::tuple<TaintType, int>> GetRanges() {
    return taint_ranges_;
  }

private:
  inline void VisitInline(TaintData* taint_info, int offset, int size) {
    if (taint_info == nullptr) {
      already_written_ += size;
      if (size != 0) {
        prev_type_ = TaintType::UNTAINTED;
      }
      return;
    }

    TaintData* start = taint_info + offset;
    for (TaintData* t = start; t < start + size; t++) {
      TaintType type = static_cast<TaintType>(*t);
      if (type != prev_type_) {
        taint_ranges_.push_back(
            std::make_tuple(type, already_written_));
      }
      prev_type_ = type;
      flag_ = AddFlag(flag_, type, GetVisitee());
      already_written_++;
    }
  }

  TaintFlag flag_;
  TaintType prev_type_;
  std::vector<std::tuple<TaintType, int>> taint_ranges_;
  int already_written_;
};


template <class T> TaintFlag CheckTaint(T* object) {
  IsTaintedVisitor visitor;
  visitor.run(object, 0, object->length());
  return visitor.GetFlag();
}

template TaintFlag CheckTaint<String>(String* object);

class WritingVisitor : public TaintVisitor {
public:
  WritingVisitor(const TaintData* in_data) :
    TaintVisitor(true), in_data_(in_data), already_written_(0) {};

  void Visit(const uint16_t* visitee,
             TaintData* taint_data,
             int offset,
             int size) override {
    VisitInline(taint_data, offset, size);
  }
  void Visit(const uint8_t* visitee,
             TaintData* taint_data,
             int offset,
             int size) override {
    VisitInline(taint_data, offset, size);
  }

private:
  inline void VisitInline(TaintData* taint_data, int offset, int size) {
    MemCopy(taint_data + offset, in_data_ + already_written_, size);
    already_written_ += size;
  }

  const TaintData* in_data_;
  int already_written_;
};


void InitTaintInfo(const std::vector<std::tuple<TaintType, int>>& range_data,
                   TaintLogRecord::TaintInformation::Builder* builder) {
  auto ranges = builder->initRanges(range_data.size());
  for (int i = 0; i < range_data.size(); i++) {
    ranges[i].setStart(std::get<1>(range_data[i]));
    ranges[i].setEnd(-1);       // TODO: unused

    TaintType t_type = std::get<0>(range_data[i]);
    ranges[i].setType(TaintTypeToRecordEnum(t_type));
    ranges[i].setEncoding(TaintTypeToRecordEncoding(t_type));
  }
}


class SingleWritingVisitor : public TaintVisitor {
public:
  SingleWritingVisitor(TaintType type) : TaintVisitor(true), type_(type) {}

  void Visit(const uint8_t* visitee,
             TaintData* taint_data,
             int offset,
             int size) override {
    VisitInline(taint_data, offset, size);
  }
  void Visit(const uint16_t* visitee,
             TaintData* taint_data,
             int offset,
             int size) override {
    VisitInline(taint_data, offset, size);
  }

private:
  inline void VisitInline(TaintData* taint_data, int offset, int size) {
    memset(taint_data + offset, type_, size);
  }

  TaintType type_;
};

template <class T>
TaintType GetTaintStatus(T* object, size_t idx) {
  TaintData output;
  CopyVisitor visitor(&output);
  visitor.run(object, idx, 1);
  return static_cast<TaintType>(output);
}

template <class T>
TaintType GetTaintStatusRange(T* source, size_t idx_start, size_t length) {
  IsTaintedVisitor visitor;
  visitor.run(source, idx_start, length);
  TaintType answer = TaintFlagToType(visitor.GetFlag());
  CheckTaintError(answer, source);
  return answer;
}

template <class T>
void SetTaintStatus(T* object, size_t idx, TaintType type) {
  SingleWritingVisitor visitor(type);
  visitor.run(object, idx, 1);
}

template <class T>
void FlattenTaintData(T* source, TaintData* dest,
                      int from_offset, int from_len) {
  CopyVisitor visitor(dest);
  visitor.run(source, from_offset, from_len);
}

template <class T, class S>
void FlattenTaint(S* source, T* dest, int from_offset, int from_len) {
  DCHECK_GE(from_offset, 0);
  DCHECK_GE(source->length(), from_offset + from_len);
  DCHECK_GE(dest->length(), from_len);
  FlattenTaintData(source, GetWriteableStringTaintData(dest),
                   from_offset, from_len);
}

template <class T, class One, class Two>
void ConcatTaint(T* result, One* first, Two* second) {
  CopyVisitor visitor(GetWriteableStringTaintData(result));
  visitor.run(first, 0, first->length());
  visitor.run(second, 0, second->length());
}

template <class T>
void CopyOut(T* source, TaintData* dest, int offset, int len) {
  CopyVisitor visitor(dest);
  visitor.run(source, offset, len);
}

template <class T>
void CopyIn(T* dest, TaintType source, int offset, int len) {
  DCHECK_GE(dest->length(), len);
  SingleWritingVisitor visitor(source);
  visitor.run(dest, offset, len);
}

template <class T>
void CopyIn(T* dest, const TaintData* source, int offset, int len) {
  WritingVisitor visitor(source);
  visitor.run(dest, offset, len);
}


void LogSetTaintString(Handle<String> str, TaintType type) {
  if (FLAG_taint_tracking_enable_symbolic) {
    MessageHolder message;
    auto log_message = message.InitRoot();
    auto set_taint = log_message.getMessage().initSetTaint();
    set_taint.setTargetId(str->taint_info());
    set_taint.setTaintType(TaintTypeToRecordEnum(type));
    TaintTracker::Impl::LogToFile(str->GetIsolate(), message);
  }
}

void SetTaintString(Handle<String> str, TaintType type) {
  {
    DisallowHeapAllocation no_gc;
    CheckTaintError(type, *str);
    CopyIn(*str, type, 0, str->length());
  }
  LogSetTaintString(str, type);
}

void JSSetTaintBuffer(
    v8::internal::Handle<v8::internal::String> str,
    v8::internal::Handle<v8::internal::JSArrayBuffer> data) {
  {
    DisallowHeapAllocation no_gc;
    CopyIn(*str,
           reinterpret_cast<TaintData*>(data->backing_store()),
           0,
           str->length());
  }
  LogSetTaintString(str, TaintType::MULTIPLE_TAINTS);
}

std::vector<std::tuple<TaintType, int>> InitTaintRanges(
    Handle<String> target) {
  IsTaintedVisitor visitor;
  {
    DisallowHeapAllocation no_gc;
    visitor.run(*target, 0, target->length());
  }
  return visitor.GetRanges();
}

::TaintLogRecord::SinkType FromSinkType(TaintSinkLabel label) {
  switch (label) {
    case TaintSinkLabel::URL_SINK:
      return ::TaintLogRecord::SinkType::URL;
    case TaintSinkLabel::EMBED_SRC_SINK:
      return TaintLogRecord::SinkType::EMBED_SRC_SINK;
    case TaintSinkLabel::IFRAME_SRC_SINK:
      return TaintLogRecord::SinkType::IFRAME_SRC_SINK;
    case TaintSinkLabel::ANCHOR_SRC_SINK:
      return TaintLogRecord::SinkType::ANCHOR_SRC_SINK;
    case TaintSinkLabel::IMG_SRC_SINK:
      return TaintLogRecord::SinkType::IMG_SRC_SINK;
    case TaintSinkLabel::SCRIPT_SRC_URL_SINK:
      return TaintLogRecord::SinkType::SCRIPT_SRC_URL_SINK;
    case TaintSinkLabel::JAVASCRIPT_EVENT_HANDLER_ATTRIBUTE:
      return TaintLogRecord::SinkType::JAVASCRIPT_EVENT_HANDLER_ATTRIBUTE;
    case TaintSinkLabel::JAVASCRIPT:
      return ::TaintLogRecord::SinkType::JAVASCRIPT;
    case TaintSinkLabel::HTML:
      return ::TaintLogRecord::SinkType::HTML;
    case TaintSinkLabel::MESSAGE_DATA:
      return ::TaintLogRecord::SinkType::MESSAGE_DATA;
    case TaintSinkLabel::COOKIE_SINK:
      return ::TaintLogRecord::SinkType::COOKIE;
    case TaintSinkLabel::STORAGE_SINK:
      return ::TaintLogRecord::SinkType::STORAGE;
    case TaintSinkLabel::ORIGIN:
      return ::TaintLogRecord::SinkType::ORIGIN;
    case TaintSinkLabel::DOM_URL:
      return ::TaintLogRecord::SinkType::DOM_URL;
    case TaintSinkLabel::ELEMENT:
      return ::TaintLogRecord::SinkType::ELEMENT;
    case TaintSinkLabel::JAVASCRIPT_URL:
      return ::TaintLogRecord::SinkType::JAVASCRIPT_URL;
    case TaintSinkLabel::CSS:
      return ::TaintLogRecord::SinkType::CSS;
    case TaintSinkLabel::CSS_STYLE_ATTRIBUTE:
      return ::TaintLogRecord::SinkType::CSS_STYLE_ATTRIBUTE;
    case TaintSinkLabel::JAVASCRIPT_SET_TIMEOUT:
      return ::TaintLogRecord::SinkType::JAVASCRIPT_SET_TIMEOUT;
    case TaintSinkLabel::JAVASCRIPT_SET_INTERVAL:
      return ::TaintLogRecord::SinkType::JAVASCRIPT_SET_INTERVAL;
    case TaintSinkLabel::LOCATION_ASSIGNMENT:
      return ::TaintLogRecord::SinkType::LOCATION_ASSIGNMENT;
    default:
      UNREACHABLE();
  }
}


class HeartBeatTask : public v8::Task {
public:
  HeartBeatTask(v8::internal::Isolate* isolate) : isolate_(isolate) {}

  void Run() override;

  static void StartTimer(v8::internal::Isolate* isolate) {
    static const double _MILLIS_PER_SECOND = 1000;

    V8::GetCurrentPlatform()->CallDelayedOnForegroundThread(
        reinterpret_cast<v8::Isolate*>(isolate),
        new HeartBeatTask(isolate),
        static_cast<double>(FLAG_taint_tracking_heart_beat_millis) /
          _MILLIS_PER_SECOND);
  }

private:
  v8::internal::Isolate* isolate_;
};


void LogInitializeNavigate(Handle<String> url) {
  MessageHolder message;
  auto root = message.InitRoot();
  auto navigate = root.getMessage().initNavigate();
  message.CopyJsStringSlow(navigate.initUrl(), url);
  auto* isolate = url->GetIsolate();
  TaintTracker::Impl::LogToFile(
      isolate, message, FlushConfig::FORCE_FLUSH);

  if (!TaintTracker::FromIsolate(isolate)->Get()->HasHeartbeat()) {
    HeartBeatTask::StartTimer(isolate);
  }
}

void LogDispose(Isolate* isolate) {
  TaintTracker::Impl* impl = TaintTracker::FromIsolate(isolate)->Get();
  if (impl->IsLogging()) {
    impl->DoFlushLog();
  }
}

class JsStringInitializer {
public:
  virtual void SetJsString(
      ::Ast::JsString::Builder builder,
      MessageHolder& holder) const = 0;

  virtual void InitMessageOriginCheck(
      TaintLogRecord::JsSinkTainted::Builder builder,
      MessageHolder& holder) const = 0;
};

template <typename Char>
class JsStringFromBuffer : public JsStringInitializer {
public:
  JsStringFromBuffer(const Char* chardata, int length) :
    chardata_(chardata), length_(length) {}

  void SetJsString(::Ast::JsString::Builder builder,
                   MessageHolder& holder) const override {
    holder.CopyBuffer(builder, chardata_, length_);
  }

  void InitMessageOriginCheck(
      TaintLogRecord::JsSinkTainted::Builder builder,
      MessageHolder& holder) const override {}

private:
  const Char* chardata_;
  int length_;
};

class JsStringFromString : public JsStringInitializer {
public:
  JsStringFromString(Handle<String> str) : str_(str) {}

  void SetJsString(::Ast::JsString::Builder builder,
                   MessageHolder& holder) const override {
    holder.CopyJsStringSlow(builder, str_);
  }

  void InitMessageOriginCheck(
      TaintLogRecord::JsSinkTainted::Builder builder,
      MessageHolder& holder) const override {
    MaybeHandle<FixedArray> maybe_res =
      TaintTracker::FromIsolate(str_->GetIsolate())->Get()->
      GetCrossOriginMessageTable(str_);

    Handle<FixedArray> res;
    if (maybe_res.ToHandle(&res)) {
      DCHECK_EQ(res->length(), 2);
      auto origin_check = builder.initMessageOriginCheck();
      Object* origin_str = res->get(0);
      Object* compare_str = res->get(1);
      DCHECK(origin_str->IsString());
      DCHECK(compare_str->IsString());
      holder.CopyJsStringSlow(
          origin_check.initOriginString(),
          Handle<String>(String::cast(origin_str)));
      holder.CopyJsStringSlow(
          origin_check.initComparedString(),
          Handle<String>(String::cast(compare_str)));
    }
  }

private:
  Handle<String> str_;
};

int64_t LogIfTainted(IsTaintedVisitor& visitor,
                     const JsStringInitializer& initer,
                     v8::internal::Isolate* isolate,
                     v8::String::TaintSinkLabel label,
                     std::shared_ptr<SymbolicState> symbolic_data) {

  if (visitor.GetFlag() == TaintType::UNTAINTED) {
    return NO_MESSAGE;
  }

  MessageHolder message;
  auto log_message = message.InitRoot();


  char stack_trace [kStackTraceInfoSize];
  FixedStringAllocator alloc(stack_trace, sizeof(stack_trace));
  StringStream stream(
      &alloc, StringStream::ObjectPrintMode::kPrintObjectConcise);
  isolate->PrintStack(&stream);

  auto sink_message = log_message.getMessage().initJsSinkTainted();

  sink_message.setStackTrace(stack_trace);
  auto source = sink_message.initTaintSource();
  InitTaintInfo(visitor.GetRanges(), &source);
  sink_message.setSinkType(FromSinkType(label));
  initer.SetJsString(sink_message.initTargetString(), message);
  initer.InitMessageOriginCheck(sink_message, message);
  if (symbolic_data) {
    auto init_sym = sink_message.initSymbolicValue();
    symbolic_data->WriteSelf(init_sym, message);
  }
  return static_cast<int64_t>(
      TaintTracker::Impl::LogToFile(
          isolate, message, FlushConfig::FORCE_FLUSH));
}



inline bool EnableConcolic() {
  return FLAG_taint_tracking_enable_concolic &&
    !FLAG_taint_tracking_enable_concolic_hooks_only;
}

int64_t LogIfTainted(Handle<String> str,
                     TaintSinkLabel label,
                     int symbolic_data) {
  IsTaintedVisitor visitor;
  {
    DisallowHeapAllocation no_gc;
    visitor.run(*str, 0, str->length());
  }
  JsStringFromString initer(str);
  Isolate* isolate = str->GetIsolate();
  std::shared_ptr<SymbolicState> symbolic_arg =
    EnableConcolic()
    ? TaintTracker::FromIsolate(isolate)->Get()->Exec().
        GetSymbolicArgumentState(symbolic_data)
    : std::shared_ptr<SymbolicState>();
  return LogIfTainted(visitor,
                      initer,
                      isolate,
                      label,
                      symbolic_arg);
}


template <typename Char>
int64_t LogIfBufferTainted(TaintData* buffer,
                           const Char* stringdata,
                           size_t length,
                           int symbolic_data,
                           v8::internal::Isolate* isolate,
                           v8::String::TaintSinkLabel label) {
  IsTaintedVisitor visitor;
  visitor.Visit(stringdata, buffer, 0, length);
  JsStringFromBuffer<Char> initer(stringdata, length);
  std::shared_ptr<SymbolicState> symbolic_arg =
    EnableConcolic()
    ? TaintTracker::FromIsolate(isolate)->Get()->Exec().
        GetSymbolicArgumentState(symbolic_data)
    : std::shared_ptr<SymbolicState>();
  return LogIfTainted(visitor, initer, isolate, label, symbolic_arg);
}

template int64_t LogIfBufferTainted<uint8_t>(
    TaintData* buffer,
    const uint8_t* stringdata,
    size_t length,
    int symbolic_data,
    v8::internal::Isolate* isolate,
    v8::String::TaintSinkLabel label);
template int64_t LogIfBufferTainted<uint16_t>(
    TaintData* buffer,
    const uint16_t* stringdata,
    size_t length,
    int symbolic_data,
    v8::internal::Isolate* isolate,
    v8::String::TaintSinkLabel label);



class SetTaintOnObjectKv : public ObjectOwnPropertiesVisitor {
public:
  SetTaintOnObjectKv(TaintType type) : type_(type) {};

  bool VisitKeyValue(Handle<String> key, Handle<Object> value) override {
    DisallowHeapAllocation no_gc;
    CopyIn(*key, type_, 0, key->length());
    if (value->IsString()) {
      Handle<String> value_as_string = Handle<String>::cast(value);
      CopyIn(*value_as_string, type_, 0, value_as_string->length());
    }
    return true;
  }

private:
  TaintType type_;
};


void SetTaintOnObjectRecursive(Handle<JSReceiver> obj, TaintType type) {
  SetTaintOnObjectKv v(type);
  v.Visit(obj);
}

void SetTaint(v8::internal::Handle<v8::internal::Object> obj,
              TaintType type) {
  if (obj->IsString()) {
    SetTaintString(Handle<String>::cast(obj), type);
  } else if (obj->IsJSReceiver()) {
    SetTaintOnObjectRecursive(Handle<JSReceiver>::cast(obj), type);
  }
}

class SetTaintInfoOnObjectKv : public ObjectOwnPropertiesVisitor {
public:
  SetTaintInfoOnObjectKv(int64_t info) : info_(info) {};

  bool VisitKeyValue(Handle<String> key, Handle<Object> value) override {
    key->set_taint_info(info_);
    if (value->IsString()) {
      Handle<String>::cast(value)->set_taint_info(info_);
    }
    return true;
  }

private:
  int64_t info_;
};

void SetTaintInfo(
    v8::internal::Handle<v8::internal::Object> obj, int64_t info) {

  if (obj->IsString()) {
    Handle<String>::cast(obj)->set_taint_info(info);
  } else if (obj->IsJSReceiver()) {
    Handle<JSReceiver> receiver = Handle<JSReceiver>::cast(obj);
    SetTaintInfoOnObjectKv kv (info);
    kv.Visit(receiver);
  }
}


Handle<Object> JSCheckTaintMaybeLog(Handle<String> str,
                                    Handle<Object> sink,
                                    int symbolic_data) {
  int64_t ret = LogIfTainted(str, TaintSinkLabel::JAVASCRIPT, symbolic_data);
  Isolate* isolate = str->GetIsolate();
  return ret == -1 ?
    isolate->factory()->ToBoolean(false) :
    isolate->factory()->NewNumberFromInt64(ret);
}

MUST_USE_RESULT v8::internal::Handle<v8::internal::JSArrayBuffer>
JSGetTaintStatus(v8::internal::Handle<v8::internal::String> str,
                 v8::internal::Isolate* isolate) {
  Handle<JSArrayBuffer> answer = isolate->factory()->NewJSArrayBuffer();
  DisallowHeapAllocation no_gc;
  int len = str->length();
  JSArrayBuffer::SetupAllocatingData(
      answer, isolate, len, false, SharedFlag::kNotShared);
  FlattenTaintData(
      *str, reinterpret_cast<TaintData*>(answer->backing_store()), 0, len);
  return answer;
}

void JSTaintLog(v8::internal::Handle<v8::internal::String> str,
                v8::internal::MaybeHandle<v8::internal::String> extra_ref) {
  Isolate* isolate = str->GetIsolate();
  MessageHolder message;
  auto log_message = message.InitRoot();
  auto js_message = log_message.getMessage().initJsLog();
  message.CopyJsStringSlow(js_message.initLogMessage(), str);
  js_message.setExtraRefTaint(
      !extra_ref.is_null() ?
      extra_ref.ToHandleChecked()->taint_info() : kUndefinedInstanceCounter);
  TaintTracker::Impl::LogToFile(
      isolate, message, FlushConfig::FORCE_FLUSH);
}

void TaintTracker::OnBeforeCompile(Handle<Script> script, Isolate* isolate) {
  DisallowHeapAllocation no_gc;
  Object* source_obj = script->source();
  DCHECK(source_obj->IsString());
  String* source = String::cast(source_obj);
  IsTaintedVisitor visitor;
  visitor.run(source, 0, source->length());
  if (visitor.GetFlag() != TaintType::UNTAINTED) {
    TaintInstanceInfo instance;
    std::unique_ptr<char[]> name (
        Object::ToString(isolate, handle(script->name(), isolate))
        .ToHandleChecked()->ToCString());
    std::unique_ptr<char[]> source_url (
        Object::ToString(isolate, handle(script->source_url(), isolate))
        .ToHandleChecked()->ToCString());
    std::unique_ptr<char[]> source_code (source->ToCString());
    instance.taint_flag = visitor.GetFlag();
    instance.name = name.get();
    instance.source_url = source_url.get();
    instance.source_code = source_code.get();
    instance.ranges = visitor.GetRanges();
    FromIsolate(isolate)->Get()->Trigger(instance, isolate);
  }
}

TaintTracker* TaintTracker::New(bool enable_serializer,
                                v8::internal::Isolate* isolate) {
  return new TaintTracker(enable_serializer, isolate);
}

void TaintTracker::RegisterTaintListener(TaintListener* listener) {
  Get()->RegisterTaintListener(listener);
}

// static
TaintTracker* TaintTracker::FromIsolate(Isolate* isolate) {
  return isolate->taint_tracking_data();
}


TaintTracker::TaintTracker(bool enable_serializer,
                           v8::internal::Isolate* isolate) :
  impl_(std::unique_ptr<TaintTracker::Impl>(
            new TaintTracker::Impl(enable_serializer, isolate))) {}

TaintTracker::~TaintTracker() {}

TaintTracker::Impl* TaintTracker::Get() {
  return impl_.get();
}

TaintTracker::Impl::Impl(bool enable_serializer,
                         v8::internal::Isolate* isolate)
  : message_counter_(0),
    log_(),
    listeners_(),
    is_logging_(false),
    log_flush_scheduled_(false),
    has_heartbeat_(false),
    unsent_messages_(0),
    log_mutex_(),
    exec_(isolate),
    versioner_(new ObjectVersioner(isolate)) {
  symbolic_elem_counter_ = enable_serializer ? 1 : kMaxCounterSnapshot;
  last_message_flushed_.Start();
}

void TaintTracker::Initialize(v8::internal::Isolate* isolate) {
  Get()->Initialize(isolate);
}

bool TaintTracker::IsRewriteAstEnabled() {
  return FLAG_taint_tracking_enable_ast_modification;
}

void TaintTracker::Impl::Initialize(v8::internal::Isolate* isolate) {
  if (strlen(FLAG_taint_log_file) != 0) {
    std::lock_guard<std::mutex> guard(log_mutex_);
    is_logging_ = true;
    log_.open(LogFileName());
    buffer_log_storage_ = kj::heapArray<uint8_t>(kLogBufferSize);
    kj_log_.reset(new ::kj::std::StdOutputStream(log_));
    buffered_log_.reset(new ::kj::BufferedOutputStreamWrapper(
                            *kj_log_,
                            buffer_log_storage_));
  }

  HandleScope scope(isolate);
  if (EnableConcolic()) {
    Exec().Initialize();
  }

  static const int INITIAL_SIZE = 10;
  Handle<Object> tmp = ObjectHashTable::New(isolate, INITIAL_SIZE);
  cross_origin_message_table_ =
    Handle<ObjectHashTable>::cast(
        isolate->global_handles()->Create(*tmp.location()));
}

TaintTracker::Impl::~Impl() {
  if (is_logging_) {
    std::lock_guard<std::mutex> guard(log_mutex_);
    log_.close();
  }

  GlobalHandles::Destroy(
      reinterpret_cast<Object**>(cross_origin_message_table_.location()));
}

void TaintTracker::Impl::RegisterTaintListener(TaintListener* listener) {
  listeners_.push_back(std::unique_ptr<TaintListener>(listener));
}

void TaintTracker::Impl::Trigger(
    const TaintInstanceInfo& info, Isolate* isolate) {
  for (auto& listener : listeners_) {
    listener->OnTaintedCompilation(info, isolate);
  }
}

bool TaintTracker::Impl::IsLogging() const {
  return is_logging_;
}

bool TaintTracker::Impl::HasHeartbeat() const {
  return is_logging_;
}

void MakeUniqueLogFileName(std::ostringstream& base) {
  base << FLAG_taint_log_file << "_"
       << v8::base::OS::GetCurrentProcessId() << "_"
       << static_cast<int64_t>(v8::base::OS::TimeCurrentMillis());
}

std::string TaintTracker::Impl::LogFileName() {
  std::lock_guard<std::mutex> lock(isolate_counter_mutex_);
  std::ostringstream log_fname;
  MakeUniqueLogFileName(log_fname);
  log_fname << "_" << (isolate_counter_++);
  return log_fname.str();
}

InstanceCounter* TaintTracker::symbolic_elem_counter() {
  return &(Get()->symbolic_elem_counter_);
}

InstanceCounter TaintTracker::Impl::NewInstance() {
  return symbolic_elem_counter_++;
}


MUST_USE_RESULT v8::internal::Handle<v8::internal::HeapObject>
JSTaintConstants(v8::internal::Isolate* isolate) {
  Factory* factory = isolate->factory();
  Handle<JSObject> ret = factory->NewJSObjectWithNullProto();
  MaybeHandle<Object> ignore;
  for (int i = TaintType::UNTAINTED; i < TaintType::MAX_TAINT_TYPE; i++) {
    std::string taint_string = TaintTypeToString(static_cast<TaintType>(i));
    Vector<const char> js_string(taint_string.data(), taint_string.size());
    ignore = Object::SetProperty(
        ret,
        Handle<Name>::cast(
            factory->NewStringFromUtf8(js_string).ToHandleChecked()),
        Handle<Object>::cast(factory->NewHeapNumber(i)),
        LanguageMode::STRICT);
  }
  ignore = Object::SetProperty(
      ret,
      Handle<Name>::cast(
          factory->NewStringFromAsciiChecked(kEnableHeaderLoggingName)),
      Handle<Object>::cast(factory->NewHeapNumber(
                               FLAG_taint_tracking_enable_header_logging ?
                               1 : 0
                           )),
      LanguageMode::STRICT);
  ignore = Object::SetProperty(
      ret,
      Handle<Name>::cast(
          factory->NewStringFromAsciiChecked(kEnableBodyLoggingName)),
      Handle<Object>::cast(factory->NewHeapNumber(
                               FLAG_taint_tracking_enable_page_logging ?
                               1 : 0
                           )),
      LanguageMode::STRICT);
  std::ostringstream log_name_base;
  MakeUniqueLogFileName(log_name_base);
  log_name_base << "_full_page_" << isolate;
  ignore = Object::SetProperty(
      ret,
      Handle<Name>::cast(
          factory->NewStringFromAsciiChecked(kLoggingFilenamePrefix)),
      Handle<Object>::cast(
          factory->NewStringFromAsciiChecked(log_name_base.str().c_str())),
      LanguageMode::STRICT);
  ignore = Object::SetProperty(
      ret,
      Handle<Name>::cast(
          factory->NewStringFromAsciiChecked(kJobIdName)),
      Handle<Object>::cast(
          factory->NewStringFromAsciiChecked(FLAG_taint_tracking_job_id)),
      LanguageMode::STRICT);
  return ret;
}

template void OnNewConcatStringCopy<SeqOneByteString, String, String>(
    SeqOneByteString*, String*, String*);
template void OnNewConcatStringCopy<SeqTwoByteString, String, String>(
    SeqTwoByteString*, String*, String*);

template void OnNewSubStringCopy<String, SeqOneByteString>(
    String*, SeqOneByteString*, int, int);
template void OnNewSubStringCopy<SeqOneByteString, SeqOneByteString>(
    SeqOneByteString*, SeqOneByteString*, int, int);
template void OnNewSubStringCopy<String, SeqTwoByteString>(
    String*, SeqTwoByteString*, int, int);
template void OnNewSubStringCopy<ConsString, SeqString>(
    ConsString*, SeqString*, int, int);
template void OnNewSubStringCopy<SeqOneByteString, SeqString>(
    SeqOneByteString*, SeqString*, int, int);
template void OnNewSubStringCopy<String, SeqString>(
    String*, SeqString*, int, int);

template void FlattenTaintData<ExternalString>(
    ExternalString*, TaintData*, int, int);
template void FlattenTaintData<String>(String*, TaintData*, int, int);

template TaintType GetTaintStatusRange<String>(String*, size_t, size_t);

template TaintType GetTaintStatus<String>(String*, size_t);

template void SetTaintStatus<SeqOneByteString>(
    SeqOneByteString*, size_t, TaintType);
template void SetTaintStatus<SeqTwoByteString>(
    SeqTwoByteString*, size_t, TaintType);
template void SetTaintStatus<String>(String*, size_t, TaintType);

template void CopyIn<SeqOneByteString>(
    SeqOneByteString*, TaintType, int, int);

template void CopyIn<SeqOneByteString>(
    SeqOneByteString*, const TaintData*, int, int);
template void CopyIn<SeqTwoByteString>(
    SeqTwoByteString*, const TaintData*, int, int);
template void CopyIn<SeqString>(SeqString*, const TaintData*, int, int);

template void CopyOut<SeqString>(SeqString*, TaintData*, int, int);
template void CopyOut<SeqOneByteString>(
    SeqOneByteString*, TaintData*, int, int);
template void CopyOut<SeqTwoByteString>(
    SeqTwoByteString*, TaintData*, int, int);

template void OnNewReplaceRegexpWithString<SeqOneByteString>(
    String* subject, SeqOneByteString* result, JSRegExp* pattern,
    String* replacement);
template void OnNewReplaceRegexpWithString<SeqTwoByteString>(
    String* subject, SeqTwoByteString* result, JSRegExp* pattern,
    String* replacement);

template void OnJoinManyStrings<SeqOneByteString, JSArray>(
    SeqOneByteString*, JSArray*);
template void OnJoinManyStrings<SeqTwoByteString, JSArray>(
    SeqTwoByteString*, JSArray*);
template void OnJoinManyStrings<SeqOneByteString, FixedArray>(
    SeqOneByteString*, FixedArray*);
template void OnJoinManyStrings<SeqTwoByteString, FixedArray>(
    SeqTwoByteString*, FixedArray*);

template void FlattenTaint<SeqOneByteString, String>(
    String*, SeqOneByteString*, int, int);
template void FlattenTaint<SeqTwoByteString, String>(
    String*, SeqTwoByteString*, int, int);



template <size_t N>
void LogSymbolic(String* first,
                 const std::array<String*, N>& refs,
                 std::string extra,
                 SymbolicType type) {
  DCHECK(FLAG_taint_tracking_enable_symbolic);
  DCHECK_NOT_NULL(first);

  Isolate* isolate = first->GetIsolate();
  MessageHolder message;
  auto log_message = message.InitRoot();
  auto symbolic_log = log_message.getMessage().initSymbolicLog();
  symbolic_log.setTargetId(first->taint_info());
  auto arg_list = symbolic_log.initArgRefs(refs.size());
  for (int i = 0; i < refs.size(); i++) {
    arg_list.set(i, refs[i]->taint_info());
  }
  message.CopyJsStringSlow(symbolic_log.initTargetValue(), first);
  IsTaintedVisitor visitor;
  visitor.run(first, 0, first->length());
  auto info_ranges = visitor.GetRanges();
  auto value = symbolic_log.initTaintValue();
  InitTaintInfo(info_ranges, &value);
  symbolic_log.setSymbolicOperation(SymbolicTypeToEnum(type));

  TaintTracker::Impl::LogToFile(isolate, message);
}


template <class T> void OnNewStringLiteral(T* source) {
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<0>(source, {{}}, "", LITERAL);
  }
}
template void OnNewStringLiteral(String* source);
template void OnNewStringLiteral(SeqOneByteString* source);
template void OnNewStringLiteral(SeqTwoByteString* source);

void OnNewDeserializedString(String* source) {
  MarkNewString(source);
  OnNewStringLiteral(source);
}

template <class T, class S>
void OnNewSubStringCopy(T* source, S* dest, int offset, int length) {
  FlattenTaint(source, dest, offset, length);
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<1>(dest, {{source}}, std::to_string(offset), SLICE);
  }
}

void OnNewSlicedString(SlicedString* target, String* first,
                       int offset, int length) {
  MarkNewString(target);
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<1>(target, {{first}}, std::to_string(offset), SLICE);
  }
}

template <class T, class S, class R>
void OnNewConcatStringCopy(T* dest, S* first, R* second) {
  ConcatTaint(dest, first, second);
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<2>(dest, {{first, second}}, "", CONCAT);
  }
}

void OnNewConsString(ConsString* target, String* first, String* second) {
  MarkNewString(target);
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<2>(target, {{first, second}}, "", CONCAT);
  }
}

void OnNewFromJsonString(SeqString* target, String* source) {
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<1>(target, {{source}}, "", PARSED_JSON);
  }
}

template <class T> void OnNewExternalString(T* str) {
  MarkNewString(str);
  OnNewStringLiteral(str);
}
template void OnNewExternalString<ExternalOneByteString>(
    ExternalOneByteString*);
template void OnNewExternalString<ExternalTwoByteString>(
    ExternalTwoByteString*);

template <class T>
void OnNewReplaceRegexpWithString(
    String* subject, T* result, JSRegExp* pattern, String* replacement) {
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<2>(result,
                   {{subject, String::cast(pattern->source())}},
                   replacement->ToCString().get(),
                   REGEXP);
  }
}


template <class T, class Array>
void OnJoinManyStrings(T* target, Array* array) {
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<0>(target, {{}}, "TODO: print array value", JOIN);
  }
}

template <class T>
void OnConvertCase(String* source, T* answer) {
  FlattenTaint(source, answer, 0, source->length());
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<1>(answer, {{source}}, "", CASE_CHANGE);
  }
}
template void OnConvertCase<SeqOneByteString>(
    String* source, SeqOneByteString* answer);
template void OnConvertCase<SeqTwoByteString>(
    String* source, SeqTwoByteString* answer);
template void OnConvertCase<SeqString>(
    String* source, SeqString* answer);

template void OnGenericOperation<String>(SymbolicType, String*);
template void OnGenericOperation<SeqOneByteString>(
    SymbolicType, SeqOneByteString*);
template void OnGenericOperation<SeqTwoByteString>(
    SymbolicType, SeqTwoByteString*);
template <class T>
void OnGenericOperation(SymbolicType type, T* source) {
  if (FLAG_taint_tracking_enable_symbolic) {
    LogSymbolic<0>(source, {{}}, "", type);
  }

  uint8_t anti_mask;
  uint8_t mask;
  switch (type) {
    case SymbolicType::URI_DECODE:
      anti_mask = TaintType::URL_ENCODED;
      mask = TaintType::URL_DECODED;
      break;

    case SymbolicType::URI_COMPONENT_DECODE:
      anti_mask = TaintType::URL_COMPONENT_ENCODED;
      mask = TaintType::URL_COMPONENT_DECODED;
      break;

    case SymbolicType::URI_UNESCAPE:
      anti_mask = TaintType::ESCAPE_ENCODED;
      mask = TaintType::ESCAPE_DECODED;
      break;

    case SymbolicType::URI_ENCODE:
      mask = TaintType::URL_ENCODED;
      anti_mask = TaintType::URL_DECODED;
      break;

    case SymbolicType::URI_COMPONENT_ENCODE:
      mask = TaintType::URL_COMPONENT_ENCODED;
      anti_mask = TaintType::URL_COMPONENT_DECODED;
      break;

    case SymbolicType::URI_ESCAPE:
      mask = TaintType::ESCAPE_ENCODED;
      anti_mask = TaintType::ESCAPE_DECODED;
      break;

    default:
      return;
  }

  // The encoding operations are required to return a flat string.
  DCHECK(source->IsSeqString());

  {
    DisallowHeapAllocation no_gc;
    SeqString* as_seq_ptr = SeqString::cast(source);

    int length = as_seq_ptr->length();
    TaintData type_arr [length];
    CopyOut(as_seq_ptr, type_arr, 0, length);

    for (int i = 0; i < length; i++) {
      uint8_t type_i = static_cast<uint8_t>(type_arr[i]);
      uint8_t old_encoding = type_i & TaintType::ENCODING_TYPE_MASK;

      // If the old encoding is nothing, then we move to the mask encoding. If the
      // old encoding was the inverse operation, then we move to no encoding. If
      // it is neither, then we move to the multiple encoding state.
      uint8_t new_encoding = old_encoding == TaintType::NO_ENCODING
        ? mask : (
            old_encoding == anti_mask
            ? TaintType::NO_ENCODING
            : TaintType::MULTIPLE_ENCODINGS);

      type_arr[i] = static_cast<TaintType>(
          (type_i & TaintType::TAINT_TYPE_MASK) | new_encoding);
    }

    // TODO: Perform this operation in-place without the copy in and copy out
    // calls.
    CopyIn(as_seq_ptr, type_arr, 0, length);
  }
}

void InsertControlFlowHook(ParseInfo* info) {
  DCHECK_NOT_NULL(info->literal());
  if (FLAG_taint_tracking_enable_export_ast ||
      FLAG_taint_tracking_enable_ast_modification ||
      FLAG_taint_tracking_enable_source_export ||
      FLAG_taint_tracking_enable_source_hash_export) {
    CHECK(SerializeAst(info));
  }
}

ConcolicExecutor& TaintTracker::Impl::Exec() {
  return exec_;
}

ObjectVersioner& TaintTracker::Impl::Versioner() {
  return *versioner_;
}


void LogRuntimeSymbolic(Isolate* isolate,
                        Handle<Object> target_object,
                        Handle<Object> label,
                        CheckType check) {
  MessageHolder message;
  auto log_message = message.InitRoot();
  auto cntrl_flow = log_message.getMessage().initRuntimeLog();
  BuilderSerializer serializer_out;
  V8NodeLabelSerializer serializer_in(isolate);
  NodeLabel out;
  CHECK_EQ(Status::OK, serializer_in.Deserialize(label, &out));
  CHECK_EQ(Status::OK, serializer_out.Serialize(cntrl_flow.initLabel(), out));
  bool isstring = target_object->IsString();
  if (isstring) {
    cntrl_flow.setObjectLabel(
        Handle<String>::cast(target_object)->taint_info());
  }
  switch (check) {
    case CheckType::STATEMENT_BEFORE:
      cntrl_flow.setCheckType(
          ::Ast::RuntimeLog::CheckType::STATEMENT_BEFORE);
      break;
    case CheckType::STATEMENT_AFTER:
      cntrl_flow.setCheckType(::Ast::RuntimeLog::CheckType::STATEMENT_AFTER);
      break;
    case CheckType::EXPRESSION_BEFORE:
      cntrl_flow.setCheckType(
          ::Ast::RuntimeLog::CheckType::EXPRESSION_BEFORE);
      break;
    case CheckType::EXPRESSION_AFTER:
    case CheckType::STATIC_VALUE_CHECK:
      cntrl_flow.setCheckType(
          ::Ast::RuntimeLog::CheckType::EXPRESSION_AFTER);
      break;
    default:
      UNREACHABLE();
  }

  TaintTracker::Impl::LogToFile(isolate, message);
}


uint64_t MAGIC_NUMBER = 0xbaededfeed;

V8NodeLabelSerializer::V8NodeLabelSerializer(Isolate* isolate) :
  isolate_(isolate) {};

Status V8NodeLabelSerializer::Serialize(
    Object** output, const NodeLabel& label) {
  if (!label.IsValid()) {
    return Status::FAILURE;
  }
  *output = *Make(label);
  return Status::OK;
}

v8::internal::Handle<v8::internal::Object> V8NodeLabelSerializer::Make(
    const NodeLabel& label) {
  auto* factory = isolate_->factory();
  Handle<SeqOneByteString> str = factory->NewRawOneByteString(
      sizeof(NodeLabel::Rand) +
      sizeof(NodeLabel::Counter) +
      sizeof(uint64_t)).ToHandleChecked();
  NodeLabel::Rand rand_val = label.GetRand();
  NodeLabel::Counter counter_val = label.GetCounter();
  MemCopy(str->GetChars(),
          reinterpret_cast<const uint8_t*>(&rand_val),
          sizeof(NodeLabel::Rand));
  MemCopy(str->GetChars() + sizeof(NodeLabel::Rand),
          reinterpret_cast<const uint8_t*>(&counter_val),
          sizeof(NodeLabel::Counter));
  MemCopy(str->GetChars() +
            sizeof(NodeLabel::Rand) +
            sizeof(NodeLabel::Counter),
          reinterpret_cast<const uint8_t*>(&MAGIC_NUMBER),
          sizeof(uint64_t));
  return str;
}

Status V8NodeLabelSerializer::Serialize(
    Handle<Object>* output, const NodeLabel& label) {
  if (!label.IsValid()) {
    return Status::FAILURE;
  }

  *output = Make(label);
  return Status::OK;
}

Status V8NodeLabelSerializer::Deserialize(
    Handle<Object> arr, NodeLabel* label) {
  DisallowHeapAllocation no_gc;
  return Deserialize(*arr, label);
}

Status V8NodeLabelSerializer::Deserialize(Object* arr, NodeLabel* label) {
  DisallowHeapAllocation no_gc;
  SeqOneByteString* seqstr = SeqOneByteString::cast(arr);
  if (!arr->IsSeqOneByteString()) {
    return Status::FAILURE;
  }
  NodeLabel::Rand rand_val;
  NodeLabel::Counter counter_val;
  MemCopy(reinterpret_cast<uint8_t*>(&rand_val),
          seqstr->GetChars(),
          sizeof(NodeLabel::Rand));
  MemCopy(reinterpret_cast<uint8_t*>(&counter_val),
          seqstr->GetChars() + sizeof(NodeLabel::Rand),
          sizeof(NodeLabel::Counter));
  if (sizeof(NodeLabel::Rand) +
      sizeof(NodeLabel::Counter) +
      sizeof(uint64_t) != seqstr->length()) {
    return Status::FAILURE;
  }
  uint64_t magic_number_check;
  MemCopy(reinterpret_cast<uint8_t*>(&magic_number_check),
          seqstr->GetChars() +
            sizeof(NodeLabel::Counter) +
            sizeof(NodeLabel::Rand),
          sizeof(uint64_t));
  if (magic_number_check != MAGIC_NUMBER) {
    return Status::FAILURE;
  }
  label->CopyFrom(NodeLabel(rand_val, counter_val));
  return label->IsValid() ? Status::OK : Status::FAILURE;
}


void RuntimeHook(Isolate* isolate,
                 Handle<Object> target_object,
                 Handle<Object> label,
                 int checktype) {
  DCHECK(FLAG_taint_tracking_enable_ast_modification);
  CheckType check = static_cast<CheckType>(checktype);


  if (FLAG_taint_tracking_enable_symbolic) {
    LogRuntimeSymbolic(
        isolate, target_object, label, check);
  }
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeHook(
        target_object, label, check);
  }
}


void RuntimeHookVariableLoad(Isolate* isolate,
                             Handle<Object> target_object,
                             Handle<Object> proxy_label,
                             Handle<Object> past_assignment_label,
                             int checktype) {
  DCHECK(FLAG_taint_tracking_enable_ast_modification);
  CheckType check = static_cast<CheckType>(checktype);

  if (FLAG_taint_tracking_enable_symbolic) {
    LogRuntimeSymbolic(
        isolate, target_object, proxy_label, check);
  }
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->
      Get()->
      Exec().
      OnRuntimeHookVariableLoad(
          target_object, proxy_label, past_assignment_label, check);
  }
}

Handle<Object> RuntimeHookVariableStore(
    Isolate* isolate,
    Handle<Object> concrete,
    Handle<Object> label,
    CheckType checktype,
    Handle<Object> var_idx) {
  if (EnableConcolic()) {
    return TaintTracker::FromIsolate(isolate)->Get()->Exec().
      OnRuntimeHookVariableStore(concrete, label, checktype, var_idx);
  } else {
    return handle(isolate->heap()->undefined_value(), isolate);
  }
}

void RuntimeHookVariableContextStore(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> concrete,
    v8::internal::Handle<v8::internal::Object> label,
    v8::internal::Handle<v8::internal::Context> context,
    v8::internal::Handle<v8::internal::Smi> smi) {
  if (EnableConcolic()) {
    return TaintTracker::FromIsolate(isolate)->Get()->Exec().
      OnRuntimeHookVariableContextStore(concrete, label, context, smi);
  }
}

void RuntimeExitSymbolicStackFrame(v8::internal::Isolate* isolate) {
  if (EnableConcolic()) {
    return TaintTracker::FromIsolate(isolate)->Get()->Exec().
      ExitSymbolicStackFrame();
  }
}

void RuntimePrepareSymbolicStackFrame(
    v8::internal::Isolate* isolate,
    FrameType type) {
  if (EnableConcolic()) {
    return TaintTracker::FromIsolate(isolate)->Get()->Exec().
      PrepareSymbolicStackFrame(type);
  }
}

void RuntimeEnterSymbolicStackFrame(v8::internal::Isolate* isolate) {
  if (EnableConcolic()) {
    return TaintTracker::FromIsolate(isolate)->Get()->Exec().
      EnterSymbolicStackFrame();
  }
}

void RuntimeAddArgumentToStackFrame(
    v8::internal::Isolate* isolate,
    v8::internal::MaybeHandle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec().
      AddArgumentToFrame(label);
  }
}

void RuntimeAddLiteralArgumentToStackFrame(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> value) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec().
      AddLiteralArgumentToFrame(value);
  }
}

v8::internal::Handle<v8::internal::Object> GetSymbolicArgument(
    v8::internal::Isolate* isolate, uint32_t i) {
  if (EnableConcolic()) {
    return TaintTracker::FromIsolate(isolate)->Get()->Exec().
      GetSymbolicArgumentObject(i);
  } else {
    return handle(isolate->heap()->undefined_value(), isolate);
  }
}


void LogHeartBeat(v8::internal::Isolate* isolate) {
  MessageHolder holder;
  auto builder = holder.InitRoot();
  auto message = builder.getMessage();
  auto job_id_message = message.initJobId();
  job_id_message.setJobId(FLAG_taint_tracking_job_id);
  job_id_message.setTimestampMillisSinceEpoch(
      static_cast<int64_t>(v8::base::OS::TimeCurrentMillis()));
  TaintTracker::Impl::LogToFile(isolate, holder, FlushConfig::FORCE_FLUSH);
}

void HeartBeatTask::Run() {
  LogHeartBeat(isolate_);
  StartTimer(isolate_);
}


bool HasLabel(v8::internal::Isolate* isolate, const NodeLabel& label) {
  if (EnableConcolic()) {
    return TaintTracker::FromIsolate(isolate)->Get()->Exec().HasLabel(label);
  } else {
    return false;
  }
}

bool SymbolicMatchesFunctionArgs(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (EnableConcolic()) {
    return TaintTracker::FromIsolate(
        reinterpret_cast<v8::internal::Isolate*>(info.GetIsolate()))
      ->Get()->Exec().MatchesArgs(info);
  } else {
    return true;
  }
}

void RuntimeSetReturnValue(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> value,
    v8::internal::MaybeHandle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)
      ->Get()->Exec().OnRuntimeSetReturnValue(value, label);
  }
}

void RuntimeEnterTry(v8::internal::Isolate* isolate,
                     v8::internal::Handle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeEnterTry(label);
  }
}

void RuntimeExitTry(v8::internal::Isolate* isolate,
                    v8::internal::Handle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeExitTry(label);
  }
}

void RuntimeOnThrow(v8::internal::Isolate* isolate,
                    v8::internal::Handle<v8::internal::Object> exception,
                    bool is_rethrow) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeThrow(
        exception, is_rethrow);
  }
}

void RuntimeOnCatch(v8::internal::Isolate* isolate,
                    v8::internal::Handle<v8::internal::Object> thrown_object,
                    v8::internal::Handle<v8::internal::Context> context) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec()
      .OnRuntimeCatch(thrown_object, context);
  }
}

void RuntimeOnExitFinally(v8::internal::Isolate* isolate) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec()
      .OnRuntimeExitFinally();
  }
}

void RuntimeSetReceiver(v8::internal::Isolate* isolate,
                        v8::internal::Handle<v8::internal::Object> value,
                        v8::internal::Handle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec()
      .SetReceiverOnFrame(value, label);
  }
}


v8::internal::Object* RuntimePrepareApplyFrame(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> argument_list,
    v8::internal::Handle<v8::internal::Object> target_fn,
    v8::internal::Handle<v8::internal::Object> new_target,
    v8::internal::Handle<v8::internal::Object> this_argument,
    FrameType frame_type) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec()
      .RuntimePrepareApplyFrame(
          argument_list, target_fn, new_target, this_argument, frame_type);
  }
  return isolate->heap()->undefined_value();
}

v8::internal::Object* RuntimePrepareCallFrame(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> target_fn,
    FrameType caller_frame_type,
    v8::internal::Handle<v8::internal::FixedArray> args) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec()
      .RuntimePrepareCallFrame(
          target_fn, caller_frame_type, args);
  }
  return isolate->heap()->undefined_value();
}

v8::internal::Object* RuntimePrepareCallOrConstructFrame(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> target_fn,
    v8::internal::Handle<v8::internal::Object> new_target,
    v8::internal::Handle<v8::internal::FixedArray> args) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec()
      .RuntimePrepareCallOrConstructFrame(
          target_fn, new_target, args);
  }
  return isolate->heap()->undefined_value();
}


void RuntimeSetLiteralReceiver(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> target_fn) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec()
      .SetLiteralReceiverOnCurrentFrame(target_fn);
  }
}

void RuntimeCheckMessageOrigin(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> left,
    v8::internal::Handle<v8::internal::Object> right,
    v8::internal::Token::Value token) {

  if (!left->IsString() || !right->IsString()) {
    return;
  }

  Handle<String> left_as_str = Handle<String>::cast(left);
  Handle<String> right_as_str = Handle<String>::cast(right);

  IsTaintedVisitor left_visitor;
  {
    DisallowHeapAllocation no_gc;
    left_visitor.run(*left_as_str, 0, left_as_str->length());
  }

  IsTaintedVisitor right_visitor;
  {
    DisallowHeapAllocation no_gc;
    right_visitor.run(*right_as_str, 0, right_as_str->length());
  }

  bool left_has_key = false;

  TaintFlag origin_flag = AddFlag(
      kTaintFlagUntainted, TaintType::MESSAGE_ORIGIN);
  if (left_visitor.GetFlag() == origin_flag) {
    left_has_key = true;
  } else if (right_visitor.GetFlag() != origin_flag) {
    return;
  }

  if (left_has_key) {
    TaintTracker::FromIsolate(isolate)->Get()->PutCrossOriginMessageTable(
        isolate,
        left_as_str,
        right_as_str);
  } else {
    TaintTracker::FromIsolate(isolate)->Get()->PutCrossOriginMessageTable(
        isolate,
        right_as_str,
        left_as_str);
  }
}


v8::internal::MaybeHandle<FixedArray>
TaintTracker::Impl::GetCrossOriginMessageTable(
    v8::internal::Handle<v8::internal::String> ref) {
  Isolate* isolate = ref->GetIsolate();
  Object* val = cross_origin_message_table_->Lookup(
      isolate->factory()->NewNumberFromInt64(ref->taint_info()));
  if (val) {
    if (val->IsFixedArray()) {
      return Handle<FixedArray>(FixedArray::cast(val), isolate);

    }
  }
  return MaybeHandle<FixedArray>();
}


void TaintTracker::Impl::PutCrossOriginMessageTable(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::String> origin_taint,
    v8::internal::Handle<v8::internal::String> compare) {
  Handle<FixedArray> value = isolate->factory()->NewFixedArray(2);
  value->set(0, *origin_taint);
  value->set(1, *compare);
  int64_t key = origin_taint->taint_info();
  if (key == 0 || key == kUndefinedInstanceCounter) {
    // This means the key was not initialized, but there is a check.
    return;
  }

  DCHECK_NE(key, kUndefinedInstanceCounter);
  DCHECK_NE(key, 0);

  Handle<ObjectHashTable> new_table = ObjectHashTable::Put(
      cross_origin_message_table_,
      isolate->factory()->NewNumberFromInt64(key),
      value);

  if (new_table.location() != cross_origin_message_table_.location()) {
    cross_origin_message_table_ = Handle<ObjectHashTable>::cast(
        isolate->global_handles()->Create(*new_table.location()));
  }
}

void RuntimeParameterToContextStorage(
    v8::internal::Isolate* isolate,
    int parameter_index,
    int context_slot_index,
    v8::internal::Handle<v8::internal::Context> context) {
  if (EnableConcolic()) {
    TaintTracker::FromIsolate(isolate)->Get()->Exec()
      .OnRuntimeParameterToContextStorage(
          parameter_index, context_slot_index, context);
  }
}






}

STATIC_ASSERT(tainttracking::TaintType::UNTAINTED == 0);
STATIC_ASSERT(sizeof(tainttracking::TaintFlag) * kBitsPerByte >=
              tainttracking::TaintType::MAX_TAINT_TYPE);

