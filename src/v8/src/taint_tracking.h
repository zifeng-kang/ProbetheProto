#ifndef TAINT_TRACKING_H_
#define TAINT_TRACKING_H_


// This file has the main external declarations for taint tracking.


#include "include/v8.h"
#include "src/base/utils/random-number-generator.h"
#include "src/objects.h"
#include "src/parsing/token.h"

#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <vector>

namespace v8 {
namespace internal {
class FunctionLiteral;
class Parser;
class ParseInfo;
};
};

namespace tainttracking {

class AstSerializer;

typedef v8::String::TaintType TaintType;
typedef v8::String::TaintSinkLabel TaintSinkLabel;
typedef v8::String::TaintData TaintData;
const uint64_t NO_MESSAGE = -1;

enum Status {
  OK = 1,
  FAILURE = 0
};

class NodeLabel {
public:
  typedef uint64_t Rand;
  typedef uint32_t Counter;

  class Labeler {
  public:
    NodeLabel New();

    Labeler(v8::internal::Isolate*);
  private:
    Counter counter_;
    v8::base::RandomNumberGenerator* rng_;
  };

  struct Hash {
    std::size_t operator() (NodeLabel const& val) const;

  private:
    std::hash<uint64_t> underlying_;
  };

  struct EqualTo {
    bool operator() (const NodeLabel& one, const NodeLabel& two) const;
  };

  bool Equals(const NodeLabel&) const;
  void CopyFrom(const NodeLabel& other);

  NodeLabel();
  NodeLabel(Rand, Counter);
  NodeLabel(const NodeLabel& other);

  Rand GetRand() const;
  Counter GetCounter() const;
  bool IsValid() const;

private:

  Rand rand_;
  Counter counter_;
};

class V8NodeLabelSerializer {
public:
  V8NodeLabelSerializer(v8::internal::Isolate*);
  Status Serialize(v8::internal::Handle<v8::internal::Object>*,
                   const NodeLabel&);
  Status Serialize(v8::internal::Object**,
                   const NodeLabel&);
  Status Deserialize(v8::internal::Handle<v8::internal::Object>, NodeLabel*);
  Status Deserialize(v8::internal::Object*, NodeLabel*);

private:
  v8::internal::Handle<v8::internal::Object> Make(const NodeLabel& label);

  static const int COUNT_INDEX = 0;
  static const int RAND_INDEX = COUNT_INDEX + 1;
  static const int SIZE = RAND_INDEX + 1;

  v8::internal::Isolate* isolate_;
};


enum ValueState {
  NONE,
  OPTIMIZED_OUT,
  STATIC_VALUE,
  ADD_HOOK,
  UNEXECUTED,
  STATEMENT,
  LVALUE,
  PROPERTY_LVALUE
};

enum SymbolicType {
  CONCAT,
  SLICE,
  LITERAL,
  EXTERNAL,
  PARSED_JSON,
  STRINGIFIED_JSON,
  REGEXP,
  JOIN,
  CASE_CHANGE,
  URI_ENCODE,
  URI_DECODE,
  URI_COMPONENT_ENCODE,
  URI_COMPONENT_DECODE,
  URI_ESCAPE,
  URI_UNESCAPE,
  INCREMENTAL_BUILD,
};

enum CheckType {
  STATEMENT_BEFORE,
  STATEMENT_AFTER,
  EXPRESSION_BEFORE,
  EXPRESSION_AFTER,
  EXPRESSION_AFTER_OPTIMIZED_OUT,
  EXPRESSION_UNEXECUTED,
  STATIC_VALUE_CHECK,
  EXPRESSION_VARIABLE_LOAD_GLOBAL,
  EXPRESSION_VARIABLE_LOAD,
  EXPRESSION_PARAMETER_LOAD,
  EXPRESSION_PARAMETER_STORE,
  EXPRESSION_VARIABLE_LOAD_CONTEXT_LOOKUP,
  EXPRESSION_VARIABLE_STORE,
  EXPRESSION_VARIABLE_STORE_CONTEXT,
  EXPRESSION_PROPERTY_STORE,
  EXPRESSION_LVALUE,
  EXPRESSION_PROPERTY_LVALUE
};

// -1 is used by the receiver parameter
static const int NO_VARIABLE_INDEX = -2;
static const int RECEIVER_VARIABLE_INDEX = -1;


enum BranchType {
  LOOP,
  IF,
  SWITCH,
  CONDITIONAL
};

typedef uint32_t TaintFlag;
const TaintFlag kTaintFlagUntainted = 0;

typedef int64_t InstanceCounter;
const InstanceCounter kUndefinedInstanceCounter = -1;

std::string TaintTypeToString(TaintType type);
std::string TaintFlagToString(TaintFlag flag);
TaintFlag AddFlag(TaintFlag current, TaintType new_value,
                  v8::internal::String* object = nullptr);

struct TaintInstanceInfo {
  char const* name;
  char const* source_url;
  char const* source_code;
  TaintFlag taint_flag;
  std::vector<std::tuple<TaintType, int>> ranges;
};

class TaintListener {
public:
  virtual ~TaintListener() {};
  virtual void OnTaintedCompilation(const TaintInstanceInfo& info,
                                    v8::internal::Isolate* isolate) = 0;
};

class TaintTracker final {
public:
  class Impl;

  ~TaintTracker();

  void Initialize(v8::internal::Isolate* isolate);

  void RegisterTaintListener(TaintListener* listener);
  bool IsRewriteAstEnabled();

  Impl* Get();
  InstanceCounter* symbolic_elem_counter();

  static TaintTracker* FromIsolate(v8::internal::Isolate* isolate);
  static void OnBeforeCompile(
      v8::internal::Handle<v8::internal::Script> script,
      v8::internal::Isolate* isolate);
  static TaintTracker* New(bool enable_serializer,
                           v8::internal::Isolate* isolate);

private:
  TaintTracker(bool enable_serializer, v8::internal::Isolate* isolate);

  std::unique_ptr<Impl> impl_;
};

const bool kTaintTrackingEnabled = true;
const bool kInternalizedStringsEnabled = !kTaintTrackingEnabled;


// Functions for manipulating taint data
template <class T>
void InitTaintData(T* str, TaintType type = TaintType::UNTAINTED);

template <> void InitTaintData<v8::internal::SeqOneByteString>(
    v8::internal::SeqOneByteString* str, TaintType type);
template <> void InitTaintData<v8::internal::SeqTwoByteString>(
    v8::internal::SeqTwoByteString* str, TaintType type);

template <class T>
void CopyOut(T* source, TaintData* dest, int offset, int len);
template <class T>
void CopyIn(T* dest, TaintType source, int offset, int len);
template <class T>
void CopyIn(T* dest, const TaintData* source, int offset, int len);

template <class T> void FlattenTaintData(
    T* source, TaintData* dest, int from_offset, int from_len);
template <class T, class S>
void FlattenTaint(S* source, T* dest, int from_offset, int from_len);

int64_t LogIfTainted(
    v8::internal::Handle<v8::internal::String> str,
    v8::String::TaintSinkLabel label,
    int symbolic_data);

template <typename Char>
int64_t LogIfBufferTainted(TaintData* buffer,
                           const Char* stringdata,
                           size_t length,
                           int symbolic_data,
                           v8::internal::Isolate* isolate,
                           v8::String::TaintSinkLabel label);

void SetTaintOnObject(v8::internal::Handle<v8::internal::Object> obj,
                      TaintType type);

template <class T>
TaintType GetTaintStatusRange(T* source, size_t idx_start, size_t length);
template <class T> TaintType GetTaintStatus(T* object, size_t idx);
template <class T> void SetTaintStatus(T* object, size_t idx, TaintType type);
template <class T> TaintData* GetWriteableStringTaintData(T* str);


// Event listeners for New strings and operations
template <class T> void OnNewStringLiteral(T* source);
void OnNewDeserializedString(v8::internal::String* source);
template <class T> void OnNewExternalString(T* str);
template <class T, class S> void OnNewSubStringCopy(
    T* source, S* dest, int offset, int length);
template <class T, class S, class R> void OnNewConcatStringCopy(
    T* dest, S* first, R* second);
void OnNewConsString(v8::internal::ConsString* target,
                     v8::internal::String* first,
                     v8::internal::String* second);
void OnNewSlicedString(v8::internal::SlicedString* target,
                       v8::internal::String* first,
                       int offset, int length);
void OnNewFromJsonString(v8::internal::SeqString* target,
                         v8::internal::String* source);
template <class T> void OnNewReplaceRegexpWithString(
    v8::internal::String* subject,
    T* result,
    v8::internal::JSRegExp* pattern,
    v8::internal::String* replacement);
template <class T, class Array> void OnJoinManyStrings(
    T* target, Array* array);
template <class T> void OnConvertCase(
    v8::internal::String* source, T* answer);
template <class T> void OnGenericOperation(
    SymbolicType type, T* source);

// Tool kits
template <class T> void Print_String_Helper(T* source, int depth=0);

// Opaque hash that signals a change in the memory layout format. Useful for
// telling serialized code to recompile.
uint32_t LayoutVersionHash();


// Functions available from JS runtime

// This is also available to callers who embed v8
void SetTaint(v8::internal::Handle<v8::internal::Object> str,
              TaintType type);

void SetTaintInfo(v8::internal::Handle<v8::internal::Object> str, int64_t info);

void SetTaintString(v8::internal::Handle<v8::internal::String> str,
                    TaintType type);
void LogInitializeNavigate(v8::internal::Handle<v8::internal::String> url);
void LogDispose(v8::internal::Isolate* isolate);


void JSSetTaintBuffer(
    v8::internal::Handle<v8::internal::String> str,
    v8::internal::Handle<v8::internal::JSArrayBuffer> data);

MUST_USE_RESULT v8::internal::Handle<v8::internal::JSArrayBuffer>
JSGetTaintStatus(v8::internal::Handle<v8::internal::String> str,
                 v8::internal::Isolate* isolate);
void JSTaintLog(v8::internal::Handle<v8::internal::String> str,
                v8::internal::MaybeHandle<v8::internal::String> extra_ref);

v8::internal::Handle<v8::internal::Object> JSCheckTaintMaybeLog(
    v8::internal::Handle<v8::internal::String> str,
    v8::internal::Handle<v8::internal::Object> tag,
    int symbolic_data);

MUST_USE_RESULT v8::internal::Handle<v8::internal::HeapObject>
JSTaintConstants(v8::internal::Isolate* isolate);



// Symbolic analysis hooks


const int kRuntimeOnControlFlowExpArgs = 3;
const int kRuntimeOnControlFlowStatementArgs = 2;

// JS Runtime function
void RuntimeHook(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> target_object,
    v8::internal::Handle<v8::internal::Object> label,
    int checktype);

void RuntimeHookVariableLoad(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> target_object,
    v8::internal::Handle<v8::internal::Object> proxy_label,
    v8::internal::Handle<v8::internal::Object> past_assignment_label_or_idx,
    int checktype);

v8::internal::Handle<v8::internal::Object> RuntimeHookVariableStore(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> concrete,
    v8::internal::Handle<v8::internal::Object> label,
    CheckType checktype,
    v8::internal::Handle<v8::internal::Object> var_idx_or_holder);

void RuntimeHookVariableContextStore(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> concrete,
    v8::internal::Handle<v8::internal::Object> label,
    v8::internal::Handle<v8::internal::Context> context,
    v8::internal::Handle<v8::internal::Smi> smi);

void RuntimeExitSymbolicStackFrame(v8::internal::Isolate* isolate);

void RuntimePrepareSymbolicStackFrame(
    v8::internal::Isolate* isolate,
    FrameType type);

void RuntimeEnterSymbolicStackFrame(v8::internal::Isolate* isolate);

void RuntimeAddArgumentToStackFrame(
    v8::internal::Isolate* isolate,
    v8::internal::MaybeHandle<v8::internal::Object> label);

void RuntimeAddLiteralArgumentToStackFrame(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> value);

v8::internal::Handle<v8::internal::Object> GetSymbolicArgument(
    v8::internal::Isolate* isolate, uint32_t i);

bool HasLabel(v8::internal::Isolate* isolate, const NodeLabel& label);

bool SymbolicMatchesFunctionArgs(
    const v8::FunctionCallbackInfo<v8::Value>& info);

bool AllowDeserializingCode();

// Instrument AST with control flow checks
void InsertControlFlowHook(v8::internal::ParseInfo* info);

void SetSymbolicReturnValue(
    v8::internal::Isolate*,
    v8::internal::Handle<v8::internal::Object> object);

void RuntimeSetReturnValue(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> value,
    v8::internal::MaybeHandle<v8::internal::Object> label);

void RuntimeEnterTry(v8::internal::Isolate* isolate,
                     v8::internal::Handle<v8::internal::Object> label);
void RuntimeExitTry(v8::internal::Isolate* isolate,
                    v8::internal::Handle<v8::internal::Object> label);
void RuntimeOnThrow(v8::internal::Isolate* isolate,
                    v8::internal::Handle<v8::internal::Object> exception,
                    bool is_rethrow);
void RuntimeOnCatch(v8::internal::Isolate* isolate,
                    v8::internal::Handle<v8::internal::Object> thrown_object,
                    v8::internal::Handle<v8::internal::Context> context);
void RuntimeOnExitFinally(v8::internal::Isolate* isolate);

void RuntimeSetReceiver(v8::internal::Isolate* isolate,
                        v8::internal::Handle<v8::internal::Object> value,
                        v8::internal::Handle<v8::internal::Object> label);


v8::internal::Object* RuntimePrepareApplyFrame(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> argument_list,
    v8::internal::Handle<v8::internal::Object> target_fn,
    v8::internal::Handle<v8::internal::Object> new_target,
    v8::internal::Handle<v8::internal::Object> this_argument,
    FrameType caller_frame_type);

v8::internal::Object* RuntimePrepareCallFrame(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> target_fn,
    FrameType caller_frame_type,
    v8::internal::Handle<v8::internal::FixedArray> args);

v8::internal::Object* RuntimePrepareCallOrConstructFrame(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> target_fn,
    v8::internal::Handle<v8::internal::Object> new_target,
    v8::internal::Handle<v8::internal::FixedArray> args);

void RuntimeSetLiteralReceiver(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> target_fn);

void RuntimeCheckMessageOrigin(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> left,
    v8::internal::Handle<v8::internal::Object> right,
    v8::internal::Token::Value token);

void RuntimeParameterToContextStorage(
    v8::internal::Isolate* isolate,
    int parameter_index,
    int context_slot_index,
    v8::internal::Handle<v8::internal::Context> context);


} // namespace tainttracking

#endif

// Local Variables:
// mode: c++
// End:

