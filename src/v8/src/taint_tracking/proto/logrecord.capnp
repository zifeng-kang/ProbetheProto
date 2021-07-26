@0x9b61a0c1a03f2616;

using Ast = import "ast.capnp" .Ast;

struct TaintLogRecord {

  enum TaintType {
    untainted @0;
    tainted @1;
    cookie @2;
    message @3;
    url @4;
    urlHash @13;
    urlProtocol @14;
    urlHost @15;
    urlHostname @16;
    urlOrigin @17;
    urlPort @18;
    urlPathname @19;
    urlSearch @20;
    dom @5;
    referrer @6;
    windowname @7;
    storage @8;
    network @9;
    javascriptUrl @12;
    multipleTaints @10;
    error @11;
  }

  enum TaintEncoding {
    unknown @0;
    none @1;
    urlEncoded @2;
    urlComponentEncoded @3;
    escapeEncoded @4;
    multipleEncodings @5;
    urlDecoded @6;
    urlComponentDecoded @7;
    escapeDecoded @8;
  }

  enum SymbolicOperation {
    concat @0;
    slice @1;
    literal @2;
    external @3;
    parsedJson @4;
    stringifiedJson @5;
    regexp @6;
    join @7;
    caseChange @8;
    uriEncode @9;
    uriDecode @10;
    uriEscape @11;
    uriUnescape @12;
    incrementalBuild @13;
    uriComponentDecode @14;
    uriComponentEncode @15;
  }

  enum SinkType {
    url @0;
    embedSrcSink @11;
    iframeSrcSink @12;
    anchorSrcSink @13;
    imgSrcSink @14;
    scriptSrcUrlSink @15;
    javascript @1;
    javascriptEventHandlerAttribute @16;
    html @2;
    messageData @3;
    cookie @4;
    storage @5;
    origin @6;
    domUrl @7;
    element @8;
    javascriptUrl @9;
    css @10;
    cssStyleAttribute @17;
    javascriptSetInterval @18;
    javascriptSetTimeout @19;
    locationAssignment @20;
    prototypePollution @21;
  }

  enum BranchType {
    if @0;
    loop @1;
    switch @2;
    conditional @3;
  }

  struct TaintRange {
    start @0 :UInt32;
    end @1 :UInt32;
    type @2 :TaintType;
    encoding @3 :TaintEncoding;
  }

  struct TaintInformation {
    ranges @0 :List(TaintRange);
  }

  struct TaintMessage {
    sourceName @0 :Text;
    sourceUrl @1 :Text;
    sourceCode @2 :Text;
    taintType @3 :TaintInformation;
  }

  struct JsSinkTainted {
    struct MessageOriginCheckInfo {
      originString @0 :Ast.JsString;
      comparedString @1 :Ast.JsString;
    }

    taintSource @0 :TaintInformation;
    targetString @1 :Ast.JsString;
    symbolicRef @2 :Int64;
    sinkType @3 :SinkType;
    size @4 :Int64;
    symbolicValue @5 :SymbolicValue;
    stackTrace @6 :Text;

    # Optional. Only present if the JS source is from a message, and the message
    # had its origin checked before the injection.
    messageOriginCheck @7 :MessageOriginCheckInfo;
  }

  struct JsLog {
    logMessage @0 :Ast.JsString;
    extraRefTaint @1 :Int64;
  }

  struct SetTaint {
    targetId @0 :Int64;
    taintType @1 :TaintType;
  }

  struct SymbolicLog {
    targetId @0 :Int64;
    targetValue @1 :Ast.JsString;
    argRefs @2 :List(Int64);
    taintValue @3 :TaintInformation;
    symbolicOperation @4 :SymbolicOperation;
  }

  struct DebugMessage {
    struct MemoryError {
      symbolicRef @0 :Int64;
    }

    message @0 :List(Text);
    stackTrace @1 :Text;
    messageType :union {
      generic @2 :Void;
      memoryError @3 :MemoryError;
    }
  }

  struct SymbolicValue {
    struct TaintedInput {
      taintValue @0 :TaintInformation;
    }

    struct BinaryOperation {
      token @0 :Ast.Token;
      left @1 :SymbolicValue;
      right @2 :SymbolicValue;
    }

    struct UnaryOperation {
      token @0 :Ast.Token;
      expression @1 :SymbolicValue;
    }

    struct Conditional {
      cond @0 :SymbolicValue;
      then @1 :SymbolicValue;
      else @2 :SymbolicValue;
    }

    struct PropertyAccess {
      obj @0 :SymbolicValue;
      key @1 :SymbolicValue;
    }

    struct Call {
      enum Type {
        unknown @0;
        callNew @1;
        call @2;
      }

      type @2 :Type;
      expression @0 :SymbolicValue;
      args @1 :List(SymbolicValue);
    }

    struct CallRuntime {
      expression @1 :Ast.CallRuntime.RuntimeInfo;
      args @0 :List(SymbolicValue);
    }

    struct ApiCallReturn {
      value :union {
        unknown @1 :Void;
        documentUrl @0 :Void;
      }
    }

    struct MergedState {
      enum Type {
        unknown @0;
        call @1;
        property @2;
      }

      type @2 :Type;
      primary @0 :SymbolicValue;
      secondary @1 :SymbolicValue;
    }

    struct ArrayLiteral {
      values @0 :List(SymbolicValue);
    }

    struct KeyValue {
      key @0 :SymbolicValue;
      value @1 :SymbolicValue;
    }

    struct ObjectLiteral {
      keyValues @0 :List(KeyValue);
    }

    struct ObjectAssignment {
      keyValue @0 :KeyValue;

      # Should be a literal JsObject or object literal or array literal
      rest @1 :SymbolicValue;
    }

    struct Uninstrumented {
      enum Type {
        unknown @0;
        receiver @1;
        thrownException @2;
        argument @3;
        optimizedOut @4;
      }

      type @0 :Type;
    }

    value :union {
      literal @0 :Void;
      astLiteral @8 :Ast.JsObjectValue;
      taintedInput @1 :TaintedInput;
      binaryOperation @2 :BinaryOperation;
      unaryOperation @3 :UnaryOperation;
      conditional @6 :Conditional;
      dummy @4 :Void;
      property @7 :PropertyAccess;
      call @9 :Call;
      optimizedOut @11 :Uninstrumented;
      unexecuted @13 :Void;
      callRuntime @14 :CallRuntime;
      apiValue @15 :ApiCallReturn;
      merged @16 :MergedState;
      alreadySerialized @18 :Void;
      arrayLiteral @19 :ArrayLiteral;
      objectLiteral @20 :ObjectLiteral;
      objectAssignment @21 :ObjectAssignment;
      lvalue @22 :Void;
    }

    concrete @10 :Ast.JsObjectValue;

    # Used for debugging purposes
    comment @5 :List(Text);
    label @12 :Ast.NodeLabel;

    uniqueId @17 :Int64;
  }

  struct SymbolicConstraint {
    # Must be converted to a boolean
    constraint :union {
      assertion @0 :SymbolicValue;
      assertNot @3 :SymbolicValue;
      jump @1 :SymbolicValue;
      switchTag @2 :SymbolicValue;
      iterator @4 :SymbolicValue;
    }
  }

  struct NavigateEvent {
    url @0 :Ast.JsString;
  }

  struct JobId {
    jobId @0 :Text;
    timestampMillisSinceEpoch @1 :Int64;
  }

  message :union {
    taintMessage @0 :TaintMessage;
    jsSinkTainted @1 :JsSinkTainted;
    jsLog @2 :JsLog;
    symbolicLog @3 :SymbolicLog;
    error @4 :DebugMessage;
    setTaint @6 :SetTaint;
    runtimeLog @8 :Ast.RuntimeLog;
    taintedControlFlow @10 :SymbolicConstraint;
    ast @9 :Ast;
    navigate @11 :NavigateEvent;
    cachedValue @12 :SymbolicValue;
    jobId @14 :JobId;
  }

  isolate @5 :UInt64;
  messageId @7 :UInt64;
  contextId @13 :Ast.JsObjectValue;
}

struct TaintLogRecordGroup {
  contents @0 :List(TaintLogRecord);
}

