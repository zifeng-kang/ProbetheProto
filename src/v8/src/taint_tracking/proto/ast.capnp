@0xd323f4577284d1c3;

struct Ast {
  enum VariableMode {
    var @0;
    constLegacy @1;
    let @2;
    import @3;
    const @4;
    temporary @5;
    dynamic @6;
    dynamicGlobal @7;
    dynamicLocal @8;
  }

  struct JsString {
    struct FlatJsString {
      content @0 :Data;
      isOneByte @1 :Bool;
    }

    segments @0 :List(FlatJsString);
  }

  struct NodeLabel {
    # Id of expression in AST
    nodeReference @0 :UInt32;
    # random compile-time constant for disambiguation
    nodeCompileConst @1 :UInt64;
  }

  struct RuntimeLog {
    enum CheckType {
      statementBefore @0;
      statementAfter @1;
      expressionBefore @2;
      expressionAfter @3;
    }

    obj @0 :JsObjectValue;
    label @1 :NodeLabel;
    objectLabel @2 :Int64;
    checkType @3 :CheckType;
  }

  struct ScopePointer {
    parentExprId @0 :Int64;
  }

  struct DeclarationScope {
    scope @0 :ScopePointer;
    declarations @1 :List(Declaration);
  }

  enum InitializationFlag {
    createdInitialized @0;
    needsInitialization @1;
  }

  struct DeclarationInterface {
    proxy @0 :VariableProxyNode;
    mode @1 :VariableMode;
    scope @2 :ScopePointer;
  }

  enum KeyedAccessStoreMode {
    standardStore @0;
    storeTransitionToObject @1;
    storeTransitionToDouble @2;
    storeAndGrowNoTransition @3;
    storeAndGrowTransitionToObject @4;
    storeAndGrowTransitionToDouble @5;
    storeNoTransitionIgnoreOutOfBounds @6;
    storeNoTransitionHandleCow @7;
  }

  enum FunctionKind {
    normalFunction @0;
    arrowFunction @1;
    generatorFunction @2;
    conciseMethod @3;
    conciseGeneratorMethod @4;
    getterFunction @5;
    setterFunction @6;
    accessorFunction @7;
    defaultBaseConstructor @8;
    defaultSubclassConstructor @9;
    baseConstructor @10;
    subClassConstructor @11;
    asyncFunction @12;
    asyncArrowFunction @13;
    asyncConciseMethod @14;
  }

  enum Type {
  # TODO
  }

  enum Token {

    # Binary operations
    comma @0;
    or @1;
    and @2;
    bitOr @3;
    bitXor @4;
    bitAnd @5;
    shl @6;
    sar @7;
    shr @8;
    ror @9;
    add @10;
    sub @11;
    mul @12;
    div @13;
    mod @14;
    exp @15;
    init @32;

    # counting
    inc @45;
    dec @46;

    # Assignments
    assign @31;
    assignBitOr @33;
    assignBitXor @34;
    assignBitAnd @35;
    assignShl @36;
    assignSar @37;
    assignShr @38;
    assignAdd @39;
    assignSub @40;
    assignMul @41;
    assignDiv @42;
    assignMod @43;
    assignExp @44;


    # comparisons
    eq @16;
    ne @17;
    eqStrict @18;
    neStrict @19;
    lt @20;
    gt @21;
    lte @22;
    gte @23;
    instanceof @24;
    in @25;

    # Unary operators
    not @26;
    bitNot @27;
    delete @28;
    typeof @29;
    void @30;

    # Signals an error
    unknown @47;
  }

  struct ApiFunctionData {
    serialNumber @0 :Int32;
  }

  struct BuiltinFunctionData {
    id @0 :Int32;
    name @1 :Text;
  }

  struct FunctionInstance {
    name @0 :JsString;
    fnLabel @4 :NodeLabel;
    scriptName @5 :JsObjectValue;
    startPosition @6 :Int64;
    endPosition @7 :Int64;
    scriptId @8 :Int64;
    receiver @9 :JsObjectValue;

    type :union {
      apiFunction @1 :ApiFunctionData;
      builtinFunction @2 :BuiltinFunctionData;
      jsFunction @3 :Void;
    }
  }

  struct RegExp {
    enum Flag {
      none @0;
      global @1;
      ignoreCase @2;
      multiline @3;
      sticky @4;
      unicode @5;
    }

    source @0 :JsString;
    flags @1 :List(Flag);
    receiver @2 :JsObjectValue;
  }

  struct KeyValue {
    key @0 :JsObjectValue;
    value @1 :JsObjectValue;
  }

  struct JsReceiver {
    enum Type {
      unknown @0;
      object @1;
      array @2;
    }

    keyValues @0 :List(KeyValue);
    type @1 :Type;
  }

  struct JsObjectValue {
    value :union {
      string @0 :JsString;
      smi @1 :Int32;
      number @2 :Float64;
      boolean @3 :Bool;
      nullObject @4 :Void;
      undefined @5 :Void;
      symbol @6 :JsString;
      theHole @7 :Void;
      function @8 :FunctionInstance;
      unknown @9 :Void;
      regexp @10 :RegExp;
      receiver @11 :JsReceiver;
      astObjectLiteral @12 :ObjectLiteral;
      astArrayLiteral @13 :ArrayLiteral;
      previouslySerialized @14 :Void;
      unserializedObject @16 :Void;
    }

    uniqueId @15 :Int64;
  }

  struct Variable {
    enum Kind {
      normal @0;
      function @1;
      this @2;
      arguments @3;
    }

    enum Location {
      parameter @0;
      unallocated @1;
      context @2;
      global @3;
      lookupSlot @4;
      local @5;
    }

    scope @0 :ScopePointer;
    name @1 :JsString;
    mode @2 :VariableMode;
    kind @3 :Kind;
    initializationFlag @4 :InitializationFlag;
    location @5 :Location;
  }

  # Begin node types
  struct FunctionDeclaration {
    declaration @0 :DeclarationInterface;
    functionLiteral @1 :FunctionLiteralNode;
  }

  struct DoWhileStatement {
    cond @0 :Expression;
    body @1 :Statement;
  }

  struct WhileStatement {
    cond @0 :Expression;
    body @1 :Statement;
  }

  struct ForStatement {
    cond @0 :Expression;
    body @1 :Statement;
    init @2 :Statement;
    next @3 :Statement;
  }

  struct ForInStatement {
    body @0 :Statement;
    each @1 :Expression;
    subject @2 :Expression;
  }

  struct ContinueStatement {}
  struct BreakStatement {}

  struct ReturnStatement {
    value @0 :Expression;
  }

  struct CaseClause {
    label @0 :Expression;
    isDefault @2 :Bool;
    statements @1 :List(Statement);
    node @3 :NodeInfo;
  }

  struct SwitchStatement {
    tag @0 :Expression;
    caseClauses @1 :List(CaseClause);
  }

  struct IfStatement {
    cond @0 :Expression;
    then @1 :Statement;
    else @2 :Statement;
  }


  struct ForOfStatement {
    body @0 :Statement;
    iterator @1 :Variable;
    assignIterator @2 :Expression;
    nextResult @3 :Expression;
    resultDone @4 :Expression;
    assignEach @5 :Expression;
  }

  struct WithStatement {
    scope @0 :ScopePointer;
    expression @1 :Expression;
    statement @2 :Statement;
  }

  struct BlockNode {
    block @0 :Block;
    node @1 :NodeInfo;
  }

  struct TryCatchStatement {
    scope @0 :ScopePointer;
    variable @1 :Variable;
    catchBlock @2 :BlockNode;
    tryBlock @3 :BlockNode;
  }

  struct TryFinallyStatement {
    tryBlock @0 :BlockNode;
    finallyBlock @1 :BlockNode;
  }

  struct EmptyStatement {}

  struct Literal {
    objectValue @0 :JsObjectValue;
  }

  struct RegExpLiteral {
    pattern @0 :JsString;
    flags @1 :Int32;
  }

  struct ArrayLiteral {
    values @0 :List(Expression);
    isSimple @1 :Bool;          # True means the value is available at compile
                                # time
  }

  struct VariableProxy {
    value :union {
      name @0 :JsString;
      var @1 :Variable;
    }
    isThis @2 :Bool;
    isAssigned @3 :Bool;
    isResolved @4 :Bool;
    isNewTarget @5 :Bool;
  }

  struct Property {
    obj @0 :Expression;
    key @1 :Expression;
    isForCall @2 :Bool;
    isStringAccess @3 :Bool;
  }

  struct Call {
    enum CallType {
    # Currently only uses global call type
      possiblyEvalCall @0;
      globalCall @1;
      lookupSlotCall @2;
      namedPropertyCall @3;
      keyedPropertyCall @4;
      namedSuperPropertyCall @5;
      keyedSuperPropertyCall @6;
      superCall @7;
      otherCall @8;
      unknown @9;
    }

    expression @0 :Expression;
    arguments @1 :List(Expression);
    callType @2 :CallType;
  }

  struct CallNew {
    expression @0 :Expression;
    arguments @1 :List(Expression);
  }

  struct CallRuntime {
    struct RuntimeFunction {
      id @0 :Int64;
      name @1 :Text;
    }

    struct RuntimeInfo {
      fn :union {
        runtimeFunction @0 :RuntimeFunction;
        contextIndex @1 :Int32;
      }
    }

    arguments @1 :List(Expression);
    info @0 :RuntimeInfo;
  }

  struct UnaryOperation {
    expression @0 :Expression;
    token @1 :Token;
  }

  struct BinaryOperation {
    left @0 :Expression;
    right @1 :Expression;
    token @2 :Token;
  }

  struct CompareOperation {
    token @0 :Token;
    type @1 :Type;
    left @2 :Expression;
    right @3 :Expression;
  }

  struct Conditional {
    cond @0 :Expression;
    then @1 :Expression;
    else @2 :Expression;
  }

  struct Assignment {
    target @0 :Expression;
    value @1 :Expression;
    operation @2 :Token;
    isUninitializedField @3 :Bool;
    storeMode @4 :KeyedAccessStoreMode;
    isSimple @5 :Bool;
  }

  struct FunctionLiteralNode {
    func @0 :FunctionLiteral;
    node @1 :NodeInfo;

    # Byte position in source code of the end
    endPosition @2 :Int64;
    functionTokenPosition @3 :Int64;
  }

  struct FunctionLiteral {
    enum FunctionType {
      anonymousExpression @0;
      namedExpression @1;
      declaration @2;
      accessorOrMethod @3;
    }

    name @0 :JsString;
    functionType @1 :FunctionType;
    functionKind @2 :FunctionKind;
    scope @3 :DeclarationScope;
    body @4 :List(Statement);
  }

  struct ClassLiteral {
  # TODO
  }

  struct NativeFunctionLiteral {
    name @0 :Text;
    extensionName @1 :Text;
  }

  struct ThisFunction {}
  struct EmptyParentheses {}

  struct SuperPropertyReference {
    thisVar @0 :VariableProxyNode;
    homeObject @1 :Expression;
  }

  struct VariableProxyNode {
    proxy @0 :VariableProxy;
    node @1 :NodeInfo;
  }

  struct SuperCallReference {
    thisVar @0 :VariableProxyNode;
    newTargetVar @1 :VariableProxyNode;
    thisFunctionVar @2 :VariableProxyNode;
  }

  struct Block {
    scope @0 :ScopePointer;
    statements @1 :List(Statement);
  }

  struct LiteralProperty {
    enum Kind {
      constant @0;              # Property with constant value (compile time)
      computed @1;              # Property with computed value (execution time).
      materializedLiteral @2;   # Property value is materialized at compile time.
      getter @3;
      setter @4;    # Property is an accessor function.
      prototype @5; # Property is __proto__.
    }

    key @0 :Expression;
    value @1 :Expression;
    isComputedName @2 :Bool;
    isStatic @3 :Bool;
    kind @4 :Kind;
  }

  struct ObjectLiteral {
    properties @0 :List(LiteralProperty);
    isSimple @1 :Bool;          # True means the value is available at compile
                                # time
  }

  struct CountOperation {
    operation @0 :Token;
    expression @1 :Expression;
    isPrefix @2 :Bool;
    isPostfix @3 :Bool;
    storeMode @4 :KeyedAccessStoreMode;
  }

  struct Throw {
    exception @0 :Expression;
  }

  struct Spread {
  # TODO
  }

  struct DoExpression {
    block @0 :BlockNode;
    result @1 :VariableProxyNode;
    representedFunction @2 :FunctionLiteralNode;
  }

  struct Yield {
    generator @0 :Expression;
    expression @1 :Expression;
  }

  struct Declaration {
    nodeVal :union {
      variableDeclaration @0 :DeclarationInterface;
      functionDeclaration @1 :FunctionDeclaration;
    }

    node @2 :NodeInfo;
  }

  struct ExpressionStatement {
    expression @0 :Expression;
  }

  struct Statement {
    nodeVal :union {
      unknownStatement @0 :Void;

      doWhileStatement @1 :DoWhileStatement;
      whileStatement @2 :WhileStatement;
      forStatement @3 :ForStatement;
      forInStatement @4 :ForInStatement;
      forOfStatement @5 :ForOfStatement;
      block @6 :Block;
      switchStatement @7 :SwitchStatement;
      emptyStatement @8 :EmptyStatement;
      ifStatement @9 :IfStatement;
      continueStatement @10 :ContinueStatement;
      breakStatement @11 :BreakStatement;
      returnStatement @12 :ReturnStatement;
      withStatement @13 :WithStatement;
      tryCatchStatement @14 :TryCatchStatement;
      tryFinallyStatement @15 :TryFinallyStatement;
      expressionStatement @16 :ExpressionStatement;
      debuggerStatement @18 :Void;
    }

    node @17 :NodeInfo;
  }

  struct Expression {
    nodeVal :union {
      regExpLiteral @0 :RegExpLiteral;
      objectLiteral @1 :ObjectLiteral;
      arrayLiteral @2 :ArrayLiteral;
      assignment @3 :Assignment;
      countOperation @4 :CountOperation;
      property @5 :Property;
      call @6 :Call;
      callNew @7 :CallNew;
      functionLiteral @8 :FunctionLiteral;
      classLiteral @9 :ClassLiteral;
      nativeFunctionLiteral @10 :NativeFunctionLiteral;
      conditional @11 :Conditional;
      variableProxy @12 :VariableProxy;
      literal @13 :Literal;
      yield @14 :Yield;
      throw @15 :Throw;
      callRuntime @16 :CallRuntime;
      unaryOperation @17 :UnaryOperation;
      binaryOperation @18 :BinaryOperation;
      compareOperation @19 :CompareOperation;
      spread @20 :Spread;
      thisFunction @21 :ThisFunction;
      superPropertyReference @22 :SuperPropertyReference;
      superCallReference @23 :SuperCallReference;
      caseClause @24 :CaseClause;
      emptyParentheses @25 :EmptyParentheses;
      doExpression @26 :DoExpression;
    }

    node @27 :NodeInfo;
  }

  struct NodeInfo {
    label @0 :NodeLabel;
    position @1 :Int64;
  }

  # Will be a function literal
  root @0 :FunctionLiteralNode;

  # should be string values
  source @1 :JsObjectValue;
  sourceSha256 @8 :Text;
  sourceUrl @2 :JsString;
  scriptName @3 :JsString;

  # Often the url

  scriptId @4 :Int64;
  startPosition @5 :Int64;
  endPosition @6 :Int64;
  functionTokenPosition @7 :Int64;
}

