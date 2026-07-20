use std::fmt;

// ============================================================================
// AST NODE TYPES FOR BXEN v0.1
// ============================================================================
// Minimal viable set for Stage 0 compiler.
// Designed for direct lowering to x86_64 - no complex hierarchies.

// ---- Literal Types ----

#[derive(Debug, Clone, PartialEq)]
pub enum ValueType {
    I64,
    F64,
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueType::I64 => write!(f, "i64"),
            ValueType::F64 => write!(f, "f64"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LiteralValue {
    Int(i64),
    Float(f64),
    String(String),
}

impl fmt::Display for LiteralValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiteralValue::Int(v) => write!(f, "{}", v),
            LiteralValue::Float(v) => write!(f, "{}", v),
            LiteralValue::String(v) => write!(f, "\"{}\"", v),
        }
    }
}

// ---- Expressions (stack-based) ----

#[derive(Debug, Clone, PartialEq)]
pub struct Literal {
    pub value: LiteralValue,
    pub ty: ValueType,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Parameter {
    pub name: String,
    pub ty: ValueType,
}

impl fmt::Display for Parameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.ty)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinaryOp {
    Add,      // +
    Sub,      // -
    Mul,      // *
    Div,      // /
    Mod,      // %
    BitAnd,   // &
    BitOr,    // |
    BitXor,   // ^
    Shl,      // <<
    Shr,      // >>
    Eq,       // ==
    Ne,       // !=
    Lt,       // <
    Le,       // <=
    Gt,       // >
    Ge,       // >=
}

impl fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinaryOp::Add => write!(f, "+"),
            BinaryOp::Sub => write!(f, "-"),
            BinaryOp::Mul => write!(f, "*"),
            BinaryOp::Div => write!(f, "/"),
            BinaryOp::Mod => write!(f, "%"),
            BinaryOp::BitAnd => write!(f, "&"),
            BinaryOp::BitOr => write!(f, "|"),
            BinaryOp::BitXor => write!(f, "^"),
            BinaryOp::Shl => write!(f, "<<"),
            BinaryOp::Shr => write!(f, ">>"),
            BinaryOp::Eq => write!(f, "=="),
            BinaryOp::Ne => write!(f, "!="),
            BinaryOp::Lt => write!(f, "<"),
            BinaryOp::Le => write!(f, "<="),
            BinaryOp::Gt => write!(f, ">"),
            BinaryOp::Ge => write!(f, ">="),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UnaryOp {
    Pos,      // + (identity, no-op on the value)
    Negate,   // -
    Not,      // ! (logical)
    BitNot,   // ~
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnaryOp::Pos => write!(f, "+"),
            UnaryOp::Negate => write!(f, "-"),
            UnaryOp::Not => write!(f, "!"),
            UnaryOp::BitNot => write!(f, "~"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Variable {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    Literal(Literal),
    Variable(Variable),
    Binary {
        op: BinaryOp,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Unary {
        op: UnaryOp,
        operand: Box<Expression>,
    },
    Call {
        name: String,
        args: Vec<Expression>,
    },
}

// ---- Statements ----

#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub name: String,
    pub value: Expression,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SinkCall {
    pub name: String,
    pub args: Vec<Expression>,
    pub sink_name: Option<String>,
}

impl fmt::Display for SinkCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        write!(f, ".")?;
        write!(f, "{}", self.sink_name.as_deref().unwrap_or("out"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Return {
    pub value: Option<Expression>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    Assignment(Assignment),
    Expression(Expression),
    Sink(SinkCall),
    Return(Return),
    // Control flow: condition is an expression evaluated to 0/1; truthiness
    // is decided by `== 0` (nonzero = true). The `else` arm is optional to
    // keep the grammar minimal; once we add `else if` we desugar to nested.
    If {
        condition: Expression,
        then_branch: Vec<Statement>,
        else_branch: Option<Vec<Statement>>,
    },
    While {
        condition: Expression,
        body: Vec<Statement>,
    },
}

// ---- Blocks ----

#[derive(Debug, Clone, PartialEq)]
pub struct HeaderBlock {
    pub items: Vec<(String, String)>,  // key-value pairs like "version", "0.1"
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModuleBlock {
    pub name: String,
    pub statements: Vec<Statement>,
    pub functions: Vec<FunctionBlock>,
    pub inputs: Vec<Parameter>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionBlock {
    pub name: String,
    pub params: Vec<Parameter>,
    pub return_type: ValueType,
    pub body: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InputBlock {
    pub items: Vec<(String, String)>,  // input variable declarations with types
}

#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub header: Option<HeaderBlock>,
    pub inputs: Option<InputBlock>,
    pub modules: Vec<ModuleBlock>,
}


