use crate::compiler::ast::*;
use crate::compiler::lexer::{Token, TokenType};

pub type Result<T> = std::result::Result<T, String>;

pub struct Parser {
    tokens: Vec<Token>,
    current: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, current: 0 }
    }

    pub fn parse(tokens: Vec<Token>) -> Result<Program> {
        let mut parser = Self::new(tokens);
        parser.parse_program()
    }

    fn parse_program(&mut self) -> Result<Program> {
        let mut header = None;
        let mut inputs = None;
        let mut modules = Vec::new();

        self.skip_newlines();

        loop {
            match self.peek().token_type {
                TokenType::Header => {
                    header = Some(self.parse_header()?);
                }
                TokenType::Input => {
                    inputs = Some(self.parse_input_block()?);
                }
                TokenType::Module => {
                    modules.push(self.parse_module()?);
                }
                TokenType::Eof => break,
                TokenType::RBrace | TokenType::Newline => {
                    self.advance();
                    continue;
                }
                _ => {
                    return Err(format!(
                        "Unexpected token at top level: {:?} at line {}, column {}",
                        self.peek().token_type, self.peek().line, self.peek().column
                    ));
                }
            }
            self.skip_newlines();
        }

        Ok(Program { header, inputs, modules })
    }
    fn parse_header(&mut self) -> Result<HeaderBlock> {
        self.expect(TokenType::Header)?;
        self.expect(TokenType::LBrace)?;
        let mut items = Vec::new();

        while !self.check(TokenType::RBrace) && !self.is_at_end() {
            self.skip_newlines();
            if self.check(TokenType::RBrace) {
                break;
            }
            let key = self.expect_identifier()?;
            self.expect(TokenType::Colon)?;
            let value = self.expect_header_value()?;

            items.push((key, value));
            self.skip_newlines();
        }

        self.expect(TokenType::RBrace)?;
        Ok(HeaderBlock { items })
    }

    fn expect_header_value(&mut self) -> Result<String> {
        let token = self.peek();
        match token.token_type {
            TokenType::Identifier(ref s) => {
                self.advance();
                Ok(s.clone())
            }
            TokenType::IntLiteral(v) => {
                self.advance();
                Ok(v.to_string())
            }
            TokenType::FloatLiteral(v) => {
                self.advance();
                Ok(v.to_string())
            }
            _ => Err(format!(
                "Expected header value at line {}, column {}",
                token.line, token.column
            )),
        }
    }

    fn parse_input_block(&mut self) -> Result<InputBlock> {
        self.expect(TokenType::Input)?;
        self.expect(TokenType::LBrace)?;
        let mut items = Vec::new();

        while !self.check(TokenType::RBrace) && !self.is_at_end() {
            self.skip_newlines();
            if self.check(TokenType::RBrace) {
                break;
            }
            let name = self.expect_identifier()?;
            self.expect(TokenType::Colon)?;
            let ty = self.expect_type()?;
            items.push((name, ty));
            self.skip_newlines();
        }

        self.expect(TokenType::RBrace)?;
        Ok(InputBlock { items })
    }

    fn expect_type(&mut self) -> Result<String> {
        match self.peek() {
            token if matches!(token.token_type, TokenType::Identifier(_)) => {
                let token = self.advance();
                match token.token_type {
                    TokenType::Identifier(s) => Ok(s),
                    _ => unreachable!(),
                }
            }
            _ => Err(format!(
                "Expected type at line {}, column {}",
                self.peek().line, self.peek().column
            )),
        }
    }

    fn parse_module(&mut self) -> Result<ModuleBlock> {
        self.expect(TokenType::Module)?;
        let name = self.expect_identifier()?;
        self.expect(TokenType::Colon)?;
        self.expect(TokenType::LBrace)?;
        let mut statements = Vec::new();
        let mut functions = Vec::new();
        let mut inputs = Vec::new();
        self.skip_newlines();

        while !self.check(TokenType::RBrace) && !self.is_at_end() {
            self.skip_newlines();
            if self.check(TokenType::RBrace) {
                break;
            }
            // Input block: input { name: type, ... }
            if self.check(TokenType::Input) {
                let input_block = self.parse_input_block()?;
                for (name, ty) in input_block.items {
                    let param_ty = match ty.as_str() {
                        "i64" => ValueType::I64,
                        "f64" => ValueType::F64,
                        _ => return Err(format!("Unknown type '{}' in input block", ty)),
                    };
                    inputs.push(Parameter { name, ty: param_ty });
                }
            }
            // Functions are parsed separately since they don't fit the
            // statement grammar (they're top-level within a module).
            else if self.check(TokenType::Func) {
                functions.push(self.parse_function()?);
            } else {
                let stmt = self.parse_statement()?;
                statements.push(stmt);
            }
            self.skip_newlines();
        }

        self.expect(TokenType::RBrace)?;
        Ok(ModuleBlock { name, statements, functions, inputs })
    }

    fn parse_statement(&mut self) -> Result<Statement> {
        // Control-flow keywords are reserved and dispatch to dedicated
        // parsers before we ever try to treat them as a name.
        match self.peek().token_type {
            TokenType::If => return self.parse_if(),
            TokenType::While => return self.parse_while(),
            TokenType::Return => return self.parse_return(),
            _ => {}
        }
        if let TokenType::Identifier(_) = self.peek().token_type {
            if self.tokens.get(self.current + 1).map(|t| matches!(t.token_type, TokenType::Colon)) == Some(true) {
                return Ok(Statement::Assignment(self.parse_assignment()?));
            }
        }
        self.parse_expression_or_sink()
    }

    // `return [expr]` — expression is optional for void functions.
    fn parse_return(&mut self) -> Result<Statement> {
        self.expect(TokenType::Return)?;
        let value = if self.check(TokenType::RBrace) || self.check(TokenType::Newline) || self.is_at_end() {
            None
        } else {
            Some(self.parse_expression()?)
        };
        Ok(Statement::Return(Return { value }))
    }

    // `if (cond) { stmts } else { stmts }` — the else-clause is optional.
    // `else if` is desugared at parse time: `else if (cond) { body }` becomes
    // `else { if (cond) { body } }`, so any-length `else if` chains work.
    fn parse_if(&mut self) -> Result<Statement> {
        self.expect(TokenType::If)?;
        let condition = self.parse_parenthesized_expression()?;
        let then_branch = self.parse_block()?;
        let else_branch = if self.check(TokenType::Else) {
            self.advance();
            if self.check(TokenType::If) {
                Some(vec![self.parse_if()?])
            } else {
                Some(self.parse_block()?)
            }
        } else {
            None
        };
        Ok(Statement::If { condition, then_branch, else_branch })
    }

    // `while (cond) { stmts }`
    fn parse_while(&mut self) -> Result<Statement> {
        self.expect(TokenType::While)?;
        let condition = self.parse_parenthesized_expression()?;
        let body = self.parse_block()?;
        Ok(Statement::While { condition, body })
    }

    // Parse `( expr )` and `expr;`-like wrappers sharing expression parsing.
    fn parse_parenthesized_expression(&mut self) -> Result<Expression> {
        self.expect(TokenType::LParen)?;
        let expr = self.parse_expression()?;
        self.expect(TokenType::RParen)?;
        Ok(expr)
    }

    // Parse a `{ ... }` statement block. Doesn't skip leading newlines
    // here because `parse_if`/`parse_while` follow directly after `)`;
    // however many authors put the open brace on its own new line, so
    // we tolerate intermixed newlines just inside the braces.
    fn parse_block(&mut self) -> Result<Vec<Statement>> {
        self.expect(TokenType::LBrace)?;
        let mut stmts = Vec::new();
        self.skip_newlines();
        while !self.check(TokenType::RBrace) && !self.is_at_end() {
            stmts.push(self.parse_statement()?);
            self.skip_newlines();
        }
        self.expect(TokenType::RBrace)?;
        Ok(stmts)
    }

    // Parse `func name(params) -> ret { body }` where params are
    // comma-separated `name: type` and `ret` is a type (i64/f64).
    fn parse_function(&mut self) -> Result<FunctionBlock> {
        self.expect(TokenType::Func)?;
        let name = self.expect_identifier()?;

        // Parse parameter list: (name: type, ...)
        self.expect(TokenType::LParen)?;
        let mut params = Vec::new();
        if !self.check(TokenType::RParen) {
            loop {
                let param_name = self.expect_identifier()?;
                self.expect(TokenType::Colon)?;
                let param_ty = self.expect_type()?;
                params.push(Parameter {
                    name: param_name,
                    ty: match param_ty.as_str() {
                        "i64" => ValueType::I64,
                        "f64" => ValueType::F64,
                        _ => return Err(format!("Unknown type '{}' in function parameter", param_ty)),
                    },
                });
                if self.check(TokenType::Comma) {
                    self.advance();
                } else {
                    break;
                }
            }
        }
        self.expect(TokenType::RParen)?;

        // Parse return type: -> type
        self.expect(TokenType::Minus)?;
        self.expect(TokenType::Greater)?;
        let return_type_str = self.expect_type()?;
        let return_type = match return_type_str.as_str() {
            "i64" => ValueType::I64,
            "f64" => ValueType::F64,
            _ => return Err(format!("Unknown return type '{}'", return_type_str)),
        };

        // Parse function body
        let body = self.parse_block()?;

        Ok(FunctionBlock { name, params, return_type, body })
    }

    fn parse_assignment(&mut self) -> Result<Assignment> {
        let name_token = self.advance();
        let name = match name_token.token_type {
            TokenType::Identifier(s) => s,
            _ => unreachable!(),
        };
        self.expect(TokenType::Colon)?;
        let expr = self.parse_expression()?;
        Ok(Assignment { name, value: expr })
    }

    fn parse_expression_or_sink(&mut self) -> Result<Statement> {
        let expr = self.parse_expression()?;

        if self.check(TokenType::Dot) {
            self.advance();
            let sink_name = if let TokenType::Identifier(s) = self.peek().token_type.clone() {
                self.advance();
                Some(s)
            } else if self.check(TokenType::RBrace) || self.is_at_end() {
                None
            } else {
                return Err(format!(
                    "Expected sink name or '}}' after '.' at line {}, column {}",
                    self.peek().line, self.peek().column
                ));
            };

            if let Expression::Call { name, args } = expr {
                return Ok(Statement::Sink(SinkCall { name, args, sink_name }));
            } else {
                return Err(format!(
                    "Only function calls can have sinks, got expression at line {}, column {}",
                    self.peek().line, self.peek().column
                ));
            }
        }

        Ok(Statement::Expression(expr))
    }

    fn parse_expression(&mut self) -> Result<Expression> {
        self.parse_precedence(0)
    }

    fn parse_precedence(&mut self, min_precedence: u8) -> Result<Expression> {
        let mut left = self.parse_primary()?;

        while !self.is_at_end() {
            let op_prec = self.get_prefix_precedence();
            if op_prec == 0 || op_prec < min_precedence {
                break;
            }

            let op_token = self.peek();
            self.advance();

            let right_prec = if self.get_postfix_precedence() > op_prec {
                self.get_postfix_precedence()
            } else {
                op_prec
            };

            let right = self.parse_precedence(right_prec)?;
            let op = self.token_to_binary_op(op_token.token_type)?;

            left = Expression::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<Expression> {
        let token = self.peek().clone();
        match token.token_type {
            TokenType::IntLiteral(value) => {
                self.advance();
                Ok(Expression::Literal(Literal {
                    value: LiteralValue::Int(value),
                    ty: ValueType::I64,
                }))
            }
            TokenType::FloatLiteral(value) => {
                self.advance();
                Ok(Expression::Literal(Literal {
                    value: LiteralValue::Float(value),
                    ty: ValueType::F64,
                }))
            }
            TokenType::StringLiteral(value) => {
                self.advance();
                Ok(Expression::Literal(Literal {
                    value: LiteralValue::String(value),
                    ty: ValueType::I64,
                }))
            }
            TokenType::Identifier(name) => {
                self.advance();
                if self.check(TokenType::LParen) {
                    self.advance();
                    let mut args = Vec::new();
                    if !self.check(TokenType::RParen) {
                        loop {
                            args.push(self.parse_expression()?);
                            if self.check(TokenType::Comma) {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(TokenType::RParen)?;
                    Ok(Expression::Call { name, args })
                } else {
                    Ok(Expression::Variable(Variable { name }))
                }
            }
            TokenType::LParen => {
                self.advance();
                let expr = self.parse_expression()?;
                self.expect(TokenType::RParen)?;
                Ok(expr)
            }
            TokenType::Plus => {
                self.advance();
                let operand = self.parse_primary()?;
                Ok(Expression::Unary { op: UnaryOp::Pos, operand: Box::new(operand) })
            }
            TokenType::Minus => {
                self.advance();
                let operand = self.parse_primary()?;
                Ok(Expression::Unary { op: UnaryOp::Negate, operand: Box::new(operand) })
            }
            TokenType::Bang => {
                self.advance();
                let operand = self.parse_primary()?;
                Ok(Expression::Unary { op: UnaryOp::Not, operand: Box::new(operand) })
            }
            TokenType::Tilde => {
                self.advance();
                let operand = self.parse_primary()?;
                Ok(Expression::Unary { op: UnaryOp::BitNot, operand: Box::new(operand) })
            }
            _ => Err(format!(
                "Unexpected token in expression: {:?} at line {}, column {}",
                token.token_type, token.line, token.column
            )),
        }
    }

    fn get_prefix_precedence(&self) -> u8 {
        match self.peek().token_type {
            TokenType::EqualEqual | TokenType::BangEqual => 10,
            TokenType::Less | TokenType::LessEqual | TokenType::Greater | TokenType::GreaterEqual => 11,
            TokenType::LessLess | TokenType::GreaterGreater => 12,
            TokenType::Ampersand => 13,
            TokenType::Caret => 14,
            TokenType::Pipe => 15,
            TokenType::Plus | TokenType::Minus => 16,
            TokenType::Star | TokenType::Slash | TokenType::Percent => 17,
            _ => 0,
        }
    }

    fn get_postfix_precedence(&self) -> u8 {
        18
    }

    fn token_to_binary_op(&self, token_type: TokenType) -> Result<BinaryOp> {
        match token_type {
            TokenType::Plus => Ok(BinaryOp::Add),
            TokenType::Minus => Ok(BinaryOp::Sub),
            TokenType::Star => Ok(BinaryOp::Mul),
            TokenType::Slash => Ok(BinaryOp::Div),
            TokenType::Percent => Ok(BinaryOp::Mod),
            TokenType::Ampersand => Ok(BinaryOp::BitAnd),
            TokenType::Pipe => Ok(BinaryOp::BitOr),
            TokenType::Caret => Ok(BinaryOp::BitXor),
            TokenType::LessLess => Ok(BinaryOp::Shl),
            TokenType::GreaterGreater => Ok(BinaryOp::Shr),
            TokenType::EqualEqual => Ok(BinaryOp::Eq),
            TokenType::BangEqual => Ok(BinaryOp::Ne),
            TokenType::Less => Ok(BinaryOp::Lt),
            TokenType::LessEqual => Ok(BinaryOp::Le),
            TokenType::Greater => Ok(BinaryOp::Gt),
            TokenType::GreaterEqual => Ok(BinaryOp::Ge),
            _ => Err(format!("Not a binary operator: {:?}", token_type)),
        }
    }

    fn advance(&mut self) -> Token {
        let token = self.tokens[self.current].clone();
        self.current += 1;
        token
    }

    fn peek(&self) -> Token {
        self.tokens[self.current].clone()
    }

    fn check(&self, expected: TokenType) -> bool {
        self.current < self.tokens.len() && self.tokens[self.current].token_type == expected
    }

    fn is_at_end(&self) -> bool {
        self.current >= self.tokens.len() || matches!(self.peek().token_type, TokenType::Eof)
    }

    fn expect(&mut self, expected: TokenType) -> Result<Token> {
        let token = self.peek();
        if token.token_type == expected {
            self.advance();
            Ok(token)
        } else {
            Err(format!(
                "Expected {:?} but found {:?} at line {}, column {}",
                expected, token.token_type, token.line, token.column
            ))
        }
    }

    fn expect_identifier(&mut self) -> Result<String> {
        let token = self.peek();
        match token.token_type {
            TokenType::Identifier(ref s) => {
                self.advance();
                Ok(s.clone())
            }
            _ => Err(format!(
                "Expected identifier at line {}, column {}",
                token.line, token.column
            )),
        }
    }

    fn skip_newlines(&mut self) {
        while self.check(TokenType::Newline) {
            self.advance();
        }
    }
}
