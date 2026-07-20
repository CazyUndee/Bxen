pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenType {
    IntLiteral(i64),
    FloatLiteral(f64),
    StringLiteral(String),
    Identifier(String),
    Plus, Minus, Star, Slash, Percent,
    Ampersand, Pipe, Caret,
    LessLess, GreaterGreater,
    EqualEqual, BangEqual,
    Less, LessEqual, Greater, GreaterEqual,
    Bang, Tilde,
    LBrace, RBrace, LParen, RParen,
Dot, DotDot, Colon, Comma,
    Header, Input, Module,
    If, Else, While,
    Func, Return,
    Newline, Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub token_type: TokenType,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug)]
pub struct Lexer {
    source: Vec<char>,
    position: usize,
    line: usize,
    column: usize,
}

impl Lexer {
    pub fn new(source: &str) -> Self {
        Self {
            source: source.chars().collect(),
            position: 0,
            line: 1,
            column: 1,
        }
    }

    pub fn tokenize(source: &str) -> Result<Vec<Token>> {
        let mut lexer = Self::new(source);
        let mut tokens = Vec::new();

        while !lexer.is_at_end() {
            lexer.skip_whitespace();
            if lexer.is_at_end() {
                break;
            }
            if lexer.current_char() == Some('\n') {
                tokens.push(lexer.make_token(TokenType::Newline));
                lexer.advance();
                continue;
            }
            if lexer.current_char() == Some('\r') {
                lexer.advance();
                continue;
            }
            let token = lexer.scan_token()?;
            tokens.push(token);
        }

        tokens.push(Token {
            token_type: TokenType::Eof,
            line: lexer.line,
            column: lexer.column,
        });

        Ok(tokens)
    }

    fn current_char(&self) -> Option<char> {
        if self.position < self.source.len() {
            Some(self.source[self.position])
        } else {
            None
        }
    }

    fn peek_char(&self) -> Option<char> {
        if self.position + 1 < self.source.len() {
            Some(self.source[self.position + 1])
        } else {
            None
        }
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.current_char();
        if ch == Some('\n') {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        self.position += 1;
        ch
    }

    fn is_at_end(&self) -> bool {
        self.position >= self.source.len()
    }

    fn make_token(&self, token_type: TokenType) -> Token {
        Token {
            token_type,
            line: self.line,
            column: self.column,
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.current_char() {
            if ch.is_whitespace() && ch != '\n' && ch != '\r' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn match_char(&mut self, expected: char) -> bool {
        if self.current_char() == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn scan_token(&mut self) -> Result<Token> {
        let ch = self.advance().ok_or("Unexpected EOF")?;
        match ch {
            '+' => Ok(self.make_token(TokenType::Plus)),
            '-' => Ok(self.make_token(TokenType::Minus)),
            '*' => Ok(self.make_token(TokenType::Star)),
            '/' => {
                if self.match_char('/') {
                    self.scan_line_comment()
                } else {
                    Ok(self.make_token(TokenType::Slash))
                }
            }
            '%' => Ok(self.make_token(TokenType::Percent)),
            '&' => Ok(self.make_token(TokenType::Ampersand)),
            '|' => Ok(self.make_token(TokenType::Pipe)),
            '^' => Ok(self.make_token(TokenType::Caret)),
            '!' => {
                if self.match_char('=') {
                    Ok(self.make_token(TokenType::BangEqual))
                } else {
                    Ok(self.make_token(TokenType::Bang))
                }
            }
            '~' => Ok(self.make_token(TokenType::Tilde)),
            '(' => Ok(self.make_token(TokenType::LParen)),
            ')' => Ok(self.make_token(TokenType::RParen)),
            '{' => Ok(self.make_token(TokenType::LBrace)),
            '}' => Ok(self.make_token(TokenType::RBrace)),
            '.' => {
                if self.match_char('.') {
                    Ok(self.make_token(TokenType::DotDot))
                } else {
                    Ok(self.make_token(TokenType::Dot))
                }
            }
            ':' => Ok(self.make_token(TokenType::Colon)),
            ',' => Ok(self.make_token(TokenType::Comma)),
            '<' => {
                if self.match_char('<') {
                    Ok(self.make_token(TokenType::LessLess))
                } else if self.match_char('=') {
                    Ok(self.make_token(TokenType::LessEqual))
                } else {
                    Ok(self.make_token(TokenType::Less))
                }
            }
            '>' => {
                if self.match_char('>') {
                    Ok(self.make_token(TokenType::GreaterGreater))
                } else if self.match_char('=') {
                    Ok(self.make_token(TokenType::GreaterEqual))
                } else {
                    Ok(self.make_token(TokenType::Greater))
                }
            }
            '=' => {
                if self.match_char('=') {
                    Ok(self.make_token(TokenType::EqualEqual))
                } else {
                    Err(format!("Unexpected '=' at line {}, column {}",
                        self.line, self.column - 1))
                }
            }
            '"' => self.scan_string(),
            c if c.is_ascii_digit() => self.scan_number(ch),
            c if c.is_ascii_alphabetic() || c == '_' => self.scan_identifier(ch),
            _ => Err(format!("Unexpected character '{}' at line {}, column {}",
                ch, self.line, self.column - 1)),
        }
    }

    fn scan_line_comment(&mut self) -> Result<Token> {
        while let Some(ch) = self.current_char() {
            if ch == '\n' {
                break;
            }
            self.advance();
        }
        Ok(Token {
            token_type: TokenType::Newline,
            line: self.line,
            column: self.column,
        })
    }

    fn scan_string(&mut self) -> Result<Token> {
        let start_line = self.line;
        let start_col = self.column - 1;
        let mut value = String::new();

        loop {
            match self.current_char() {
                None | Some('\n') => {
                    return Err(format!(
                        "Unterminated string literal starting at line {}, column {}",
                        start_line, start_col
                    ));
                }
                Some('"') => {
                    self.advance();
                    break;
                }
                Some('\\') => {
                    self.advance();
                    let escaped = self.advance().ok_or_else(|| {
                        format!("Unterminated escape sequence in string at line {}, column {}", self.line, self.column)
                    })?;
                    match escaped {
                        'n' => value.push('\n'),
                        't' => value.push('\t'),
                        'r' => value.push('\r'),
                        '\\' => value.push('\\'),
                        '"' => value.push('"'),
                        '0' => value.push('\0'),
                        _ => return Err(format!(
                            "Invalid escape sequence '\\{}' in string at line {}, column {}",
                            escaped, self.line, self.column
                        )),
                    }
                }
                Some(ch) => {
                    value.push(ch);
                    self.advance();
                }
            }
        }

        Ok(Token {
            token_type: TokenType::StringLiteral(value),
            line: start_line,
            column: start_col,
        })
    }

    fn scan_number(&mut self, first: char) -> Result<Token> {
        let start_line = self.line;
        let start_col = self.column - 1;
        let mut value_str = first.to_string();

        while let Some(ch) = self.current_char() {
            if ch.is_ascii_digit() {
                value_str.push(self.advance().unwrap());
            } else {
                break;
            }
        }

        if self.current_char() == Some('.') && self.peek_char().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            self.advance();
            value_str.push('.');
            while let Some(ch) = self.current_char() {
                if ch.is_ascii_digit() {
                    value_str.push(self.advance().unwrap());
                } else {
                    break;
                }
            }
            let value: f64 = value_str.parse()
                .map_err(|_| format!("Invalid float '{}' at line {}, column {}", value_str, start_line, start_col))?;
            return Ok(Token {
                token_type: TokenType::FloatLiteral(value),
                line: start_line,
                column: start_col,
            });
        }

        let value: i64 = value_str.parse()
            .map_err(|_| format!("Invalid integer '{}' at line {}, column {}", value_str, start_line, start_col))?;
        Ok(Token {
            token_type: TokenType::IntLiteral(value),
            line: start_line,
            column: start_col,
        })
    }

    fn scan_identifier(&mut self, first: char) -> Result<Token> {
        let start_line = self.line;
        let start_col = self.column - 1;
        let mut value = first.to_string();

        while let Some(ch) = self.current_char() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                value.push(self.advance().unwrap());
            } else {
                break;
            }
        }

let token_type = match value.as_str() {
            "header" => TokenType::Header,
            "input" => TokenType::Input,
            "module" => TokenType::Module,
            "if" => TokenType::If,
            "else" => TokenType::Else,
            "while" => TokenType::While,
            "func" => TokenType::Func,
            "return" => TokenType::Return,
            _ => TokenType::Identifier(value),
        };

        Ok(Token {
            token_type,
            line: start_line,
            column: start_col,
        })
    }
}
