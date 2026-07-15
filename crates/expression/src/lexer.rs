use crate::{ParseError, Span, MAX_EXACT_EXPRESSION_NUMBER};

/// Maximum number of lexical tokens in one expression.
pub const MAX_TOKENS: usize = 4_096;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TokenKind {
    Null,
    Boolean(bool),
    Number(f64),
    String(String),
    Identifier(String),
    Dot,
    LeftParenthesis,
    RightParenthesis,
    Bang,
    And,
    Or,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    End,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) span: Span,
}

pub(crate) struct Lexer<'source> {
    source: &'source str,
    position: usize,
}

impl<'source> Lexer<'source> {
    pub(crate) const fn new(source: &'source str) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    pub(crate) fn tokenize(mut self) -> Result<Vec<Token>, ParseError> {
        let mut tokens = Vec::new();
        while let Some(character) = self.peek() {
            if character.is_whitespace() {
                self.bump();
                continue;
            }
            if tokens.len() >= MAX_TOKENS {
                return Err(ParseError::new(
                    format!("expression exceeds {MAX_TOKENS}-token limit"),
                    Span::new(self.position, self.position + character.len_utf8()),
                ));
            }

            let start = self.position;
            let kind = match character {
                '(' => {
                    self.bump();
                    TokenKind::LeftParenthesis
                }
                ')' => {
                    self.bump();
                    TokenKind::RightParenthesis
                }
                '.' => {
                    self.bump();
                    TokenKind::Dot
                }
                '!' => {
                    self.bump();
                    if self.take_if('=') {
                        TokenKind::NotEqual
                    } else {
                        TokenKind::Bang
                    }
                }
                '=' => {
                    self.bump();
                    if self.take_if('=') {
                        TokenKind::Equal
                    } else {
                        return Err(ParseError::new(
                            "assignment is not supported; use `==` for equality",
                            Span::new(start, self.position),
                        ));
                    }
                }
                '<' => {
                    self.bump();
                    if self.take_if('=') {
                        TokenKind::LessEqual
                    } else {
                        TokenKind::Less
                    }
                }
                '>' => {
                    self.bump();
                    if self.take_if('=') {
                        TokenKind::GreaterEqual
                    } else {
                        TokenKind::Greater
                    }
                }
                '&' => {
                    self.bump();
                    if self.take_if('&') {
                        TokenKind::And
                    } else {
                        return Err(ParseError::new(
                            "single `&` is not supported; use `&&`",
                            Span::new(start, self.position),
                        ));
                    }
                }
                '|' => {
                    self.bump();
                    if self.take_if('|') {
                        TokenKind::Or
                    } else {
                        return Err(ParseError::new(
                            "single `|` is not supported; use `||`",
                            Span::new(start, self.position),
                        ));
                    }
                }
                '\'' | '"' => TokenKind::String(self.scan_string(character, start)?),
                '-' if self.peek_second().is_some_and(|next| next.is_ascii_digit()) => {
                    TokenKind::Number(self.scan_number(start)?)
                }
                character if character.is_ascii_digit() => {
                    TokenKind::Number(self.scan_number(start)?)
                }
                character if is_identifier_start(character) => self.scan_identifier(),
                '$' if self.remaining().starts_with("${{") => {
                    return Err(ParseError::new(
                        "interpolation syntax is not supported",
                        Span::new(start, (start + 3).min(self.source.len())),
                    ));
                }
                _ => {
                    self.bump();
                    return Err(ParseError::new(
                        format!("unexpected character `{character}`"),
                        Span::new(start, self.position),
                    ));
                }
            };
            tokens.push(Token {
                kind,
                span: Span::new(start, self.position),
            });
        }
        tokens.push(Token {
            kind: TokenKind::End,
            span: Span::new(self.position, self.position),
        });
        Ok(tokens)
    }

    fn scan_identifier(&mut self) -> TokenKind {
        let start = self.position;
        self.bump();
        while self.peek().is_some_and(is_identifier_continue) {
            self.bump();
        }
        match &self.source[start..self.position] {
            "null" => TokenKind::Null,
            "true" => TokenKind::Boolean(true),
            "false" => TokenKind::Boolean(false),
            identifier => TokenKind::Identifier(identifier.to_owned()),
        }
    }

    fn scan_number(&mut self, start: usize) -> Result<f64, ParseError> {
        self.take_if('-');
        if self.take_if('0') {
            if self
                .peek()
                .is_some_and(|character| character.is_ascii_digit())
            {
                return Err(ParseError::new(
                    "number literals cannot contain leading zeroes",
                    Span::new(start, self.position + 1),
                ));
            }
        } else {
            self.take_ascii_digits();
        }

        if self.take_if('.') {
            if !self
                .peek()
                .is_some_and(|character| character.is_ascii_digit())
            {
                return Err(ParseError::new(
                    "fractional part requires at least one digit",
                    Span::new(start, self.position),
                ));
            }
            self.take_ascii_digits();
        }

        if self
            .peek()
            .is_some_and(|character| matches!(character, 'e' | 'E'))
        {
            self.bump();
            if self
                .peek()
                .is_some_and(|character| matches!(character, '+' | '-'))
            {
                self.bump();
            }
            if !self
                .peek()
                .is_some_and(|character| character.is_ascii_digit())
            {
                return Err(ParseError::new(
                    "exponent requires at least one digit",
                    Span::new(start, self.position),
                ));
            }
            self.take_ascii_digits();
        }

        let text = &self.source[start..self.position];
        let value = text.parse::<f64>().map_err(|_| {
            ParseError::new("invalid number literal", Span::new(start, self.position))
        })?;
        if !value.is_finite() {
            return Err(ParseError::new(
                "number literal is outside the finite range",
                Span::new(start, self.position),
            ));
        }
        if value.abs() > MAX_EXACT_EXPRESSION_NUMBER {
            return Err(ParseError::new(
                "number literal is outside the exact expression range",
                Span::new(start, self.position),
            ));
        }
        Ok(value)
    }

    fn scan_string(&mut self, quote: char, start: usize) -> Result<String, ParseError> {
        self.bump();
        let mut result = String::new();
        loop {
            let Some(character) = self.bump() else {
                return Err(ParseError::new(
                    "unterminated string literal",
                    Span::new(start, self.position),
                ));
            };
            if character == quote {
                return Ok(result);
            }
            if character == '\\' {
                let escape_start = self.position - 1;
                let Some(escaped) = self.bump() else {
                    return Err(ParseError::new(
                        "unterminated string escape",
                        Span::new(escape_start, self.position),
                    ));
                };
                match escaped {
                    '\\' => result.push('\\'),
                    '\'' => result.push('\''),
                    '"' => result.push('"'),
                    '/' => result.push('/'),
                    'b' => result.push('\u{0008}'),
                    'f' => result.push('\u{000c}'),
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    'u' => result.push(self.scan_unicode_escape(escape_start)?),
                    _ => {
                        return Err(ParseError::new(
                            format!("unsupported string escape `\\{escaped}`"),
                            Span::new(escape_start, self.position),
                        ));
                    }
                }
            } else if character.is_control() {
                return Err(ParseError::new(
                    "unescaped control character in string literal",
                    Span::new(self.position - character.len_utf8(), self.position),
                ));
            } else {
                result.push(character);
            }
        }
    }

    fn scan_unicode_escape(&mut self, escape_start: usize) -> Result<char, ParseError> {
        let first = self.scan_hex_quad(escape_start)?;
        let scalar = if (0xD800..=0xDBFF).contains(&first) {
            if !self.take_if('\\') || !self.take_if('u') {
                return Err(ParseError::new(
                    "high surrogate must be followed by a low surrogate escape",
                    Span::new(escape_start, self.position),
                ));
            }
            let second = self.scan_hex_quad(escape_start)?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(ParseError::new(
                    "invalid low surrogate in unicode escape",
                    Span::new(escape_start, self.position),
                ));
            }
            0x1_0000 + (u32::from(first - 0xD800) << 10) + u32::from(second - 0xDC00)
        } else if (0xDC00..=0xDFFF).contains(&first) {
            return Err(ParseError::new(
                "low surrogate without a preceding high surrogate",
                Span::new(escape_start, self.position),
            ));
        } else {
            u32::from(first)
        };
        char::from_u32(scalar).ok_or_else(|| {
            ParseError::new(
                "invalid unicode scalar in string escape",
                Span::new(escape_start, self.position),
            )
        })
    }

    fn scan_hex_quad(&mut self, escape_start: usize) -> Result<u16, ParseError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let Some(character) = self.bump() else {
                return Err(ParseError::new(
                    "unicode escape requires four hexadecimal digits",
                    Span::new(escape_start, self.position),
                ));
            };
            let Some(digit) = character.to_digit(16) else {
                return Err(ParseError::new(
                    "unicode escape requires four hexadecimal digits",
                    Span::new(escape_start, self.position),
                ));
            };
            value = (value << 4) | digit as u16;
        }
        Ok(value)
    }

    fn take_ascii_digits(&mut self) {
        while self
            .peek()
            .is_some_and(|character| character.is_ascii_digit())
        {
            self.bump();
        }
    }

    fn take_if(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn peek_second(&self) -> Option<char> {
        self.remaining().chars().nth(1)
    }

    fn bump(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.position += character.len_utf8();
        Some(character)
    }

    fn remaining(&self) -> &str {
        &self.source[self.position..]
    }
}

const fn is_identifier_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_'
}

const fn is_identifier_continue(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
}
