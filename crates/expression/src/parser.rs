use crate::{
    ast::{BinaryOperator, SyntaxNode, UnaryOperator},
    evaluation::evaluate_node,
    lexer::{Lexer, Token, TokenKind},
    EvalError, EvalErrorKind, ParseError, Resolver, Span, Value,
};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{collections::BTreeSet, fmt, str::FromStr};

/// Maximum accepted expression size, in UTF-8 bytes.
pub const MAX_EXPRESSION_BYTES: usize = 64 * 1024;
/// Maximum syntactic nesting through parentheses and unary operators.
pub const MAX_PARSE_DEPTH: usize = 128;

/// A parsed, reusable workflow expression.
#[derive(Clone, Debug, PartialEq)]
pub struct Expression {
    source: String,
    root: SyntaxNode,
}

impl Expression {
    /// Parses a complete expression.
    pub fn parse(source: &str) -> Result<Self, ParseError> {
        if source.len() > MAX_EXPRESSION_BYTES {
            return Err(ParseError::new(
                format!("expression exceeds {MAX_EXPRESSION_BYTES}-byte limit"),
                Span::new(MAX_EXPRESSION_BYTES, source.len()),
            ));
        }

        let tokens = Lexer::new(source).tokenize()?;
        let root = Parser::new(tokens).parse()?;
        Ok(Self {
            source: source.to_owned(),
            root,
        })
    }

    /// Returns the exact source used to parse this expression.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns dotted context paths referenced by this expression, sorted and unique.
    #[must_use]
    pub fn context_references(&self) -> Vec<String> {
        let mut references = BTreeSet::new();
        self.root.collect_references(&mut references);
        references.into_iter().collect()
    }

    /// Returns a unique, parseable representation of this expression AST.
    /// Insignificant source whitespace, quote choice, redundant parentheses,
    /// and equivalent numeric spellings do not affect this form.
    #[must_use]
    pub fn canonical_source(&self) -> String {
        let mut output = String::new();
        self.root.write_canonical(&mut output);
        output
    }

    /// Evaluates this expression against a context resolver.
    pub fn evaluate<R>(&self, resolver: &R) -> Result<Value, EvalError>
    where
        R: Resolver + ?Sized,
    {
        evaluate_node(&self.root, resolver, 0)
    }

    /// Evaluates a workflow condition, requiring a boolean result.
    pub fn evaluate_bool<R>(&self, resolver: &R) -> Result<bool, EvalError>
    where
        R: Resolver + ?Sized,
    {
        let value = self.evaluate(resolver)?;
        value.as_bool().ok_or_else(|| {
            EvalError::new(
                EvalErrorKind::ExpectedBoolean {
                    operator: "condition",
                    found: value.value_type(),
                },
                self.root.span(),
            )
        })
    }
}

impl FromStr for Expression {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        Self::parse(source)
    }
}

impl fmt::Display for Expression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.source)
    }
}

impl Serialize for Expression {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.source)
    }
}

struct ExpressionVisitor;

impl<'de> Visitor<'de> for ExpressionVisitor {
    type Value = Expression;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a safe workflow expression string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Expression::parse(value).map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Expression::parse(&value).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for Expression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(ExpressionVisitor)
    }
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
    nesting: usize,
}

impl Parser {
    const fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            position: 0,
            nesting: 0,
        }
    }

    fn parse(mut self) -> Result<SyntaxNode, ParseError> {
        if self.at_end() {
            return Err(ParseError::new("expression is empty", self.current().span));
        }
        let expression = self.parse_or()?;
        if !self.at_end() {
            let token = self.current();
            let message = if matches!(token.kind, TokenKind::LeftParenthesis) {
                "function calls are not supported".to_owned()
            } else {
                format!(
                    "unexpected {} after expression",
                    describe_token(&token.kind)
                )
            };
            return Err(ParseError::new(message, token.span));
        }
        Ok(expression)
    }

    fn parse_or(&mut self) -> Result<SyntaxNode, ParseError> {
        let mut left = self.parse_and()?;
        while matches!(self.current().kind, TokenKind::Or) {
            let operator = self.take();
            let right = self.parse_and()?;
            let span = left.span().through(right.span());
            left = SyntaxNode::Binary {
                operator: BinaryOperator::Or,
                operator_span: operator.span,
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<SyntaxNode, ParseError> {
        let mut left = self.parse_equality()?;
        while matches!(self.current().kind, TokenKind::And) {
            let operator = self.take();
            let right = self.parse_equality()?;
            let span = left.span().through(right.span());
            left = SyntaxNode::Binary {
                operator: BinaryOperator::And,
                operator_span: operator.span,
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }
        Ok(left)
    }

    fn parse_equality(&mut self) -> Result<SyntaxNode, ParseError> {
        let mut left = self.parse_comparison()?;
        loop {
            let operator = match self.current().kind {
                TokenKind::Equal => BinaryOperator::Equal,
                TokenKind::NotEqual => BinaryOperator::NotEqual,
                _ => break,
            };
            let operator_token = self.take();
            let right = self.parse_comparison()?;
            let span = left.span().through(right.span());
            left = SyntaxNode::Binary {
                operator,
                operator_span: operator_token.span,
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }
        Ok(left)
    }

    fn parse_comparison(&mut self) -> Result<SyntaxNode, ParseError> {
        let mut left = self.parse_unary()?;
        loop {
            let operator = match self.current().kind {
                TokenKind::Less => BinaryOperator::Less,
                TokenKind::LessEqual => BinaryOperator::LessEqual,
                TokenKind::Greater => BinaryOperator::Greater,
                TokenKind::GreaterEqual => BinaryOperator::GreaterEqual,
                _ => break,
            };
            let operator_token = self.take();
            let right = self.parse_unary()?;
            let span = left.span().through(right.span());
            left = SyntaxNode::Binary {
                operator,
                operator_span: operator_token.span,
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<SyntaxNode, ParseError> {
        if matches!(self.current().kind, TokenKind::Bang) {
            let operator = self.take();
            self.enter_nesting(operator.span)?;
            let operand_result = self.parse_unary();
            self.nesting -= 1;
            let operand = operand_result?;
            let span = operator.span.through(operand.span());
            Ok(SyntaxNode::Unary {
                operator: UnaryOperator::Not,
                operator_span: operator.span,
                operand: Box::new(operand),
                span,
            })
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<SyntaxNode, ParseError> {
        let token = self.take();
        match token.kind {
            TokenKind::Null => Ok(SyntaxNode::Literal {
                value: Value::null(),
                span: token.span,
            }),
            TokenKind::Boolean(value) => Ok(SyntaxNode::Literal {
                value: Value::boolean(value),
                span: token.span,
            }),
            TokenKind::Number(value) => Ok(SyntaxNode::Literal {
                value: Value::number(value).expect("lexer only emits finite numbers"),
                span: token.span,
            }),
            TokenKind::String(value) => Ok(SyntaxNode::Literal {
                value: Value::string(value),
                span: token.span,
            }),
            TokenKind::Identifier(first) => self.parse_lookup(first, token.span),
            TokenKind::LeftParenthesis => {
                self.enter_nesting(token.span)?;
                let expression_result = self.parse_or();
                self.nesting -= 1;
                let expression = expression_result?;
                if !matches!(self.current().kind, TokenKind::RightParenthesis) {
                    return Err(ParseError::new("expected `)`", self.current().span));
                }
                let closing = self.take();
                // Parentheses do not need a separate runtime node, but retaining their
                // full span makes condition-result errors point at the complete input.
                Ok(with_span(expression, token.span.through(closing.span)))
            }
            TokenKind::End => Err(ParseError::new("expected expression", token.span)),
            _ => Err(ParseError::new(
                format!("expected expression, found {}", describe_token(&token.kind)),
                token.span,
            )),
        }
    }

    fn parse_lookup(&mut self, first: String, first_span: Span) -> Result<SyntaxNode, ParseError> {
        let mut path = vec![first];
        let mut end = first_span.end;
        while matches!(self.current().kind, TokenKind::Dot) {
            self.take();
            let segment = self.take();
            let name = match segment.kind {
                TokenKind::Identifier(name) => name,
                TokenKind::Null => "null".to_owned(),
                TokenKind::Boolean(true) => "true".to_owned(),
                TokenKind::Boolean(false) => "false".to_owned(),
                _ => {
                    return Err(ParseError::new(
                        "expected identifier after `.`",
                        segment.span,
                    ));
                }
            };
            path.push(name);
            end = segment.span.end;
        }
        if matches!(self.current().kind, TokenKind::LeftParenthesis) {
            return Err(ParseError::new(
                "function calls are not supported",
                self.current().span,
            ));
        }
        Ok(SyntaxNode::Lookup {
            path,
            span: Span::new(first_span.start, end),
        })
    }

    fn enter_nesting(&mut self, span: Span) -> Result<(), ParseError> {
        if self.nesting >= MAX_PARSE_DEPTH {
            return Err(ParseError::new(
                format!("expression nesting exceeds {MAX_PARSE_DEPTH}-level limit"),
                span,
            ));
        }
        self.nesting += 1;
        Ok(())
    }

    fn current(&self) -> &Token {
        // The lexer always appends an end token and the parser never consumes past it.
        &self.tokens[self.position]
    }

    fn take(&mut self) -> Token {
        let token = self.current().clone();
        if !matches!(token.kind, TokenKind::End) {
            self.position += 1;
        }
        token
    }

    fn at_end(&self) -> bool {
        matches!(self.current().kind, TokenKind::End)
    }
}

fn with_span(mut node: SyntaxNode, span: Span) -> SyntaxNode {
    match &mut node {
        SyntaxNode::Literal {
            span: node_span, ..
        }
        | SyntaxNode::Lookup {
            span: node_span, ..
        }
        | SyntaxNode::Unary {
            span: node_span, ..
        }
        | SyntaxNode::Binary {
            span: node_span, ..
        } => *node_span = span,
    }
    node
}

fn describe_token(token: &TokenKind) -> &'static str {
    match token {
        TokenKind::Null => "`null`",
        TokenKind::Boolean(_) => "boolean literal",
        TokenKind::Number(_) => "number literal",
        TokenKind::String(_) => "string literal",
        TokenKind::Identifier(_) => "identifier",
        TokenKind::Dot => "`.`",
        TokenKind::LeftParenthesis => "`(`",
        TokenKind::RightParenthesis => "`)`",
        TokenKind::Bang => "`!`",
        TokenKind::And => "`&&`",
        TokenKind::Or => "`||`",
        TokenKind::Equal => "`==`",
        TokenKind::NotEqual => "`!=`",
        TokenKind::Less => "`<`",
        TokenKind::LessEqual => "`<=`",
        TokenKind::Greater => "`>`",
        TokenKind::GreaterEqual => "`>=`",
        TokenKind::End => "end of input",
    }
}
