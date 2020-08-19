#[derive(Debug, PartialEq, Eq)]
pub enum ParserError<'a> {
    ExpectedOptionOrIdentityGot(super::lexer::Token<'a>),
}

impl<'a> std::fmt::Display for ParserError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(match self {
            Self::ExpectedOptionOrIdentityGot(token) => {
                write!(
                    f,
                    "Expected an option to rule (e.g. persist, nopass, keepenv, setenv) or user identity got \"{}\".",
                    token
                );
            }
        })
    }
}
