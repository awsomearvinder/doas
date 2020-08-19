#[derive(Debug, PartialEq, Eq)]
pub enum ParserError<'a> {
    NoUser(&'a str),
    ExpectedRuleGot(super::lexer::Token<'a>),
    ExpectedOptionOrIdentityGot(super::lexer::Token<'a>),
    ExpectedCmdNameGot(super::lexer::Token<'a>),
}

impl<'a> std::fmt::Display for ParserError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoUser(name) => write!(f, "Couldn't find a user representing \"{}\"", name),
            Self::ExpectedRuleGot(token) => {
                write!(f, "Expected a rule (permit | deny) got \"{}\".", token)
            }
            Self::ExpectedOptionOrIdentityGot(token) => {
                write!(
                    f,
                    "Expected an option to rule (e.g. persist, nopass, keepenv, setenv) or user identity got \"{}\".",
                    token
                )
            }
            Self::ExpectedCmdNameGot(token) => {
                write!(f, "Expected a command name got \"{}\".", token)
            }
        }
    }
}
