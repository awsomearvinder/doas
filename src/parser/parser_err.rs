use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum ParserError<'a, I> {
    NoTarget,
    FoundTrailingAfterRule,
    NoArgsLeft,
    UnknownRule(String),
    NoUser,
    NoRule,
    NoCmd,
    NoCmdArgs,
    UnmatchedOrNoSetEnvBracket,
    NomError(I, nom::error::ErrorKind),
    InvalidKeyValsInSetEnv(HashMap<&'a str, &'a str>),
}

impl<'a, I> nom::error::ParseError<I> for ParserError<'a, I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self::NomError(input, kind)
    }
    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a, I> std::fmt::Display for ParserError<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FoundTrailingAfterRule => write!(f, "Found trailing characters after the rule"),
            Self::NoArgsLeft => write!(f, "No args are left."),
            Self::NoUser => write!(f, "No user identity provided"),
            Self::NoRule => write!(f, "No rule provided in config"),
            Self::UnknownRule(e) => write!(f, "Encountered an Unknown rule {}", e),
            Self::InvalidKeyValsInSetEnv(map) => write!(
                f,
                "unequal amount of keyvalue pairs in setenv arg {:#?}",
                map
            ),
            Self::UnmatchedOrNoSetEnvBracket => {
                write!(f, "You have an unmatched or no setenv bracket.")
            }
            Self::NomError(_, _) => write!(
                f,
                "Got some internal nom error, consider sending a bug report! context: {}",
                self
            ),
            Self::NoTarget => write!(f, "No provided target for rule after as keyword"),
            Self::NoCmd => write!(f, "No provided command after cmd keyword"),
            Self::NoCmdArgs => write!(f, "No provided command after args keyword"),
        }
    }
}
