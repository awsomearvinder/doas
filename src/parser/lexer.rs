///! This module takes given contents and spits out Tokens that are more easily digested
///! By programs.
use nom::bytes::complete::tag;
use nom::bytes::complete::take_till;
use nom::bytes::complete::take_until;
use nom::bytes::complete::take_while;
use nom::multi::many0;

use std::collections::HashMap;

#[cfg(test)]
mod lexer_tests;

///Returns a Vector of tokens or a lexer error
///lexer errors exist due to ambiguities (is a token a part of setenv? inside quotes?)
///when something is missing.
#[allow(dead_code)]
pub fn get_tokens(data: &str) -> Result<Vec<Token>, LexerError<&str>> {
    //This will be updated to hold the remaining data we have yet to parse.
    let mut data = data.trim();
    let mut tokens = Vec::new();
    while let Ok((remaining, token)) =
        get_next_token(data).map_err(|_| LexerError::CouldntGetNextToken::<&str>)
    {
        data = remaining;
        tokens.push(token);
    }
    tokens.push(Token::Eol);
    Ok(tokens)
}

///This takes the data, returns the next token along with the remaining data.
fn get_next_token(data: &str) -> nom::IResult<&str, Token, LexerError<&str>> {
    if let Some(data) = data.strip_prefix('\n') {
        return Ok((data, Token::from("\n")));
    }
    let (remaining, word) = get_next_word(" \t\n")(data)?;
    if word == "#" {
        //if it's a comment just ignore it, and go to the next relevant thing.
        let (remaining, _) = take_until("\n")(remaining)?;
        return get_next_token(remaining);
    }
    if word == "setenv" {
        return parse_set_env(remaining);
    }
    Ok((remaining, Token::from(word)))
}

//TODO: It might be a good idea to sub out returning a Token for a HasMap<&str, &str>
//for less ambiguity. (It can return any token?)
///This parses the set enviorment seperately from get_next_token
///due to the added complexity of handling setenv.
///It returns a Token::SetEnv or a lexer error.
fn parse_set_env(data: &str) -> nom::IResult<&str, Token, LexerError<&str>> {
    let (remaining, _) = take_till(|c| c == '{')(data)?;
    let (remaining, _) = tag::<_, _, ()>("{")(remaining) //take the first brace out.
        .map_err(|_| nom::Err::Failure(LexerError::NoOrUnmatchedBracket))?;
    let (remaining, between_braces) = take_till(|c| c == '}')(remaining)?;
    let (remaining, _) = tag::<_, _, ()>("}")(remaining) //make sure our output dosen't contain the last brace.
        .map_err(|_| nom::Err::Failure(LexerError::NoOrUnmatchedBracket))?;
    let (_, tokens) = many0(get_next_word(" \t="))(between_braces)?;
    let num_to_take = if tokens.len() % 2 == 1 {
        tokens.len() - 1 //eventually we'd want to somehow tell the user that they have an odd number of setenv key/vals.
                         //this is obviously a bug because key/values should be pairs.
    } else {
        tokens.len()
    };
    let map = (&tokens[..num_to_take])
        .chunks(2)
        .map(|a| {
            if let [a, b] = a {
                (*a, *b)
            } else {
                panic!("Was given an uneven amount of args in setenv")
            }
        })
        .collect();
    Ok((remaining, Token::SetEnv(map)))
}

///This type represents a combinator function working with &str such as with nom.
type Combinator<'a> = dyn Fn(&str) -> nom::IResult<&str, &str, LexerError<&str>> + 'a;

//TODO: get_next_word is probably a bad name?
///Get next value seperated by the seperator and remaining in a tuple.
///Tosses out the seperator.
fn get_next_word(seperator: &str) -> Box<Combinator<'_>> {
    let escaped = std::cell::Cell::new(false);
    let in_quotes = std::cell::Cell::new(false);
    //I'm sorry to whoever has to read this atrocity.
    Box::new(move |contents| {
        let seperator_detector = |c: char| {
            if c == '"' && !escaped.get() {
                in_quotes.set(!in_quotes.get());
            }
            if in_quotes.get() {
                return true;
            }
            if escaped.get() {
                escaped.set(false);
                return true;
            }
            if c == '\\' && !escaped.get() {
                escaped.set(true);
            }
            !seperator.contains(c)
        };
        let (remaining, _): (&str, &str) = take_till(seperator_detector)(contents)?;
        if remaining.is_empty() {
            return Err(nom::Err::Error(LexerError::NoWordsLeft));
        }
        //Reset for the next run.
        escaped.set(false);
        in_quotes.set(false);
        take_while(seperator_detector)(remaining)
    })
}

///A lexer Token.
#[derive(Debug, PartialEq, Eq)]
pub enum Token<'a> {
    Permit,
    Deny,
    Persist,
    NoPass,
    KeepEnv,
    As,
    Cmd,
    Args,
    Eol,
    Ident(&'a str),
    SetEnv(HashMap<&'a str, &'a str>),
}

impl<'a> std::fmt::Display for Token<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permit => write!(f, "permit"),
            Self::Deny => write!(f, "deny"),
            Self::Persist => write!(f, "persist"),
            Self::NoPass => write!(f, "nopass"),
            Self::KeepEnv => write!(f, "keepenv"),
            Self::As => write!(f, "as"),
            Self::Cmd => write!(f, "cmd"),
            Self::Args => write!(f, "args"),
            Self::Eol => write!(f, "End Of Line"),
            Self::Ident(identifier) => write!(f, "{}", identifier),
            Self::SetEnv(map) => write!(f, "setenv {{{:?}}}", map),
        }
    }
}

impl<'a> From<&'a str> for Token<'a> {
    fn from(token: &'a str) -> Self {
        match token {
            "permit" => Self::Permit,
            "deny" => Self::Deny,
            "\n" => Self::Eol,
            "nopass" => Self::NoPass,
            "keepenv" => Self::KeepEnv,
            "persist" => Self::Persist,
            "as" => Self::As,
            "cmd" => Self::Cmd,
            "args" => Self::Args,
            c => Self::Ident(c),
        }
    }
}

///Possible instances of a Lexer Error.
#[derive(Debug, PartialEq, Eq)]
pub enum LexerError<I> {
    NoOrUnmatchedBracket,
    NoWordsLeft,
    CouldntGetNextToken,
    NomError(I, nom::error::ErrorKind),
}

impl<I> nom::error::ParseError<I> for LexerError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self::NomError(input, kind)
    }
    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}
