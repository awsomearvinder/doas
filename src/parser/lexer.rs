use nom::bytes::complete::tag;
use nom::bytes::complete::take_till;
use nom::bytes::complete::take_until;
use nom::bytes::complete::take_while;
use nom::multi::many0;

use std::collections::HashMap;

#[cfg(test)]
mod lexer_tests;

#[allow(dead_code)]
pub fn get_tokens(data: &str) -> Result<Vec<Token>, LexerError<&str>> {
    let mut data = data.trim();
    let mut tokens = Vec::new();
    while let Ok((remaining, token)) =
        get_next_token(data).map_err(|_| LexerError::CouldntGetNextToken::<&str>)
    {
        data = remaining;
        tokens.push(token);
    }
    tokens.push(Token::EOL);
    Ok(tokens)
}

fn get_next_token(data: &str) -> nom::IResult<&str, Token, LexerError<&str>> {
    let (remaining, word) = get_next_word(" \t")(data)?;
    if word == "#" {
        let (remaining, _) = take_until("\n")(remaining)?;
        return get_next_token(remaining);
    }
    if word == "setenv" {
        return parse_set_env(remaining);
    }
    Ok((remaining, Token::from(word)))
}

fn parse_set_env(data: &str) -> nom::IResult<&str, Token, LexerError<&str>> {
    let (remaining, _) = take_till(|c| c == '{')(data)?;
    let (remaining, _) = tag::<_, _, ()>("{")(remaining)
        .map_err(|_| nom::Err::Failure(LexerError::NoOrUnmatchedBracket))?;
    let (remaining, between_braces) = take_till(|c| c == '}')(remaining)?;
    let (remaining, _) = tag::<_, _, ()>("}")(remaining)
        .map_err(|_| nom::Err::Failure(LexerError::NoOrUnmatchedBracket))?; //make sure our output dosen't contain the last brace.
    let (_, tokens) = many0(get_next_word(" \t="))(between_braces)?;
    let num_to_take = if tokens.len() % 2 == 1 {
        tokens.len() - 1
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

type Combinator<'a> = dyn Fn(&str) -> nom::IResult<&str, &str, LexerError<&str>> + 'a;

fn get_next_word<'a>(seperator: &'a str) -> Box<Combinator<'a>> {
    let escaped = std::cell::Cell::new(false);
    let in_quotes = std::cell::Cell::new(false);
    //I'm sorry to whoever has to read this atrocity.
    Box::new(move |contents| {
        let seperator_detector = |c: char| {
            if c == '"' && !escaped.get() {
                in_quotes.set(!in_quotes.get());
                eprintln!("in_quotes: {:?} c {}", in_quotes, c);
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

#[derive(Debug, PartialEq, Eq)]
pub enum Token<'a> {
    Permit,
    Deny,
    NoPass,
    KeepEnv,
    As,
    Cmd,
    Args,
    EOL,
    Ident(&'a str),
    SetEnv(HashMap<&'a str, &'a str>),
}

impl<'a> From<&'a str> for Token<'a> {
    fn from(token: &'a str) -> Self {
        match token {
            "permit" => Self::Permit,
            "deny" => Self::Deny,
            "\n" => Self::EOL,
            "nopass" => Self::NoPass,
            "keepenv" => Self::KeepEnv,
            "as" => Self::As,
            "cmd" => Self::Cmd,
            "args" => Self::Args,
            c => Self::Ident(c),
        }
    }
}

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
