//TODO: This entire API could of been improved if I just passed around the rule builder, instead of
//Arg Possibilities and that whole jam. Oh well, live and learn.
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::bytes::complete::take_till;
use nom::bytes::complete::take_until;
use nom::combinator::map;
use nom::combinator::map_parser;
use nom::combinator::opt;
use nom::multi::many0;

use std::collections::HashMap;

pub mod parser_err;
use parser_err::ParserError;

pub mod rules;
use rules::Rule;
use rules::RuleBuilder;

#[cfg(test)]
mod tests;

mod lexer;

#[allow(dead_code)]
pub fn parse_rule(contents: &str) -> Result<Rule, ParserError<&str>> {
    //This builds our "Rule" type, which can be a permit, deny, or comment (with info on the rule).
    let mut rule_builder = RuleBuilder::new();

    //Get's whether it's permit or deny or comment.
    let (remaining, parser_rule) =
        get_rule_type(contents).map_err(|_| match get_next_word(contents) {
            Err(nom::Err::Error(ParserError::NoArgsLeft)) => ParserError::NoRule,
            Ok((_, matched)) => ParserError::UnknownRule(matched.to_owned()),
            _ => unreachable!(),
        })?;
    rule_builder = rule_builder.with_rule_type(parser_rule);

    //Parse all the options following permit or deny
    let (remaining, conf_args) = parse_all_args(remaining).map_err(|err| match err {
        nom::Err::Failure(e) => e,
        nom::Err::Error(e) => e,
        _ => unreachable!(),
    })?;
    for i in conf_args {
        rule_builder = match i {
            ArgPossibility::Persist => rule_builder.with_persist(true),
            ArgPossibility::NoPass => rule_builder.with_no_pass(true),
            ArgPossibility::KeepEnv => rule_builder.with_keep_env(true),
            ArgPossibility::SetEnv(map) => rule_builder.with_set_env(map),
        }
    }

    //Get who the rule is for.
    let (remaining, user) = get_next_word(remaining).map_err(|_| ParserError::NoUser)?;
    rule_builder = rule_builder.with_identity_name(user);

    //Get the target of the rule, e.g. who can the user "run as", if it's provided.
    let (remaining, target) = get_target(remaining).map_err(|_| ParserError::NoTarget)?;
    if let Some(target) = target {
        rule_builder = rule_builder.with_target(target);
    }

    //get the cmd, if it exists.
    let (mut remaining, cmd) = get_cmd(remaining).map_err(|_| ParserError::NoCmd)?;

    if let Some(cmd) = cmd {
        rule_builder = rule_builder.with_cmd(cmd);
        let (remaining_inner, cmd_args) =
            get_cmd_args(remaining).map_err(|_| ParserError::NoCmdArgs)?;

        //Args should only be given if a cmd has been given.
        if let Some(args) = cmd_args {
            rule_builder = rule_builder.with_cmd_args(args);
        }

        remaining = remaining_inner;
    }

    if !remaining.trim().is_empty() {
        return Err(ParserError::FoundTrailingAfterRule);
    }

    Ok(rule_builder.build().unwrap())
}

fn get_rule_type(contents: &str) -> nom::IResult<&str, &str, ParserError<&str>> {
    map_parser(get_next_word, alt((tag("#"), tag("permit"), tag("deny"))))(contents)
}

///Get's the target if the next word is (as), otherwise return's None. Error's if nothing following
///as
fn get_target(contents: &str) -> nom::IResult<&str, Option<&str>, ParserError<&str>> {
    Ok(match opt(map_parser(get_next_word, tag("as")))(contents)? {
        (remaining, Some(_)) => {
            let (remaining, next_word) = get_next_word(remaining)?;
            (remaining, Some(next_word))
        }
        (remaining, None) => (remaining, None),
    })
}

//FIXME: This should not return two Vec's, just a &str and a Vec
///Get's the command (as a Vec) along with the args (as a Vec)
fn get_cmd(contents: &str) -> nom::IResult<&str, Option<&str>, ParserError<&str>> {
    let (remaining, matched) = opt(map_parser(get_next_word, tag("cmd")))(contents)?;
    let (remaining, _) = take_till(|c| !" \t=".contains(c))(remaining)?;
    if matched.is_none() {
        return Ok((remaining, None));
    }
    Ok(match take_until("args")(remaining) {
        Ok((remaining, cmd)) => (remaining, Some(cmd.trim())),
        Err(nom::Err::Error((remaining, nom::error::ErrorKind::TakeUntil))) => {
            if remaining.is_empty() {
                return Err(nom::Err::Failure(ParserError::NoCmd));
            } else {
                ("", Some(remaining.trim()))
            }
        }
        _ => unreachable!(),
    })
}

fn get_cmd_args(contents: &str) -> nom::IResult<&str, Option<Vec<&str>>, ParserError<&str>> {
    let (remaining, matched) = opt(map_parser(get_next_word, tag("args")))(contents)?;
    if matched.is_none() {
        return Ok((remaining, None));
    }
    let (remaining, args) = many0(get_next_word)(remaining)?;
    Ok((remaining, Some(args)))
}

///Repeatedly parses the next argument.
fn parse_all_args(contents: &str) -> nom::IResult<&str, Vec<ArgPossibility>, ParserError<&str>> {
    Ok(many0(parse_arg)(contents.trim())?)
}

///Parses an argument. Returns an error if it can't recognize arg, or it can't parse an arg.
fn parse_arg(contents: &str) -> nom::IResult<&str, ArgPossibility, ParserError<&str>> {
    alt((
        map(
            alt((tag("persist"), tag("nopass"), tag("keepenv"))),
            |s: &str| match s {
                "persist" => ArgPossibility::Persist,
                "nopass" => ArgPossibility::NoPass,
                "keepenv" => ArgPossibility::KeepEnv,
                _ => unreachable!(),
            },
        ),
        parse_set_env,
    ))(contents.trim())
}

///Parses the setenv arg, errors if unmatched { or }.
fn parse_set_env(contents: &str) -> nom::IResult<&str, ArgPossibility, ParserError<'_, &str>> {
    let (remaining, _matched_val) = tag("setenv")(contents)?;
    let (after_opening_brace, _brace) = tag::<_, _, ParserError<&str>>("{")(remaining.trim_start())
        .map_err(|_| nom::Err::Failure(ParserError::UnmatchedOrNoSetEnvBracket))?;

    let (everything_following_closing_brace, inside_set_env) =
        take_until::<_, _, ParserError<&str>>("}")(after_opening_brace.trim_start())
            .map_err(|_| nom::Err::Failure(ParserError::UnmatchedOrNoSetEnvBracket))?;

    let (_should_be_empty, pairs) = many0(get_next_word)(inside_set_env)?;
    let pairs = pairs
        .into_iter()
        .as_slice()
        .chunks(2)
        .filter_map(|t| {
            if t.len() == 2 {
                Some((t[0], t[1]))
            } else {
                None
            }
        })
        .collect();
    if !_should_be_empty.trim().is_empty() {
        Err(nom::Err::Error(ParserError::InvalidKeyValsInSetEnv(pairs)))
    } else {
        Ok((
            &everything_following_closing_brace[1..],
            ArgPossibility::SetEnv(pairs),
        ))
    }
}

///Returns the next word, fails if no words are left. (space, equal, or tab seperated)
fn get_next_word(contents: &str) -> nom::IResult<&str, &str, ParserError<&str>> {
    let (remaining, _whitespace) = take_till(|c| !" =\t".contains(c))(contents)?;
    if remaining.is_empty() {
        return Err(nom::Err::Error(ParserError::NoArgsLeft));
    }
    take_till(|c| " =\t".contains(c))(remaining)
}

///Represents everything an arg can be
#[derive(Debug, Eq, PartialEq)]
pub enum ArgPossibility<'a> {
    Persist,
    NoPass,
    KeepEnv,
    SetEnv(HashMap<&'a str, &'a str>),
}
