use crate::user::User;

use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::bytes::complete::take_till;
use nom::combinator::map;

use std::collections::HashMap;

fn parse_rule(contents: &str) -> Result<Rule, ParserError<&str>> {
    let rule_builder = RuleBuilder::new();

    let (remaining, parser_rule) =
        alt::<_, _, ParserError<&str>, _>((tag("#"), tag("permit"), tag("deny")))(contents)
            .map_err(|_| ParserError::UnknownRule)?;

    let rule_builder = match parser_rule {
        "permit" => rule_builder.with_rule_type("permit"),
        "deny" => rule_builder.with_rule_type("deny"),
        "#" => rule_builder.with_rule_type("comment"),
        _ => unreachable!(),
    };

    remaining.trim_start();
    todo!()
}

fn parse_arg(contents: &str) -> nom::IResult<&str, ArgPossibility, ParserError<&str>> {
    alt((
        map(
            alt((tag("persist"), tag("nopass"), tag("keepenv"))),
            |s: &str| match s {
                "persist" => ArgPossibility::persist,
                "nopass" => ArgPossibility::no_pass,
                "keepenv" => ArgPossibility::keep_env,
                _ => unreachable!(),
            },
        ),
        parse_set_env,
    ))(contents)
}

fn parse_set_env(contents: &str) -> nom::IResult<&str, ArgPossibility, ParserError<&str>> {
    let (remaining, matched_val) = tag("setenv")(contents)?;
    let (after_opening_brace, brace) = tag("{")(remaining.trim_start())?;
    let (inside_set_env, closing_brace) = take_till(|c| c == '}')(after_opening_brace.trim())?;
    todo!()
}

fn get_next_word(contents: &str) -> nom::IResult<&str, ArgPossibility, ParserError<&str>> {
    todo!()
}

#[derive(Debug, Eq, PartialEq)]
enum ArgPossibility<'a> {
    persist,
    no_pass,
    keep_env,
    set_env(HashMap<&'a str, &'a str>),
}

#[derive(Debug, PartialEq, Eq)]
enum Rule {
    Permit(User, ConfigArgs),
    Deny(User, ConfigArgs),
    Comment,
}

struct RuleBuilder<'a> {
    rule_type: Option<&'a str>,
    identity_name: Option<&'a str>,
    permit: bool,
    no_pass: bool,
    set_env: HashMap<&'a str, &'a str>,
    target: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq, Default)]
struct ConfigArgs {
    permit: bool,
    keep_env: bool,
    no_pass: bool,
    set_env: HashMap<String, String>,
    target: Option<User>,
}

impl<'a> RuleBuilder<'a> {
    fn new() -> Self {
        Self {
            rule_type: None,
            identity_name: None,
            permit: false,
            no_pass: false,
            set_env: HashMap::new(),
            target: None,
        }
    }
    fn with_rule_type(mut self, rule: &'a str) -> RuleBuilder<'a> {
        self.rule_type = Some(rule);
        self
    }
    fn with_identity_name(mut self, name: &'a str) -> RuleBuilder<'a> {
        self.identity_name = Some(name);
        self
    }
    fn with_no_pass(mut self, no_pass: bool) -> RuleBuilder<'a> {
        self.no_pass = no_pass;
        self
    }
    fn with_set_env(mut self, env: HashMap<&'a str, &'a str>) -> RuleBuilder<'a> {
        self.set_env = env;
        self
    }
    fn with_target(mut self, target_user: &'a str) -> RuleBuilder<'a> {
        self.target = Some(target_user);
        self
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ParserError<I> {
    UnknownRule,
    NomError(I, nom::error::ErrorKind),
}

impl<I> nom::error::ParseError<I> for ParserError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self::NomError(input, kind)
    }
    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_parse_arg_bool_type() {
        assert_eq!(
            parse_arg("persist test"),
            Ok((" test", ArgPossibility::persist)),
        );
    }

    #[test]
    #[ignore]
    fn check_parse_arg_set_env() {
        todo!()
    }

    #[test]
    #[ignore]
    fn check_ok_parse_path() {
        assert_eq!(
            parse_rule(
                "permit nopass keepenv setenv {TESTVAR = TESTKEY} 😀test_user as root cmd cargo"
            ),
            Ok(Rule::Permit(
                User::test_user(),
                ConfigArgs {
                    keep_env: true,
                    no_pass: true,
                    set_env: {
                        let mut m = HashMap::new();
                        m.insert(String::from("TESTVAR"), String::from("TESTKEY"));
                        m
                    },
                    ..Default::default()
                }
            ))
        )
    }

    #[test]
    #[ignore]
    fn check_err_parse_path() {
        assert!(parse_rule("hi permit") == Err(ParserError::UnknownRule))
    }

    #[test]
    #[ignore]
    fn check_deny_path() {
        assert_eq!(
            parse_rule("permit nopass keepenv setenv {TESTVAR = TESTKEY} as root cmd cargo"),
            Ok(Rule::Permit(
                User::test_user(),
                ConfigArgs {
                    keep_env: true,
                    no_pass: true,
                    set_env: {
                        let mut m = HashMap::new();
                        m.insert(String::from("TESTVAR"), String::from("TESTKEY"));
                        m
                    },
                    ..Default::default()
                }
            ))
        )
    }
}
