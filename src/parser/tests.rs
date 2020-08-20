use super::*;
use std::collections::HashMap;

#[test]
fn check_parse_line() {
    assert_eq!(
        parse_rules("permit bender as root"),
        vec![rules::RuleBuilder::new()
            .target("root")
            .permit()
            .identity_name("bender")
            .build()]
    )
}

#[test]
fn check_parse_multi_line() {
    assert_eq!(
        parse_rules("permit bender as root\n permit test as user"),
        vec![
            rules::RuleBuilder::new()
                .target("root")
                .permit()
                .identity_name("bender")
                .build(),
            rules::RuleBuilder::new()
                .permit()
                .target("user")
                .identity_name("test")
                .build()
        ]
    )
}

#[test]
fn check_unknown_rule() {
    assert_eq!(
        parse_rules("wiojgroijgioj"),
        vec![Err(ParserError::ExpectedRuleGot(lexer::Token::from(
            "wiojgroijgioj"
        )))]
    )
}

#[test]
fn check_unknown_option() {
    assert_eq!(
        parse_rules("permit cmd"),
        vec![Err(ParserError::ExpectedOptionOrIdentityGot(
            lexer::Token::from("cmd")
        ))]
    )
}

#[test]
fn check_unknown_cmd_path() {
    assert_eq!(
        parse_rules("permit john john"),
        vec![Err(ParserError::ExpectedCmdPathGot(lexer::Token::from(
            "john"
        )))]
    )
}

#[test]
fn check_parse_full_multi_line() {
    assert_eq!(
        parse_rules(
            "permit bender as root cmd cargo args\n permit test as user cmd echo args \"hi\""
        ),
        vec![
            rules::RuleBuilder::new()
                .target("root")
                .permit()
                .identity_name("bender")
                .with_cmd("cargo")
                .with_cmd_args(vec![])
                .build(),
            rules::RuleBuilder::new()
                .permit()
                .target("user")
                .identity_name("test")
                .with_cmd("echo")
                .with_cmd_args(vec!["\"hi\""]) //TODO: Change this to not include quotes (unless escaped.) or escaped chars.
                .build()
        ]
    )
}

#[test]
fn check_parse_deny_full_multi_line() {
    assert_eq!(
        parse_rules(
            "deny bender as root cmd cargo args\n permit test as user cmd echo args \"hi bois\" test"
        ),
        vec![
            rules::RuleBuilder::new()
                .target("root")
                .deny()
                .identity_name("bender")
                .with_cmd("cargo")
                .with_cmd_args(vec![])
                .build(),
            rules::RuleBuilder::new()
                .permit()
                .target("user")
                .identity_name("test")
                .with_cmd("echo")
                .with_cmd_args(vec!["\"hi bois\"", "test"])
                .build()
        ]
    )
}

#[test]
fn check_parse_full_line() {
    assert_eq!(
        parse_rules(
            "permit persist setenv { key value key2=value2 \"key one\" \"value one\" } bender as root cmd cargo args"
        ),
        vec![
            rules::RuleBuilder::new()
                .target("root")
                .permit()
                .persist()
                .set_env({
                    let mut m = HashMap::new();
                    m.insert("key", "value");
                    m.insert("key2", "value2");
                    m.insert("\"key one\"", "\"value one\"");
                    m
                })
                .identity_name("bender")
                .with_cmd("cargo")
                .with_cmd_args(vec![])
                .build(),
        ]
    )
}
