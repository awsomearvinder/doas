use super::rules::ConfigArgs;
use super::Rule;
use super::*;

#[test]
fn check_parse_arg_bool_type() {
    assert_eq!(
        parse_arg(" persist test"),
        Ok((" test", ArgPossibility::Persist)),
    );
}

#[test]
fn check_get_next_word() {
    assert_eq!(get_next_word(" hmmm lets see"), Ok((" lets see", "hmmm")));
}

#[test]
fn check_parse_arg_bool_type_wrong() {
    assert!(parse_arg("a test").is_err());
    assert!(parse_arg("permit test").is_err());
    assert!(parse_arg("candy test").is_err());
}

#[test]
fn check_parse_arg_set_env() {
    assert_eq!(
            parse_set_env("setenv { testkey1 testval1 testkey2=testval2 } some values that the parser shouldn't care about"),
            Ok((
                " some values that the parser shouldn't care about",
                ArgPossibility::SetEnv({
                    let mut m = HashMap::new();
                    m.insert("testkey1", "testval1");
                    m.insert("testkey2", "testval2");
                    m
                })
            ))
        );
}

#[test]
fn check_parse_all_args() {
    assert_eq!(
        parse_all_args("persist keepenv setenv {key1=value1 key2 val2} some other stuff"),
        Ok((
            " some other stuff",
            vec![
                ArgPossibility::Persist,
                ArgPossibility::KeepEnv,
                ArgPossibility::SetEnv({
                    let mut m = HashMap::new();
                    m.insert("key1", "value1");
                    m.insert("key2", "val2");
                    m
                })
            ]
        ))
    );
}

#[test]
fn check_ok_permit_parse_path() {
    assert_eq!(
        parse_rule("permit keepenv setenv {TESTVAR = TESTKEY} user as root cmd cargo"),
        Ok::<_, ParserError<&str>>(
            RuleBuilder::new()
                .with_rule_type("permit")
                .with_keep_env(true)
                .with_set_env({
                    let mut m = HashMap::new();
                    m.insert("TESTVAR", "TESTKEY");
                    m
                })
                .with_target("root")
                .with_cmd(std::process::Command::new("cargo"))
                .with_identity_name("user")
        )
        .unwrap()
        .build()
    )
}

#[test]
fn check_err_parse_path() {
    assert_eq!(
        parse_rule("hi permit"),
        Err(ParserError::UnknownRule(String::from("hi")))
    );
}

#[test]
fn check_unmatched_bracket_in_set_env() {
    assert_eq!(
        parse_set_env("setenv { woigjoaiwgjowig"),
        Err(nom::Err::Failure(ParserError::UnmatchedOrNoSetEnvBracket))
    );
    assert_eq!(
        parse_set_env("setenv  woigjoaiwgjowig }"),
        Err(nom::Err::Failure(ParserError::UnmatchedOrNoSetEnvBracket))
    );
}

#[test]
fn check_err_no_cmd() {
    assert_eq!(
        parse_rule("deny user as root cmd "),
        Err(ParserError::NoCmd)
    )
}

#[test]
fn check_err_no_target() {
    assert_eq!(parse_rule("deny user as "), Err(ParserError::NoTarget))
}

#[test]
fn check_err_trailing_chars() {
    assert_eq!(
        parse_rule("deny user as user wioagjewaiogjwioagjio"),
        Err(ParserError::FoundTrailingAfterRule)
    )
}

#[test]
fn check_ok_deny_path() {
    assert_eq!(
        parse_rule("deny keepenv setenv {TESTVAR = TESTKEY} user as root cmd cargo"),
        Ok::<_, ParserError<&str>>(
            RuleBuilder::new()
                .with_rule_type("deny")
                .with_keep_env(true)
                .with_set_env({
                    let mut m = HashMap::new();
                    m.insert("TESTVAR", "TESTKEY");
                    m
                })
                .with_identity_name("user")
                .with_target("root")
                .with_cmd(std::process::Command::new("cargo"))
        )
        .unwrap()
        .build()
    )
}

#[test]
fn check_get_next_word_no_args_left() {
    assert_eq!(
        get_next_word("    "),
        Err(nom::Err::Error(ParserError::NoArgsLeft))
    )
}

#[test]
fn check_unmatched_set_env_first_bracket() {
    assert_eq!(
        parse_rule("deny keepenv setenv TESTVAR = TESTKEY} user as root cmd cargo"),
        Err(ParserError::UnmatchedOrNoSetEnvBracket)
    )
}

#[test]
fn check_unmatched_set_env_second_bracket() {
    assert_eq!(
        parse_rule("deny keepenv setenv {TESTVAR = TESTKEY user as root cmd cargo"),
        Err(ParserError::UnmatchedOrNoSetEnvBracket)
    )
}
