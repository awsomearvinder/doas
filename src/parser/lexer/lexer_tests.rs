use super::*;

#[test]
fn test_parse_set_env() {
    assert_eq!(
        parse_set_env("{ key value key2 value2}"),
        Ok(("", {
            let mut m = HashMap::new();
            m.insert("key", "value");
            m.insert("key2", "value2");
            Token::SetEnv(m)
        }))
    )
}

#[test]
fn test_parse_set_env_with_escapes() {
    assert_eq!(
        parse_set_env(r#"{ key value key2=value2 key\ with\ escapes value key3 value3}"#),
        Ok(("", {
            let mut m = HashMap::new();
            m.insert("key", "value");
            m.insert("key2", "value2");
            m.insert("key\\ with\\ escapes", "value");
            m.insert("key3", "value3");
            Token::SetEnv(m)
        }))
    );
}

#[test]
fn test_parse_set_env_with_quotes() {
    assert_eq!(
        parse_set_env(
            r#"{ key value key2=value2 "fancy key with quotes" "fancy value" key3 value3}"#
        ),
        Ok(("", {
            let mut m = HashMap::new();
            m.insert("key", "value");
            m.insert("key2", "value2");
            m.insert("\"fancy key with quotes\"", "\"fancy value\"");
            m.insert("key3", "value3");
            Token::SetEnv(m)
        }))
    );
}

#[test]
fn test_get_next_word() {
    assert_eq!(
        get_next_word(" \t=")(" test one two three"),
        Ok((" one two three", "test"))
    )
}

#[test]
fn test_full_line() {
    assert_eq!(
        get_tokens("permit setenv {key value key2=value2 \"weird key\" \"weird value\" \\ lol\\ escapes value }bender as root cmd cargo"),
        Ok(vec![
            Token::from("permit"),
            Token::SetEnv({
                let mut m = HashMap::new();
                m.insert("key", "value");
                m.insert("key2", "value2");
                m.insert("\"weird key\"", "\"weird value\"");
                m.insert("\\ lol\\ escapes", "value");
                m
            }),
            Token::from("bender"),
            Token::from("as"),
            Token::from("root"),
            Token::from("cmd"),
            Token::from("cargo"),
            Token::from("\n"),
        ])
    )
}
