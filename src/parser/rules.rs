//! This module defines the Rule type - a type used regularly throughout doas
//! in order to represent any given rule in the config.
//! A rule is defined as a series of arguments that apply to doas to one particular user.
//! A real implementation of doas should always use the last match of the config.
use super::ParserError;
use std::collections::HashMap;

//TODO: Remove the Comment enum.
///Represents a Rule.
///The first String is the user the rule applies too
///Config args are the arguments that apply to the user
///(aside from permit or deny.)
///Created with RuleBuilder.
#[derive(Debug, PartialEq, Eq)]
pub enum Rule {
    Permit(UserOrGroup, ConfigArgs),
    Deny(UserOrGroup, ConfigArgs),
}

#[derive(Debug, PartialEq, Eq)]
pub enum UserOrGroup {
    User(String),
    Group(String),
}

///The potential args given to any rule.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct ConfigArgs {
    persist: bool,
    keep_env: bool,
    no_pass: bool,
    set_env: HashMap<String, String>,
    target: Option<String>,
    cmd: Option<String>,
    args: Option<Vec<String>>,
}

impl Rule {
    ///Returns a boolean representing if the user is allowed to run the command or not
    ///Returns None in the case that the rule dosen't match on the given args.
    pub fn is_allowed<'a, T: std::fmt::Debug + IntoIterator<Item = &'a str>>(
        &self,
        name: &str,
        groups: T,
        cmd: &str,
        cmd_args: &[&str],
        target: &str,
    ) -> Option<bool> {
        match self {
            Self::Permit(user, conf_args) => {
                if check_if_match(user, name, groups, target, cmd, cmd_args, conf_args) {
                    Some(true)
                } else {
                    None
                }
            }
            Self::Deny(user, conf_args) => {
                if check_if_match(user, name, groups, target, cmd, cmd_args, conf_args) {
                    Some(false)
                } else {
                    None
                }
            }
        }
    }
    pub fn get_identity(&self) -> &UserOrGroup {
        match self {
            Self::Permit(user, _) => user,
            Self::Deny(user, _) => user,
        }
    }
    pub fn get_set_env(&self) -> &HashMap<String, String> {
        match self {
            Self::Permit(_, args) => &args.set_env,
            Self::Deny(_, args) => &args.set_env,
        }
    }
    pub fn get_no_pass(&self) -> bool {
        match self {
            Self::Permit(_, args) => args.no_pass,
            Self::Deny(_, args) => args.no_pass,
        }
    }
    pub fn get_persist(&self) -> bool {
        match self {
            Self::Permit(_, args) => args.persist,
            Self::Deny(_, args) => args.persist,
        }
    }
}

///Helper function to check if a set of data matches with the rule.
fn check_if_match<'a, T: std::fmt::Debug + IntoIterator<Item = &'a str>>(
    rule_applies_to: &UserOrGroup,
    user_attempt_name: &str,
    user_groups: T,
    target: &str,
    cmd: &str,
    cmd_args: &[&str],
    conf_args: &ConfigArgs,
) -> bool {
    match rule_applies_to {
        UserOrGroup::User(s) if s.as_str() != user_attempt_name => return false,
        UserOrGroup::Group(s) if user_groups.into_iter().all(|g| g != s.as_str()) => return false,
        _ => (),
    }

    if let Some(rule_target) = &conf_args.target {
        if target.trim() != rule_target.trim() {
            return false;
        }
    }

    if let Some(conf_cmd) = &conf_args.cmd {
        if conf_cmd.trim() != cmd.trim() {
            return false;
        }
    }
    if let Some(conf_cmd_args) = conf_args.args.clone() {
        if !cmd_args
            .iter()
            .map(|s| s.trim())
            .eq(conf_cmd_args.iter().map(|s| s.trim()))
        {
            return false;
        }
    }
    true
}

///This instantiates the Rule rather then creating
///the Rule directly.
#[derive(Default)]
pub struct RuleBuilder<'a> {
    rule_type: Option<RuleType>,
    identity_name: Option<&'a str>,
    persist: bool,
    keep_env: bool,
    no_pass: bool,
    set_env: HashMap<&'a str, &'a str>,
    target: Option<&'a str>,
    cmd: Option<&'a str>,
    args: Option<Vec<&'a str>>,
}
enum RuleType {
    Permit,
    Deny,
}

impl<'a> RuleBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn permit(self) -> Self {
        Self {
            rule_type: Some(RuleType::Permit),
            ..self
        }
    }

    pub fn deny(self) -> Self {
        Self {
            rule_type: Some(RuleType::Deny),
            ..self
        }
    }

    pub fn keep_env(self) -> Self {
        Self {
            keep_env: true,
            ..self
        }
    }

    pub fn set_env(self, m: HashMap<&'a str, &'a str>) -> Self {
        Self { set_env: m, ..self }
    }

    pub fn identity_name(self, name: &'a str) -> RuleBuilder<'a> {
        Self {
            identity_name: Some(name),
            ..self
        }
    }

    pub fn no_pass(self) -> Self {
        Self {
            no_pass: true,
            ..self
        }
    }

    pub fn target(self, target_user: &'a str) -> RuleBuilder<'a> {
        Self {
            target: Some(target_user),
            ..self
        }
    }

    pub fn persist(self) -> RuleBuilder<'a> {
        Self {
            persist: true,
            ..self
        }
    }

    pub fn with_cmd(self, cmd: &'a str) -> RuleBuilder<'a> {
        Self {
            cmd: Some(cmd),
            ..self
        }
    }

    pub fn with_cmd_args(self, args: Vec<&'a str>) -> RuleBuilder<'a> {
        Self {
            args: Some(args),
            ..self
        }
    }

    //TODO: This probably dosen't need to return a Result anymore.
    pub fn build(self) -> Result<Rule, ParserError<'static>> {
        //arguments for doas user.
        let args = ConfigArgs {
            persist: self.persist,
            keep_env: self.keep_env,
            no_pass: self.no_pass,
            set_env: self
                .set_env
                .into_iter()
                .map(|(k, v)| (escaped_string(k), escaped_string(v)))
                .collect(),
            target: self.target.map(|s| escaped_string(s)),
            cmd: self.cmd.map(|s| escaped_string(s)),
            args: self
                .args
                .map(|v| v.into_iter().map(|s| escaped_string(s)).collect()),
        };

        let identity = self.identity_name.expect("wasn't given identity name.");

        let identity = if identity.starts_with(':') {
            UserOrGroup::Group(String::from(&identity[1..]))
        } else {
            UserOrGroup::User(String::from(identity))
        };

        Ok(match self.rule_type.expect("wasn't given rule type") {
            RuleType::Permit => Rule::Permit(identity, args),
            RuleType::Deny => Rule::Deny(identity, args),
        })
    }
}

///This struct is a helper struct to work with escaped string characters and
///to remove and parse them out
#[derive(Debug, Default)]
struct EscapeString {
    previous_char_is_escape: bool,
}
impl EscapeString {
    fn new() -> Self {
        Self {
            previous_char_is_escape: false,
        }
    }
    ///returns whether the character should be escaped based on the previous run (assuming the
    ///previous run was the character before it)
    fn should_char_be_escaped(&mut self, c: char) -> bool {
        if self.previous_char_is_escape {
            self.previous_char_is_escape = false;
            true
        } else if c == '\\' {
            self.previous_char_is_escape = true;
            false
        } else {
            c != '\"'
        }
    }
}

///Returns a string with parsed out escape characters.
fn escaped_string(s: &str) -> String {
    let mut escaped_string_state = EscapeString::new();
    s.chars()
        .filter(|&c| escaped_string_state.should_char_be_escaped(c))
        .collect()
}

///Minimal tests for escaping strings.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_string() {
        assert_eq!(escaped_string(r#"\ woah"#), String::from(" woah"));
        assert_eq!(escaped_string("\" woah\""), String::from(" woah"));
        assert_eq!(escaped_string(r#"\" woah\""#), String::from(r#"" woah""#));
        assert_eq!(escaped_string("\\\" woah"), String::from("\" woah"));
    }
}
