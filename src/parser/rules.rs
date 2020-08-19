use super::ParserError;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum Rule {
    Permit(String, ConfigArgs),
    Deny(String, ConfigArgs),
    Comment,
}

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
    pub fn is_allowed(
        &self,
        name: &str,
        cmd: &str,
        cmd_args: &[&str],
        target: &str,
    ) -> Option<bool> {
        match self {
            Self::Permit(user, conf_args) => {
                if check_if_match(user, name, target, cmd, cmd_args, conf_args) {
                    Some(true)
                } else {
                    None
                }
            }
            Self::Deny(user, conf_args) => {
                if check_if_match(user, name, target, cmd, cmd_args, conf_args) {
                    Some(false)
                } else {
                    None
                }
            }
            Self::Comment => None,
        }
    }
    pub fn get_identity(&self) -> Option<&str> {
        match self {
            Self::Permit(user, _) => Some(user),
            Self::Deny(user, _) => Some(user),
            Self::Comment => None,
        }
    }
    pub fn get_set_env(&self) -> Option<&HashMap<String, String>> {
        match self {
            Self::Permit(_, args) => Some(&args.set_env),
            Self::Deny(_, args) => Some(&args.set_env),
            Self::Comment => None,
        }
    }
}

fn check_if_match(
    user_rule_name: &str,
    user_attempt_name: &str,
    target: &str,
    cmd: &str,
    cmd_args: &[&str],
    conf_args: &ConfigArgs,
) -> bool {
    let mut cmd_args = cmd_args.iter().collect::<Vec<_>>();
    cmd_args.sort();

    if user_rule_name != user_attempt_name {
        return false;
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
    if let Some(mut conf_cmd_args) = conf_args.args.clone() {
        conf_cmd_args.sort();
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

    pub fn permit(mut self) -> Self {
        Self {
            rule_type: Some(RuleType::Permit),
            ..self
        }
    }

    pub fn deny(mut self) -> Self {
        Self {
            rule_type: Some(RuleType::Deny),
            ..self
        }
    }

    pub fn keep_env(mut self) -> Self {
        Self {
            keep_env: true,
            ..self
        }
    }

    pub fn set_env(mut self, m: HashMap<&'a str, &'a str>) -> Self {
        Self { set_env: m, ..self }
    }

    pub fn identity_name(mut self, name: &'a str) -> RuleBuilder<'a> {
        Self {
            identity_name: Some(name),
            ..self
        }
    }

    pub fn no_pass(mut self) -> Self {
        Self {
            no_pass: true,
            ..self
        }
    }

    pub fn target(mut self, target_user: &'a str) -> RuleBuilder<'a> {
        Self {
            target: Some(target_user),
            ..self
        }
    }

    pub fn persist(mut self) -> RuleBuilder<'a> {
        Self {
            persist: true,
            ..self
        }
    }

    pub fn with_cmd(mut self, cmd: &'a str) -> RuleBuilder<'a> {
        Self {
            cmd: Some(cmd),
            ..self
        }
    }

    pub fn with_cmd_args(mut self, args: Vec<&'a str>) -> RuleBuilder<'a> {
        Self {
            args: Some(args),
            ..self
        }
    }

    pub fn build(self) -> Result<Rule, ParserError<'static, &'static str>> {
        //arguments for doas user.
        let args = ConfigArgs {
            persist: self.persist,
            keep_env: self.keep_env,
            no_pass: self.no_pass,
            set_env: self
                .set_env
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            target: self.target.map(|s| s.to_owned()),
            cmd: self.cmd.map(|s| s.to_owned()),
            args: self
                .args
                .map(|v| v.into_iter().map(|s| s.to_owned()).collect()),
        };

        let identity = self.identity_name.ok_or(ParserError::NoUser)?.to_owned();

        Ok(match self.rule_type.ok_or(ParserError::NoRule)? {
            RuleType::Permit => Rule::Permit(identity, args),
            RuleType::Deny => Rule::Deny(identity, args),
        })
    }
}
