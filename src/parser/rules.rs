use super::ParserError;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum Rule {
    Permit(String, ConfigArgs),
    Deny(String, ConfigArgs),
    Comment,
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
            .eq(cmd_args.iter().map(|s| s.trim()))
        {
            return false;
        }
    }
    true
}

pub struct RuleBuilder<'a> {
    rule_type: Option<&'a str>,
    identity_name: Option<&'a str>,
    persist: bool,
    keep_env: bool,
    no_pass: bool,
    set_env: HashMap<&'a str, &'a str>,
    target: Option<&'a str>,
    cmd: Option<&'a str>,
    args: Option<Vec<&'a str>>,
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

impl<'a> RuleBuilder<'a> {
    pub fn new() -> Self {
        Self {
            rule_type: None,
            identity_name: None,
            keep_env: false,
            persist: false,
            no_pass: false,
            set_env: HashMap::new(),
            target: None,
            cmd: None,
            args: None,
        }
    }

    pub fn with_rule_type(mut self, rule: &'a str) -> RuleBuilder<'a> {
        self.rule_type = Some(rule);
        self
    }

    pub fn with_keep_env(mut self, keep_env: bool) -> RuleBuilder<'a> {
        self.keep_env = keep_env;
        self
    }

    pub fn with_identity_name(mut self, name: &'a str) -> RuleBuilder<'a> {
        self.identity_name = Some(name);
        self
    }

    pub fn with_no_pass(mut self, no_pass: bool) -> RuleBuilder<'a> {
        self.no_pass = no_pass;
        self
    }

    pub fn with_set_env(mut self, env: HashMap<&'a str, &'a str>) -> RuleBuilder<'a> {
        self.set_env = env;
        self
    }

    pub fn with_target(mut self, target_user: &'a str) -> RuleBuilder<'a> {
        self.target = Some(target_user);
        self
    }

    pub fn with_persist(mut self, persist: bool) -> RuleBuilder<'a> {
        self.persist = persist;
        self
    }

    pub fn with_cmd(mut self, cmd: &'a str) -> RuleBuilder<'a> {
        self.cmd = Some(cmd);
        self
    }

    pub fn with_cmd_args(mut self, args: Vec<&'a str>) -> RuleBuilder<'a> {
        self.args = Some(args);
        self
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
            "permit" => Rule::Permit(identity, args),
            "deny" => Rule::Deny(identity, args),
            "#" => Rule::Comment,
            a => return Err(ParserError::UnknownRule(a.to_owned())),
        })
    }
}
