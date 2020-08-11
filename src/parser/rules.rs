use super::ParserError;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum Rule {
    Permit(String, ConfigArgs),
    Deny(String, ConfigArgs),
    Comment,
}

pub struct RuleBuilder<'a> {
    rule_type: Option<&'a str>,
    identity_name: Option<&'a str>,
    persist: bool,
    keep_env: bool,
    no_pass: bool,
    set_env: HashMap<&'a str, &'a str>,
    target: Option<&'a str>,
    cmd: WrapperCMD,
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct ConfigArgs {
    persist: bool,
    keep_env: bool,
    no_pass: bool,
    set_env: HashMap<String, String>,
    target: Option<String>,
    cmd: WrapperCMD,
}
#[derive(Debug, Default)]
struct WrapperCMD {
    cmd: Option<std::process::Command>,
}
impl PartialEq for WrapperCMD {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self) == format!("{:?}", other)
    }
}
impl Eq for WrapperCMD {}

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
            cmd: WrapperCMD { cmd: None },
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
    pub fn with_cmd(mut self, cmd: std::process::Command) -> RuleBuilder<'a> {
        self.cmd = WrapperCMD { cmd: Some(cmd) };
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
            cmd: self.cmd,
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
