pub mod parser_err;
use parser_err::ParserError;

pub mod rules;
use rules::Rule;

#[cfg(test)]
mod tests;

mod lexer;

#[allow(dead_code)]
pub fn parse_rules(contents: &str) -> Vec<Result<Rule, ParserError<&str>>> {
    let tokens = dbg!(lexer::get_tokens(contents).unwrap_or_else(|e| panic!("Got err {:?}", e)));
    let mut tokens = tokens.into_iter();
    let mut rules = vec![];
    let rule = rules::RuleBuilder::new();
    let rule = match tokens.next() {
        Some(lexer::Token::Permit) => rule.permit(),
        Some(lexer::Token::Deny) => rule.deny(),
        Some(token) => panic!("Expected rule in config got {:?} token", token),
        None => return rules,
    };
    let mut rule = rule;
    loop {
        match tokens.next() {
            Some(lexer::Token::NoPass) => rule = rule.no_pass(),
            Some(lexer::Token::Persist) => rule = rule.persist(),
            Some(lexer::Token::KeepEnv) => rule = rule.keep_env(),
            Some(lexer::Token::SetEnv(m)) => rule = rule.set_env(m),
            Some(lexer::Token::Ident(user_identity)) => {
                rule = rule.identity_name(user_identity);
                break;
            }
            Some(token) => panic!("Expected option or user identity got token {:?}", token),
            None => panic!("Expected option or user identity, got nothing."),
        }
    }
    eprintln!("{:?}", contents);
    'outer: loop {
        match tokens.next() {
            Some(lexer::Token::As) => match tokens.next() {
                Some(lexer::Token::Ident(target)) => rule = rule.target(target),
                Some(token) => panic!("Expected target user's name, got {:?} token", token),
                None => panic!("Expected target user name."),
            },
            Some(lexer::Token::Cmd) => match tokens.next() {
                Some(lexer::Token::Ident(cmd_name)) => {
                    rule = rule.with_cmd(cmd_name);
                    match tokens.next() {
                        Some(lexer::Token::Args) => {
                            rule = rule.with_cmd(cmd_name);
                            let mut args = vec![];
                            for i in &mut tokens {
                                if let lexer::Token::Ident(arg) = i {
                                    args.push(arg);
                                } else if lexer::Token::EOL == i {
                                    rule = rule.with_cmd_args(args);
                                    rules.push(rule.build());
                                    break 'outer;
                                }
                            }
                            rule = rule.with_cmd_args(args);
                            rules.push(rule.build());
                            break 'outer;
                        }
                        Some(token) => panic!("expected args token, found token {:?}", token),
                        None => {
                            rules.push(rule.build());
                            break 'outer;
                        }
                    }
                }
                Some(token) => panic!("Expected command name, got {:?} token", token),
                None => panic!("Expected command name"),
            },
            Some(lexer::Token::EOL) => {
                rules.push(rule.build());
                break;
            }
            Some(token) => {
                panic!("Got unexpected token {:?}", token);
            }
            None => break,
        }
    }
    rules
}
