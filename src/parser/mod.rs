pub mod parser_err;
use parser_err::ParserError;

pub mod rules;
use rules::Rule;

#[cfg(test)]
mod tests;

mod lexer;

#[allow(dead_code)]
pub fn parse_rules<'a>(contents: &'a str) -> Vec<Result<Rule, ParserError<'a>>> {
    let tokens = lexer::get_tokens(contents).unwrap_or_else(|e| panic!("Got err {:?}", e));
    let mut tokens = tokens.into_iter().peekable();
    let mut rules = vec![];
    'main: loop {
        let rule = rules::RuleBuilder::new();
        let rule = match tokens.next() {
            Some(lexer::Token::Permit) => rule.permit(),
            Some(lexer::Token::Deny) => rule.deny(),
            Some(lexer::Token::EOL) => continue,
            Some(token) => {
                rules.push(Err(ParserError::ExpectedRuleGot(token)));
                loop {
                    if tokens.peek() == Some(&lexer::Token::Permit)
                        || tokens.peek() == Some(&lexer::Token::Deny)
                    {
                        continue 'main;
                    } else {
                        tokens.next();
                    }
                }
            }
            None => break 'main,
        };

        let mut rule = get_options_and_identity(rule, &mut tokens).unwrap();
        eprintln!("{:?}", contents);

        loop {
            match tokens.next() {
                Some(lexer::Token::As) => match tokens.next() {
                    Some(lexer::Token::Ident(target)) => rule = rule.target(target),
                    Some(token) => panic!("Expected target user's name, got {:?} token", token),
                    None => panic!("Expected target user name."),
                },
                Some(lexer::Token::Cmd) => {
                    rules.push(get_cmd_and_args(rule, &mut tokens));
                    break;
                }
                Some(lexer::Token::EOL) => {
                    rules.push(rule.build());
                    break;
                }
                Some(token) => {
                    panic!("Got unexpected token {:?}", token);
                }
                None => break 'main,
            }
        }
    }
    rules
}

pub fn get_cmd_and_args<'a, T: Iterator<Item = lexer::Token<'a>>>(
    mut builder: rules::RuleBuilder<'a>,
    tokens: &mut T,
) -> Result<rules::Rule, ParserError<'a>> {
    match tokens.next() {
        Some(lexer::Token::Ident(cmd_name)) => {
            builder = builder.with_cmd(cmd_name);
            match tokens.next() {
                Some(lexer::Token::Args) => {
                    builder = builder.with_cmd(cmd_name);
                    let mut args = vec![];
                    for i in tokens {
                        if let lexer::Token::Ident(arg) = i {
                            args.push(arg);
                        } else if lexer::Token::EOL == i {
                            break;
                        }
                    }
                    builder = builder.with_cmd_args(args);
                    builder.build()
                }
                Some(lexer::Token::EOL) => builder.build(),
                Some(token) => panic!("expected args token, found token {:?}", token),
                None => builder.build(),
            }
        }
        Some(token) => Err(ParserError::ExpectedCmdNameGot(token)),
        None => Err(ParserError::ExpectedCmdNameGot(lexer::Token::EOL)),
    }
}
pub fn get_options_and_identity<'a, T: Iterator<Item = lexer::Token<'a>>>(
    mut builder: rules::RuleBuilder<'a>,
    tokens: &mut T,
) -> Result<rules::RuleBuilder<'a>, ParserError<'a>> {
    loop {
        match tokens.next() {
            Some(lexer::Token::NoPass) => builder = builder.no_pass(),
            Some(lexer::Token::Persist) => builder = builder.persist(),
            Some(lexer::Token::KeepEnv) => builder = builder.keep_env(),
            Some(lexer::Token::SetEnv(m)) => builder = builder.set_env(m),
            Some(lexer::Token::Ident(user_identity)) => {
                builder = builder.identity_name(user_identity);
                return Ok(builder);
            }
            Some(token) => return Err(ParserError::ExpectedOptionOrIdentityGot(token)),
            None => return Err(ParserError::ExpectedOptionOrIdentityGot(lexer::Token::EOL)),
        }
    }
}
