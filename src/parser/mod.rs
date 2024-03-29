//! This module is dedicated to parsinng rules by passing passed contents to the lexer - and
//! parsing the tokens. Dedicated to turning some config for doas to a series of rules (enum)
//! digestible by your program.

pub mod parser_err;
use parser_err::ParserError;

pub mod rules;
use rules::Rule;

#[cfg(test)]
mod tests;

mod lexer;

///Parse the rules in contents.
#[allow(dead_code)]
pub fn parse_rules(contents: &str) -> Vec<Result<Rule, ParserError<'_>>> {
    let tokens = lexer::get_tokens(contents).unwrap_or_else(|e| panic!("Got err {:?}", e));
    let mut tokens = tokens.into_iter().peekable();
    let mut rules = vec![];
    'main: loop {
        let rule = rules::RuleBuilder::new();
        let rule = match tokens.next() {
            Some(lexer::Token::Permit) => rule.permit(),
            Some(lexer::Token::Deny) => rule.deny(),
            Some(lexer::Token::Eol) => continue,
            Some(token) => {
                rules.push(Err(ParserError::ExpectedRuleGot(token)));
                loop {
                    let next_item = tokens.peek();
                    if next_item == Some(&lexer::Token::Permit)
                        || next_item == Some(&lexer::Token::Deny)
                        || next_item == None
                    {
                        continue 'main;
                    } else {
                        tokens.next();
                    }
                }
            }
            None => break 'main,
        };

        let mut rule = match get_options_and_identity(rule, &mut tokens) {
            Ok(rule) => rule,
            Err(e) => {
                rules.push(Err(e));
                go_until_next_rule(&mut tokens);
                continue 'main;
            }
        };

        loop {
            match tokens.next() {
                Some(lexer::Token::As) => match tokens.next() {
                    Some(lexer::Token::Ident(target)) => rule = rule.target(target),
                    Some(token) => {
                        rules.push(Err(ParserError::ExpectedTargetGot(token)));
                        continue 'main;
                    }
                    None => rules.push(Err(ParserError::ExpectedTargetGot(lexer::Token::Eol))),
                },
                Some(lexer::Token::Cmd) => {
                    rules.push(get_cmd_and_args(rule, &mut tokens));
                    break;
                }
                Some(lexer::Token::Eol) => {
                    rules.push(rule.build());
                    break;
                }
                Some(token) => {
                    rules.push(Err(ParserError::ExpectedCmdPathGot(token)));
                    go_until_next_rule(&mut tokens);
                    continue 'main;
                }
                None => break 'main,
            }
        }
    }
    rules
}

///This gets commands and args inside of the iterator. The last part of a rule.
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
                        } else if lexer::Token::Eol == i {
                            break;
                        }
                    }
                    builder = builder.with_cmd_args(args);
                    builder.build()
                }
                Some(lexer::Token::Eol) => builder.build(),
                Some(token) => panic!("expected args token, found token {:?}", token),
                None => builder.build(),
            }
        }
        Some(token) => Err(ParserError::ExpectedCmdNameGot(token)),
        None => Err(ParserError::ExpectedCmdNameGot(lexer::Token::Eol)),
    }
}
///This takes a iterator, and until it finds a identifier it keeps applying
///the given options to the rule builder.
///Once it finds the identifier, set that as the identity_name and return.
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
            None => return Err(ParserError::ExpectedOptionOrIdentityGot(lexer::Token::Eol)),
        }
    }
}

///Moves forward the iterator until the next rule is encountered. (Permit | Deny is found.)
fn go_until_next_rule<'a, T: Iterator<Item = lexer::Token<'a>>>(
    tokens: &mut std::iter::Peekable<T>,
) {
    loop {
        let next_item = tokens.peek();
        if next_item == Some(&lexer::Token::Permit)
            || next_item == Some(&lexer::Token::Deny)
            || next_item == None
        {
            return;
        } else {
            tokens.next();
        }
    }
}
