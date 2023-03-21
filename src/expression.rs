// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! # Function-like Expression Language
//!

use std::fmt;
use std::str::FromStr;

use crate::{errstr, Error, MAX_RECURSION_DEPTH};

#[derive(Debug, Clone)]
/// A token of the form `x(...)` or `x`
pub struct Tree<'a> {
    /// The name `x`
    pub name: &'a str,
    /// The comma-separated contents of the `(...)`, if any
    pub args: Vec<Tree<'a>>,
}
// or_b(pk(A),pk(B))
//
// A = musig(musig(B,C),D,E)
// or_b()
// pk(A), pk(B)

/// A trait for extracting a structure from a Tree representation in token form
pub trait FromTree: Sized {
    /// Extract a structure from Tree representation
    fn from_tree(top: &Tree<'_>) -> Result<Self, Error>;
}

impl<'a> fmt::Display for Tree<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}", self.name)?;
        for arg in &self.args {
            write!(f, ",{}", arg)?;
        }
        write!(f, ")")
    }
}

enum Found {
    Nothing,
    LBracket(usize), // Either a left ( or {
    Comma(usize),
    RBracket(usize), // Either a right ) or }
}

fn next_expr(sl: &str, delim: char) -> Found {
    // Decide whether we are parsing a key or not.
    // When parsing a key ignore all the '(' and ')'.
    // We keep count of lparan whenever we are inside a key context
    // We exit the context whenever we find the corresponding ')'
    // in which we entered the context. This allows to special case
    // parse the '(' ')' inside key expressions.(slip77 and musig).
    let mut key_ctx = false;
    let mut key_lparan_count = 0;
    let mut found = Found::Nothing;
    if delim == '(' {
        for (n, ch) in sl.char_indices() {
            match ch {
                '(' => {
                    // already inside a key context
                    if key_ctx {
                        key_lparan_count += 1;
                    } else if &sl[..n] == "slip77" || &sl[..n] == "musig" {
                        key_lparan_count = 1;
                        key_ctx = true;
                    } else {
                        found = Found::LBracket(n);
                        break;
                    }
                }
                ',' => {
                    if !key_ctx {
                        found = Found::Comma(n);
                        break;
                    }
                }
                ')' => {
                    if key_ctx {
                        key_lparan_count -= 1;
                        if key_lparan_count == 0 {
                            key_ctx = false;
                        }
                    } else {
                        found = Found::RBracket(n);
                        break;
                    }
                }
                _ => {}
            }
        }
    } else if delim == '{' {
        let mut new_count = 0;
        for (n, ch) in sl.char_indices() {
            match ch {
                '{' => {
                    found = Found::LBracket(n);
                    break;
                }
                '(' => {
                    new_count += 1;
                }
                ',' => {
                    if new_count == 0 {
                        found = Found::Comma(n);
                        break;
                    }
                }
                ')' => {
                    new_count -= 1;
                }
                '}' => {
                    found = Found::RBracket(n);
                    break;
                }
                _ => {}
            }
        }
    } else {
        unreachable!("{}", "Internal: delimiters in parsing must be '(' or '{'");
    }
    found
}

// Get the corresponding delim
fn closing_delim(delim: char) -> char {
    match delim {
        '(' => ')',
        '{' => '}',
        _ => unreachable!("Unknown delimiter"),
    }
}

impl<'a> Tree<'a> {
    /// Parse an expression with round brackets
    pub fn from_slice(sl: &'a str) -> Result<(Tree<'a>, &'a str), Error> {
        // Parsing TapTree or just miniscript
        Self::from_slice_delim(sl, 0u32, '(')
    }

    pub(crate) fn from_slice_delim(
        mut sl: &'a str,
        depth: u32,
        delim: char,
    ) -> Result<(Tree<'a>, &'a str), Error> {
        if depth >= MAX_RECURSION_DEPTH {
            return Err(Error::MaxRecursiveDepthExceeded);
        }

        match next_expr(sl, delim) {
            // String-ending terminal
            Found::Nothing => Ok((
                Tree {
                    name: sl,
                    args: vec![],
                },
                "",
            )),
            // Terminal
            Found::Comma(n) | Found::RBracket(n) => Ok((
                Tree {
                    name: &sl[..n],
                    args: vec![],
                },
                &sl[n..],
            )),
            // Function call
            Found::LBracket(n) => {
                let mut ret = Tree {
                    name: &sl[..n],
                    args: vec![],
                };

                sl = &sl[n + 1..];
                loop {
                    let (arg, new_sl) = Tree::from_slice_delim(sl, depth + 1, delim)?;
                    ret.args.push(arg);

                    if new_sl.is_empty() {
                        return Err(Error::ExpectedChar(closing_delim(delim)));
                    }

                    sl = &new_sl[1..];
                    match new_sl.as_bytes()[0] {
                        b',' => {}
                        last_byte => {
                            if last_byte == closing_delim(delim) as u8 {
                                break;
                            } else {
                                return Err(Error::ExpectedChar(closing_delim(delim)));
                            }
                        }
                    }
                }
                Ok((ret, sl))
            }
        }
    }

    /// Parses a tree from a string
    pub fn from_str(s: &'a str) -> Result<Tree<'a>, Error> {
        // Filter out non-ASCII because we byte-index strings all over the
        // place and Rust gets very upsbt when you splinch a string.
        for ch in s.bytes() {
            if !ch.is_ascii() {
                return Err(Error::Unprintable(ch));
            }
        }

        let (top, rem) = Tree::from_slice(s)?;
        if rem.is_empty() {
            Ok(top)
        } else {
            Err(errstr(rem))
        }
    }
}

/// Parse a string as a u32, for timelocks or thresholds
pub fn parse_num<T: FromStr>(s: &str) -> Result<T, Error> {
    if s.len() > 1 {
        let ch = s.chars().next().unwrap();
        let ch = if ch == '-' {
            s.chars().nth(1).ok_or(Error::Unexpected(
                "Negative number must follow dash sign".to_string(),
            ))?
        } else {
            ch
        };
        if !('1'..='9').contains(&ch) {
            return Err(Error::Unexpected(
                "Number must start with a digit 1-9".to_string(),
            ));
        }
    }
    T::from_str(s).map_err(|_| errstr(s))
}

/// Attempts to parse a terminal expression
pub fn terminal<T, F, Err>(term: &Tree<'_>, convert: F) -> Result<T, Error>
where
    F: FnOnce(&str) -> Result<T, Err>,
    Err: ToString,
{
    if term.args.is_empty() {
        convert(term.name).map_err(|e| Error::Unexpected(e.to_string()))
    } else {
        Err(errstr(term.name))
    }
}

/// Attempts to parse an expression with exactly one child
pub fn unary<L, T, F>(term: &Tree<'_>, convert: F) -> Result<T, Error>
where
    L: FromTree,
    F: FnOnce(L) -> T,
{
    if term.args.len() == 1 {
        let left = FromTree::from_tree(&term.args[0])?;
        Ok(convert(left))
    } else {
        Err(errstr(term.name))
    }
}

/// Attempts to parse an expression with exactly two children
pub fn binary<L, R, T, F>(term: &Tree<'_>, convert: F) -> Result<T, Error>
where
    L: FromTree,
    R: FromTree,
    F: FnOnce(L, R) -> T,
{
    if term.args.len() == 2 {
        let left = FromTree::from_tree(&term.args[0])?;
        let right = FromTree::from_tree(&term.args[1])?;
        Ok(convert(left, right))
    } else {
        Err(errstr(term.name))
    }
}

#[cfg(test)]
mod tests {

    use super::parse_num;

    #[test]
    fn test_parse_num() {
        assert!(parse_num::<u32>("0").is_ok());
        assert!(parse_num::<u32>("00").is_err());
        assert!(parse_num::<u32>("0000").is_err());
        assert!(parse_num::<u32>("06").is_err());
        assert!(parse_num::<u32>("+6").is_err());
        assert!(parse_num::<u32>("-6").is_err());
    }
}
