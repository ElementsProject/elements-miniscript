//! Miniscript Index expressions:
//! Note that these fragment is only supported for Tapscript context
//! Refer to the spec for additional details.
use std::fmt;

use elements::opcodes::{self};
use elements::script;

use super::{EvalError, TxEnv};
use crate::expression::{FromTree, Tree};
use crate::miniscript::lex::Token as Tk;
use crate::{expression, script_num_size, Error};

/// Enum representing operations with input/output indexes.
/// Pushes a single CScriptNum on stack top. This is used to represent the index of the input or output.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum IdxExpr {
    /* leaf fragments/terminals */
    /// A constant
    /// `<i>` as CScriptNum
    Const(usize),
    /// Current Input index
    CurrIdx,
    /// Add two IdxExpr
    /// `[X] [Y] ADD`
    Add(Box<IdxExpr>, Box<IdxExpr>),
    /// Subtract two IdxExpr
    /// `[X] [Y] SUB`
    Sub(Box<IdxExpr>, Box<IdxExpr>),
    /// Multiply two IdxExpr
    /// `[X] SCIPTNUMTOLE64 [Y] SCIPTNUMTOLE64 MUL64 <1> EQUALVERIFY LE64TOSCIPTNUM`
    Mul(Box<IdxExpr>, Box<IdxExpr>),
    /// Divide two IdxExpr (integer division)
    /// `[X] SCIPTNUMTOLE64 [Y] SCIPTNUMTOLE64 DIV64 <1> EQUALVERIFY NIP LE64TOSCIPTNUM`
    Div(Box<IdxExpr>, Box<IdxExpr>),
}

impl IdxExpr {
    /// Returns the script size of this [`IdxExpr`].
    pub fn script_size(&self) -> usize {
        match self {
            IdxExpr::Const(i) => script_num_size(*i),
            IdxExpr::CurrIdx => 1,
            IdxExpr::Add(x, y) => x.script_size() + y.script_size() + 1,
            IdxExpr::Sub(x, y) => x.script_size() + y.script_size() + 1,
            IdxExpr::Mul(x, y) => x.script_size() + y.script_size() + 6,
            IdxExpr::Div(x, y) => x.script_size() + y.script_size() + 7,
        }
    }
}

impl fmt::Display for IdxExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdxExpr::Const(i) => write!(f, "{}", i),
            IdxExpr::CurrIdx => write!(f, "curr_idx"),
            IdxExpr::Add(x, y) => write!(f, "idx_add({},{})", x, y),
            IdxExpr::Sub(x, y) => write!(f, "idx_sub({},{})", x, y),
            IdxExpr::Mul(x, y) => write!(f, "idx_mul({},{})", x, y),
            IdxExpr::Div(x, y) => write!(f, "idx_div({},{})", x, y),
        }
    }
}

impl fmt::Debug for IdxExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdxExpr::Const(i) => write!(f, "{:?}", i),
            IdxExpr::CurrIdx => write!(f, "curr_idx"),
            IdxExpr::Add(x, y) => write!(f, "idx_add({:?},{:?})", x, y),
            IdxExpr::Sub(x, y) => write!(f, "idx_sub({:?},{:?})", x, y),
            IdxExpr::Mul(x, y) => write!(f, "idx_mul({:?},{:?})", x, y),
            IdxExpr::Div(x, y) => write!(f, "idx_div({:?},{:?})", x, y),
        }
    }
}

impl FromTree for IdxExpr {
    fn from_tree(top: &Tree<'_>) -> Result<Self, Error> {
        match (top.name, top.args.len()) {
            ("curr_idx", 0) => Ok(IdxExpr::CurrIdx),
            ("idx_add", 2) => Ok(IdxExpr::Add(
                Box::new(Self::from_tree(&top.args[0])?),
                Box::new(Self::from_tree(&top.args[1])?),
            )),
            ("idx_sub", 2) => Ok(IdxExpr::Sub(
                Box::new(Self::from_tree(&top.args[0])?),
                Box::new(Self::from_tree(&top.args[1])?),
            )),
            ("idx_mul", 2) => Ok(IdxExpr::Mul(
                Box::new(Self::from_tree(&top.args[0])?),
                Box::new(Self::from_tree(&top.args[1])?),
            )),
            ("idx_div", 2) => Ok(IdxExpr::Div(
                Box::new(Self::from_tree(&top.args[0])?),
                Box::new(Self::from_tree(&top.args[1])?),
            )),
            (_num, 0) => {
                expression::terminal(top, expression::parse_num::<usize>).map(IdxExpr::Const)
            }
            _ => Err(Error::Unexpected(format!("Unexpected token: {:?}", top))),
        }
    }
}

impl IdxExpr {
    /// Push this script to builder
    /// Panics when trying to push a Null asset. This never occur in honest use-cases
    /// as there is no such thing as Null asset
    pub fn push_to_builder(&self, builder: script::Builder) -> script::Builder {
        use opcodes::all::*;
        match self {
            IdxExpr::Const(i) => builder.push_int(*i as i64),
            IdxExpr::CurrIdx => builder.push_opcode(OP_PUSHCURRENTINPUTINDEX),
            IdxExpr::Add(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_ADD)
            }
            IdxExpr::Sub(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_SUB)
            }
            IdxExpr::Mul(x, y) => {
                let builder = x.push_to_builder(builder).push_opcode(OP_SCRIPTNUMTOLE64);
                let builder = y.push_to_builder(builder).push_opcode(OP_SCRIPTNUMTOLE64);
                builder
                    .push_opcode(OP_MUL64)
                    .push_int(1)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_LE64TOSCRIPTNUM)
            }
            IdxExpr::Div(x, y) => {
                let builder = x.push_to_builder(builder).push_opcode(OP_SCRIPTNUMTOLE64);
                let builder = y.push_to_builder(builder).push_opcode(OP_SCRIPTNUMTOLE64);
                builder
                    .push_opcode(OP_DIV64)
                    .push_int(1)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_NIP)
                    .push_opcode(OP_LE64TOSCRIPTNUM)
            }
        }
    }

    /// Evaluate this expression
    pub fn eval(&self, env: &TxEnv) -> Result<usize, EvalError> {
        match self {
            IdxExpr::Const(i) => Ok(*i),
            IdxExpr::CurrIdx => Ok(env.idx),
            IdxExpr::Add(x, y) => Ok(x.eval(env)? + y.eval(env)?),
            IdxExpr::Sub(x, y) => Ok(x.eval(env)? - y.eval(env)?),
            IdxExpr::Mul(x, y) => Ok(x.eval(env)? * y.eval(env)?),
            IdxExpr::Div(x, y) => Ok(x.eval(env)? / y.eval(env)?),
        }
    }

    /// Returns (self, start_pos) parsed reversed form tokens starting with index end_pos
    /// Expression is parsed from tokens `[start:end_pos]`
    #[rustfmt::skip]
    pub fn from_tokens(tokens: &[Tk], end_pos: usize) -> Option<(Self, usize)> {
        let tks = tokens;
        let e = end_pos; // short abbreviations for succinct readable code
        if let Some(&[Tk::Num(i)]) = tks.get(e.checked_sub(1)?..e) {
            Some((IdxExpr::Const(i as usize), e - 1))
        } else if let Some(&[Tk::CurrInp]) = tks.get(e.checked_sub(1)?..e) {
            Some((IdxExpr::CurrIdx, e - 1))
        } else if let Some(&[Tk::Add]) = tks.get(e.checked_sub(1)?..e) {
            let (y, e) = IdxExpr::from_tokens(tks, e - 1)?;
            let (x, e) = IdxExpr::from_tokens(tks, e)?;
            Some((IdxExpr::Add(Box::new(x), Box::new(y)), e))
        } else if let Some(&[Tk::Sub]) = tks.get(e.checked_sub(1)?..e) {
            let (y, e) = IdxExpr::from_tokens(tks, e - 1)?;
            let (x, e) = IdxExpr::from_tokens(tks, e)?;
            Some((IdxExpr::Sub(Box::new(x), Box::new(y)), e))
        } else if let Some(&[Tk::ScriptNumToLe64, Tk::Mul64, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Le64ToScriptNum]) = tks.get(e.checked_sub(6)?..e) {
            let (y, e) = IdxExpr::from_tokens(tks, e - 6)?;
            if let Some(&[Tk::ScriptNumToLe64]) = tks.get(e.checked_sub(1)?..e) {
                let (x, e) = IdxExpr::from_tokens(tks, e - 1)?;
                Some((IdxExpr::Mul(Box::new(x), Box::new(y)), e))
            } else {
                None
            }
        } else if let Some(&[Tk::ScriptNumToLe64, Tk::Div64, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Nip, Tk::Le64ToScriptNum]) = tks.get(e.checked_sub(7)?..e) {
            let (y, e) = IdxExpr::from_tokens(tks, e - 7)?;
            if let Some(&[Tk::ScriptNumToLe64]) = tks.get(e.checked_sub(1)?..e) {
                let (x, e) = IdxExpr::from_tokens(tks, e - 1)?;
                Some((IdxExpr::Div(Box::new(x), Box::new(y)), e))
            } else {
                None
            }
        } else {
            None
        }
    }
}
