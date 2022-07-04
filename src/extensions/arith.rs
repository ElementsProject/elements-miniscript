//! Miniscript Arithmetic expressions:
//! Note that this fragment is only supported for Tapscript context
use std::str::FromStr;
use std::{cmp, error, fmt};

use elements::opcodes::all::*;
use elements::sighash::Prevouts;
use elements::{opcodes, script, Transaction};

use super::{ExtParam, ParseableExt};
use crate::expression::{FromTree, Tree};
use crate::miniscript::context::ScriptContextError;
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::limits::MAX_STANDARD_P2WSH_STACK_ITEM_SIZE;
use crate::miniscript::satisfy::{Satisfaction, Witness};
use crate::miniscript::types::extra_props::{OpLimits, TimelockInfo};
use crate::miniscript::types::{Base, Correctness, Dissat, ExtData, Input, Malleability};
use crate::{
    expression, interpreter, miniscript, script_num_size, Error, ExtTranslator, Extension,
    Satisfier, ToPublicKey, TranslateExt,
};

/// Enum representing arithmetic operations with transaction amounts.
/// Every variant of this enum pushes a single singed 64 bit BE number on stack top.
/// All of introspection opcodes explicitly assert the amount is explicit.
///
/// This will abort when
///     - Any of operations are on confidential amounts. The Null case is automatically
///       converted to explicit zero.
///     - Supplied index is out of bounds.
///     - Any of the operations overflow. Refer to tapscript opcodes spec for overflow specification
///     - In extreme cases, when recursive operations exceed 400 depth
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum ExprInner {
    /* leaf fragments/terminals */
    /// A constant i64 value
    /// Minimal push of this <i64>
    Const(i64),
    /// Explicit amount at the given input index
    /// i INPSECTINPUTVALUE <1> EQUALVERIFY
    Input(usize),
    /// Explicit amount at the given output index
    /// i INPSECTOUTPUTVALUE <1> EQUALVERIFY
    Output(usize),
    /// Explicit issuance amount at this input index
    /// i OP_INSPECTINPUTISSUANCE DROP DROP <1> EQUALVERIFY NIP NIP
    // NIP drops the second to top stack item
    // issuance stack after push where the right is stack top
    // [<inflation keys> <inflation_pref> <value> <value_pref> <entropy> <blindingnonce>]
    InputIssue(usize),
    /// Explicit re-issuance amount at this input index
    /// i OP_INSPECTINPUTISSUANCE DROP DROP DROP DROP <1> EQUALVERIFY
    // issuance stack after push where the right is stack top
    // [<inflation keys> <inflation_pref> <value> <value_pref> <entropy> <blindingnonce>]
    InputReIssue(usize),

    /* Two children */
    /// Add two Arith expressions.
    /// [X] [Y] ADD64 <1> EQUALVERIFY
    Add(Box<Expr>, Box<Expr>),
    /// Subtract (X-Y)
    /// [X] [Y] SUB64 <1> EQUALVERIFY
    Sub(Box<Expr>, Box<Expr>),
    /// Multiply two Expr expressions. (a*b)
    /// [X] [Y] MUL64 <1> EQUALVERIFY
    Mul(Box<Expr>, Box<Expr>),
    /// Divide two Expr expressions. (a//b)
    /// The division operation pushes the quotient(a//b) such that the remainder a%b
    /// (must be non-negative and less than |b|).
    /// [X] [Y] DIV64 <1> EQUALVERIFY NIP
    Div(Box<Expr>, Box<Expr>),
    /// Modulo operation (a % b)
    /// The division operation the remainder a%b (must be non-negative and less than |b|).
    /// [X] [Y] DIV64 <1> EQUALVERIFY DROP
    Mod(Box<Expr>, Box<Expr>),
    /// BitWise And (a & b)
    /// [X] [Y] AND (cannot fail)
    BitAnd(Box<Expr>, Box<Expr>),
    /// BitWise or (a | b)
    /// [X] [Y] OR (cannot fail)
    BitOr(Box<Expr>, Box<Expr>),
    /// BitWise or (a ^ b)
    /// [X] [Y] XOR (cannot fail)
    Xor(Box<Expr>, Box<Expr>),
    /* One child*/
    /// BitWise invert (!a)
    /// [X] INVERT (cannot fail)
    Invert(Box<Expr>),
    /// Negate -a
    /// [X] NEG64 <1> EQUALVERIFY
    Negate(Box<Expr>),
}

/// [`ExprInner`] with some values cached
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct Expr {
    /// The actual inner expression
    inner: ExprInner,
    /// The cached script size
    script_size: usize,
    /// depth of expression thunk/tree
    depth: usize,
}

impl Expr {
    /// Obtains the inner
    pub fn into_inner(self) -> ExprInner {
        self.inner
    }

    /// Obtains the reference to inner
    pub fn as_inner(&self) -> &ExprInner {
        &self.inner
    }

    /// Obtains the script size
    pub fn script_size(&self) -> usize {
        self.script_size
    }

    /// Obtains the depth of this expression thunk
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Creates [`Expr`] from [`ExprInner`]
    pub fn from_inner(inner: ExprInner) -> Self {
        let (script_size, depth) = match &inner {
            ExprInner::Const(_c) => (8 + 1, 0),
            ExprInner::Input(i) => (
                script_num_size(*i) + 3, // i INPSECTINPUTVALUE <1> EQUALVERIFY
                0,
            ),
            ExprInner::Output(i) => (
                script_num_size(*i) + 3, // i INPSECTOUTPUTVALUE <1> EQUALVERIFY
                0,
            ),
            ExprInner::InputIssue(i) => (
                script_num_size(*i) + 7, // i OP_INSPECTINPUTISSUANCE DROP DROP <1> EQUALVERIFY NIP NIP
                0,
            ),
            ExprInner::InputReIssue(i) => (
                script_num_size(*i) + 7, // i OP_INSPECTINPUTISSUANCE DROP DROP DROP DROP <1> EQUALVERIFY
                0,
            ),
            ExprInner::Add(x, y) => (
                x.script_size + y.script_size + 3, // [X] [Y] ADD64 <1> EQUALVERIFY
                cmp::max(x.depth, y.depth),
            ),
            ExprInner::Sub(x, y) => (
                x.script_size + y.script_size + 3, // [X] [Y] SUB64 <1> EQUALVERIFY
                cmp::max(x.depth, y.depth),
            ),
            ExprInner::Mul(x, y) => (
                x.script_size + y.script_size + 3, // [X] [Y] MUL64 <1> EQUALVERIFY
                cmp::max(x.depth, y.depth),
            ),
            ExprInner::Div(x, y) => (
                x.script_size + y.script_size + 4, // [X] [Y] DIV64 <1> EQUALVERIFY NIP
                cmp::max(x.depth, y.depth),
            ),
            ExprInner::Mod(x, y) => (
                x.script_size + y.script_size + 4, // [X] [Y] DIV64 <1> EQUALVERIFY DROP
                cmp::max(x.depth, y.depth),
            ),
            ExprInner::BitAnd(x, y) => (
                x.script_size + y.script_size + 1, // [X] [Y] AND
                cmp::max(x.depth, y.depth),
            ),
            ExprInner::BitOr(x, y) => (
                x.script_size + y.script_size + 1, // [X] [Y] OR
                cmp::max(x.depth, y.depth),
            ),
            ExprInner::Xor(x, y) => (
                x.script_size + y.script_size + 1, // [X] [Y] XOR
                cmp::max(x.depth, y.depth),
            ),
            ExprInner::Invert(x) => (
                x.script_size + 1, // [X] INVERT
                x.depth + 1,
            ),
            ExprInner::Negate(x) => (
                x.script_size + 3, // [X] NEG64 <1> EQUALVERIFY
                x.depth + 1,
            ),
        };
        Self {
            inner,
            script_size,
            depth,
        }
    }

    /// Evaluate this expression
    fn eval(
        &self,
        tx: &elements::Transaction,
        utxos: &[elements::TxOut],
    ) -> Result<i64, EvalError> {
        match &self.inner {
            ExprInner::Const(c) => Ok(*c),
            ExprInner::Input(i) => {
                if *i >= utxos.len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(*i, utxos.len()));
                }
                utxos[*i]
                    .value
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInput(*i))
            }
            ExprInner::Output(i) => {
                if *i >= tx.output.len() {
                    return Err(EvalError::OutputIndexOutOfBounds(*i, tx.output.len()));
                }
                tx.output[*i]
                    .value
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitOutput(*i))
            }
            ExprInner::InputIssue(i) => {
                if *i >= tx.input.len() {
                    return Err(EvalError::InputIndexOutOfBounds(*i, tx.input.len()));
                }
                tx.input[*i]
                    .asset_issuance
                    .amount
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInputIssuance(*i))
            }
            ExprInner::InputReIssue(i) => {
                if *i >= tx.input.len() {
                    return Err(EvalError::InputIndexOutOfBounds(*i, tx.input.len()));
                }
                tx.input[*i]
                    .asset_issuance
                    .inflation_keys
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInputReIssuance(*i))
            }
            ExprInner::Add(x, y) => {
                let x = x.eval(tx, utxos)?;
                let y = y.eval(tx, utxos)?;
                x.checked_add(y).ok_or(EvalError::AddOverflow(x, y))
            }
            ExprInner::Sub(x, y) => {
                let x = x.eval(tx, utxos)?;
                let y = y.eval(tx, utxos)?;
                x.checked_sub(y).ok_or(EvalError::SubOverflow(x, y))
            }
            ExprInner::Mul(x, y) => {
                let x = x.eval(tx, utxos)?;
                let y = y.eval(tx, utxos)?;
                x.checked_mul(y).ok_or(EvalError::MulOverflow(x, y))
            }
            ExprInner::Div(x, y) => {
                let x = x.eval(tx, utxos)?;
                let y = y.eval(tx, utxos)?;
                x.checked_div_euclid(y).ok_or(EvalError::DivOverflow(x, y))
            }
            ExprInner::Mod(x, y) => {
                let x = x.eval(tx, utxos)?;
                let y = y.eval(tx, utxos)?;
                x.checked_rem_euclid(y).ok_or(EvalError::ModOverflow(x, y))
            }
            ExprInner::BitAnd(x, y) => {
                let x = x.eval(tx, utxos)?;
                let y = y.eval(tx, utxos)?;
                Ok(x & y)
            }
            ExprInner::BitOr(x, y) => {
                let x = x.eval(tx, utxos)?;
                let y = y.eval(tx, utxos)?;
                Ok(x | y)
            }
            ExprInner::Xor(x, y) => {
                let x = x.eval(tx, utxos)?;
                let y = y.eval(tx, utxos)?;
                Ok(x ^ y)
            }
            ExprInner::Invert(x) => {
                let x = x.eval(tx, utxos)?;
                Ok(!x)
            }
            ExprInner::Negate(x) => {
                let x = x.eval(tx, utxos)?;
                x.checked_neg().ok_or(EvalError::NegOverflow(x))
            }
        }
    }

    /// Push this script to builder
    fn push_to_builder(&self, builder: script::Builder) -> script::Builder {
        match &self.inner {
            ExprInner::Const(c) => builder.push_slice(&c.to_le_bytes()),
            ExprInner::Input(i) => builder
                .push_int(*i as i64)
                .push_opcode(OP_INSPECTINPUTVALUE)
                .push_int(1)
                .push_opcode(OP_EQUALVERIFY),
            ExprInner::Output(i) => builder
                .push_int(*i as i64)
                .push_opcode(OP_INSPECTOUTPUTVALUE)
                .push_int(1)
                .push_opcode(OP_EQUALVERIFY),
            ExprInner::InputIssue(i) => builder
                .push_int(*i as i64)
                .push_opcode(OP_INSPECTINPUTISSUANCE)
                .push_opcode(OP_DROP)
                .push_opcode(OP_DROP)
                .push_int(1)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_NIP)
                .push_opcode(OP_NIP),
            ExprInner::InputReIssue(i) => builder
                .push_int(*i as i64)
                .push_opcode(OP_INSPECTINPUTISSUANCE)
                .push_opcode(OP_DROP)
                .push_opcode(OP_DROP)
                .push_opcode(OP_DROP)
                .push_opcode(OP_DROP)
                .push_int(1)
                .push_opcode(OP_EQUALVERIFY),
            ExprInner::Add(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder
                    .push_opcode(OP_ADD64)
                    .push_int(1)
                    .push_opcode(OP_EQUALVERIFY)
            }
            ExprInner::Sub(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder
                    .push_opcode(OP_SUB64)
                    .push_int(1)
                    .push_opcode(OP_EQUALVERIFY)
            }
            ExprInner::Mul(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder
                    .push_opcode(OP_MUL64)
                    .push_int(1)
                    .push_opcode(OP_EQUALVERIFY)
            }
            ExprInner::Div(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder
                    .push_opcode(OP_DIV64)
                    .push_int(1)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_NIP)
            }
            ExprInner::Mod(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder
                    .push_opcode(OP_DIV64)
                    .push_int(1)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_DROP)
            }
            ExprInner::BitAnd(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_AND)
            }
            ExprInner::BitOr(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_OR)
            }
            ExprInner::Xor(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_XOR)
            }
            ExprInner::Invert(x) => x.push_to_builder(builder).push_opcode(OP_INVERT),
            ExprInner::Negate(x) => x
                .push_to_builder(builder)
                .push_opcode(OP_NEG64)
                .push_int(1)
                .push_opcode(OP_EQUALVERIFY),
        }
    }

    /// Returns (self, start_pos) parsed reversed form tokens starting with index end_pos
    /// Expression is parsed from tokens[start:end_pos]
    fn from_tokens(tokens: &[Tk], end_pos: usize) -> Option<(Self, usize)> {
        let tks = tokens;
        let e = end_pos; // short abbreviations for succinct readable code
                         //
                         // The order of arms if else is critical to the code logic. Arms are sorted
                         // in order of the tokens required to check and early return with checked_sub?.
                         // In other words, If the tokens array is not sufficient length to parse ith
                         // arm of if statement, it tokens array cannot parse any jth arm with j > i.
                         // This significantly cleans up the code as it does not require nested else if.
                         // But care must be taken when introducing new arms.
        if let Some(Tk::Bytes8(bytes)) = tks.get(e.checked_sub(1)?) {
            let mut le_bytes = [0u8; 8];
            le_bytes.copy_from_slice(&bytes);
            let expr = Expr::from_inner(ExprInner::Const(i64::from_le_bytes(le_bytes)));
            Some((expr, e - 1))
        } else if let Some(Tk::Invert) = tks.get(e.checked_sub(1)?) {
            let (x, end_pos) = Self::from_tokens(tokens, e - 1)?;
            let expr = Expr::from_inner(ExprInner::Invert(Box::new(x)));
            Some((expr, end_pos))
        } else if let Some(Tk::And) = tks.get(e.checked_sub(1)?) {
            let (y, end_pos) = Self::from_tokens(tokens, e - 1)?;
            let (x, end_pos) = Self::from_tokens(tokens, end_pos)?;
            let expr = Expr::from_inner(ExprInner::BitAnd(Box::new(x), Box::new(y)));
            Some((expr, end_pos))
        } else if let Some(Tk::Or) = tks.get(e.checked_sub(1)?) {
            let (y, end_pos) = Self::from_tokens(tokens, e - 1)?;
            let (x, end_pos) = Self::from_tokens(tokens, end_pos)?;
            let expr = Expr::from_inner(ExprInner::BitOr(Box::new(x), Box::new(y)));
            Some((expr, end_pos))
        } else if let Some(Tk::Xor) = tks.get(e.checked_sub(1)?) {
            let (y, end_pos) = Self::from_tokens(tokens, e - 1)?;
            let (x, end_pos) = Self::from_tokens(tokens, end_pos)?;
            let expr = Expr::from_inner(ExprInner::Xor(Box::new(x), Box::new(y)));
            Some((expr, end_pos))
        } else if let Some(&[Tk::Neg64, Tk::Num(1), Tk::Equal, Tk::Verify]) =
            tks.get(e.checked_sub(4)?..e)
        {
            let (x, end_pos) = Self::from_tokens(tokens, e - 4)?;
            let expr = Expr::from_inner(ExprInner::Negate(Box::new(x)));
            Some((expr, end_pos))
        } else if let Some(&[Tk::Add64, Tk::Num(1), Tk::Equal, Tk::Verify]) =
            tks.get(e.checked_sub(4)?..e)
        {
            let (y, end_pos) = Self::from_tokens(tokens, e - 4)?;
            let (x, end_pos) = Self::from_tokens(tokens, end_pos)?;
            let expr = Expr::from_inner(ExprInner::Add(Box::new(x), Box::new(y)));
            Some((expr, end_pos))
        } else if let Some(&[Tk::Sub64, Tk::Num(1), Tk::Equal, Tk::Verify]) =
            tks.get(e.checked_sub(4)?..e)
        {
            let (y, end_pos) = Self::from_tokens(tokens, e - 4)?;
            let (x, end_pos) = Self::from_tokens(tokens, end_pos)?;
            let expr = Expr::from_inner(ExprInner::Sub(Box::new(x), Box::new(y)));
            Some((expr, end_pos))
        } else if let Some(&[Tk::Mul64, Tk::Num(1), Tk::Equal, Tk::Verify]) =
            tks.get(e.checked_sub(4)?..e)
        {
            let (y, end_pos) = Self::from_tokens(tokens, e - 4)?;
            let (x, end_pos) = Self::from_tokens(tokens, end_pos)?;
            let expr = Expr::from_inner(ExprInner::Mul(Box::new(x), Box::new(y)));
            Some((expr, end_pos))
        } else if let Some(&[Tk::Div64, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Nip]) =
            tks.get(e.checked_sub(5)?..e)
        {
            let (y, end_pos) = Self::from_tokens(tokens, e - 5)?;
            let (x, end_pos) = Self::from_tokens(tokens, end_pos)?;
            let expr = Expr::from_inner(ExprInner::Div(Box::new(x), Box::new(y)));
            Some((expr, end_pos))
        } else if let Some(&[Tk::Div64, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Drop]) =
            tks.get(e.checked_sub(5)?..e)
        {
            let (y, end_pos) = Self::from_tokens(tokens, e - 5)?;
            let (x, end_pos) = Self::from_tokens(tokens, end_pos)?;
            let expr = Expr::from_inner(ExprInner::Mod(Box::new(x), Box::new(y)));
            Some((expr, end_pos))
        } else if let Some(&[Tk::Num(i), Tk::InpValue, Tk::Num(1), Tk::Equal, Tk::Verify]) =
            tks.get(e.checked_sub(5)?..e)
        {
            Some((Expr::from_inner(ExprInner::Input(i as usize)), e - 5))
        } else if let Some(&[Tk::Num(i), Tk::OutValue, Tk::Num(1), Tk::Equal, Tk::Verify]) =
            tks.get(e.checked_sub(5)?..e)
        {
            Some((Expr::from_inner(ExprInner::Output(i as usize)), e - 5))
        } else if let Some(
            &[Tk::Num(i), Tk::InpIssue, Tk::Drop, Tk::Drop, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Nip, Tk::Nip],
        ) = tks.get(e.checked_sub(9)?..e)
        {
            Some((Expr::from_inner(ExprInner::InputIssue(i as usize)), e - 9))
        } else if let Some(
            &[Tk::Num(i), Tk::InpIssue, Tk::Drop, Tk::Drop, Tk::Drop, Tk::Drop, Tk::Num(1), Tk::Equal, Tk::Verify],
        ) = tks.get(e.checked_sub(9)?..e)
        {
            Some((Expr::from_inner(ExprInner::InputReIssue(i as usize)), e - 9))
        } else {
            None
        }
    }
}

/// Miniscript Fragment containing arith expressions
/// Expr cannot be directly used a miniscript fragment because it pushes a 64 bit
/// value on stack. Two expressions can be combined with Arith to something is
/// of Base type B to be used in miniscript expressions
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum Arith {
    /// Eq
    /// [X] [Y] EQUAL
    Eq(Expr, Expr),
    /// Le
    /// [X] [Y] LESSTHAN
    Le(Expr, Expr),
    /// Leq
    /// [X] [Y] LESSTHANOREQUAL
    Leq(Expr, Expr),
    /// Ge
    /// [X] [Y] GREATERTHAN
    Ge(Expr, Expr),
    /// Geq
    /// [X] [Y] GREATERTHANOREQUAL
    Geq(Expr, Expr),
}

impl Arith {
    /// Obtains the depth of this expression
    pub fn depth(&self) -> usize {
        match self {
            Arith::Eq(x, y)
            | Arith::Le(x, y)
            | Arith::Leq(x, y)
            | Arith::Ge(x, y)
            | Arith::Geq(x, y) => cmp::max(x.depth, y.depth),
        }
    }

    /// Obtains the script size
    pub fn script_size(&self) -> usize {
        match self {
            Arith::Eq(x, y)
            | Arith::Le(x, y)
            | Arith::Leq(x, y)
            | Arith::Ge(x, y)
            | Arith::Geq(x, y) => x.script_size + y.script_size + 1,
        }
    }

    /// Evaluate this expression with context given transaction and spent utxos
    pub fn eval(
        &self,
        tx: &elements::Transaction,
        utxos: &[elements::TxOut],
    ) -> Result<bool, EvalError> {
        let res = match self {
            Arith::Eq(x, y) => x.eval(tx, utxos)? == y.eval(tx, utxos)?,
            Arith::Le(x, y) => x.eval(tx, utxos)? < y.eval(tx, utxos)?,
            Arith::Leq(x, y) => x.eval(tx, utxos)? <= y.eval(tx, utxos)?,
            Arith::Ge(x, y) => x.eval(tx, utxos)? > y.eval(tx, utxos)?,
            Arith::Geq(x, y) => x.eval(tx, utxos)? >= y.eval(tx, utxos)?,
        };
        Ok(res)
    }

    /// Push this script to builder
    pub fn push_to_builder(&self, builder: script::Builder) -> script::Builder {
        match self {
            Arith::Eq(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_EQUAL)
            }
            Arith::Le(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_LESSTHAN64)
            }
            Arith::Leq(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_LESSTHANOREQUAL64)
            }
            Arith::Ge(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_GREATERTHAN64)
            }
            Arith::Geq(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_GREATERTHANOREQUAL64)
            }
        }
    }

    /// Parse from [elements::Script]
    /// Parsing cannot roundtrip because of associative properties, similar to and_v
    /// mul(mul(a,b),c) == mul(a,mul(b,c))
    ///
    /// Returns the tokens consumed if it is possible for the object to the parsed
    /// tokens parsing reverse starting from index ind
    fn from_tokens(tokens: &[Tk]) -> Option<(Self, usize)> {
        let last_opcode = tokens.last()?;
        let (y, pos) = Expr::from_tokens(tokens, tokens.len() - 1)?;
        let (x, pos) = Expr::from_tokens(tokens, pos)?;
        match last_opcode {
            Tk::Equal => Some((Self::Eq(x, y), pos)),
            Tk::Le64 => Some((Self::Le(x, y), pos)),
            Tk::Leq64 => Some((Self::Leq(x, y), pos)),
            Tk::Ge64 => Some((Self::Ge(x, y), pos)),
            Tk::Geq64 => Some((Self::Geq(x, y), pos)),
            _ => None,
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            ExprInner::Const(c) => write!(f, "{}", c),
            ExprInner::Input(i) => write!(f, "inp_v({})", i),
            ExprInner::Output(i) => write!(f, "out_v({})", i),
            ExprInner::InputIssue(i) => write!(f, "inp_issue_v({})", i),
            ExprInner::InputReIssue(i) => write!(f, "inp_reissue_v({})", i),
            ExprInner::Add(x, y) => write!(f, "add({},{})", x, y),
            ExprInner::Sub(x, y) => write!(f, "sub({},{})", x, y),
            ExprInner::Mul(x, y) => write!(f, "mul({},{})", x, y),
            ExprInner::Div(x, y) => write!(f, "div({},{})", x, y),
            ExprInner::Mod(x, y) => write!(f, "mod({},{})", x, y),
            ExprInner::BitAnd(x, y) => write!(f, "bitand({},{})", x, y), // Use 'bit' prefix to clearly separate from miniscript And/OR
            ExprInner::BitOr(x, y) => write!(f, "bitor({},{})", x, y),
            ExprInner::Xor(x, y) => write!(f, "bitxor({},{})", x, y),
            ExprInner::Invert(x) => write!(f, "bitinv({})", x),
            ExprInner::Negate(x) => write!(f, "neg({})", x),
        }
    }
}

impl fmt::Debug for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            ExprInner::Const(c) => write!(f, "{:?}", c),
            ExprInner::Input(i) => write!(f, "inp_v({:?})", i),
            ExprInner::Output(i) => write!(f, "out_v({:?})", i),
            ExprInner::InputIssue(i) => write!(f, "inp_issue_v({:?})", i),
            ExprInner::InputReIssue(i) => write!(f, "inp_reissue_v({:?})", i),
            ExprInner::Add(x, y) => write!(f, "add({:?},{:?})", x, y),
            ExprInner::Sub(x, y) => write!(f, "sub({:?},{:?})", x, y),
            ExprInner::Mul(x, y) => write!(f, "mul({:?},{:?})", x, y),
            ExprInner::Div(x, y) => write!(f, "div({:?},{:?})", x, y),
            ExprInner::Mod(x, y) => write!(f, "mod({:?},{:?})", x, y),
            ExprInner::BitAnd(x, y) => write!(f, "bitand({:?},{:?})", x, y), // Use 'bit' prefix to clearly separate from miniscript And/OR
            ExprInner::BitOr(x, y) => write!(f, "bitor({:?},{:?})", x, y),
            ExprInner::Xor(x, y) => write!(f, "bitxor({:?},{:?})", x, y),
            ExprInner::Invert(x) => write!(f, "bitinv({:?})", x),
            ExprInner::Negate(x) => write!(f, "neg({:?})", x),
        }
    }
}

impl FromStr for Expr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree(&top)
    }
}

impl FromTree for Box<Expr> {
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        expression::FromTree::from_tree(top).map(Box::new)
    }
}

impl FromTree for Expr {
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        fn term<F>(top: &expression::Tree<'_>, frag: F) -> Result<Expr, Error>
        where
            F: FnOnce(usize) -> ExprInner,
        {
            let index = expression::terminal(&top.args[0], expression::parse_num::<usize>)?;
            Ok(Expr::from_inner(frag(index)))
        }

        fn unary<F>(top: &expression::Tree<'_>, frag: F) -> Result<Expr, Error>
        where
            F: FnOnce(Box<Expr>) -> ExprInner,
        {
            let l: Expr = FromTree::from_tree(&top.args[0])?;
            Ok(Expr::from_inner(frag(Box::new(l))))
        }

        fn binary<F>(top: &expression::Tree<'_>, frag: F) -> Result<Expr, Error>
        where
            F: FnOnce(Box<Expr>, Box<Expr>) -> ExprInner,
        {
            let l: Expr = FromTree::from_tree(&top.args[0])?;
            let r: Expr = FromTree::from_tree(&top.args[1])?;
            Ok(Expr::from_inner(frag(Box::new(l), Box::new(r))))
        }
        match (top.name, top.args.len()) {
            ("inp_v", 1) => term(top, ExprInner::Input),
            ("out_v", 1) => term(top, ExprInner::Output),
            ("inp_issue_v", 1) => term(top, ExprInner::InputIssue),
            ("inp_reissue_v", 1) => term(top, ExprInner::InputReIssue),
            ("add", 2) => binary(top, ExprInner::Add),
            ("sub", 2) => binary(top, ExprInner::Sub),
            ("mul", 2) => binary(top, ExprInner::Mul),
            ("div", 2) => binary(top, ExprInner::Div),
            ("mod", 2) => binary(top, ExprInner::Mod),
            ("bitand", 2) => binary(top, ExprInner::BitAnd),
            ("bitor", 2) => binary(top, ExprInner::BitOr),
            ("bitxor", 2) => binary(top, ExprInner::Xor),
            ("bitinv", 1) => unary(top, ExprInner::Invert),
            ("neg", 1) => unary(top, ExprInner::Negate),
            (_num, 0) => {
                Ok(Expr {
                    inner: expression::terminal(top, expression::parse_num::<i64>)
                        .map(ExprInner::Const)?,
                    script_size: 8 + 1, // 8 byte push
                    depth: 0,
                })
            }
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Extension",
                top.name,
                top.args.len(),
            ))),
        }
    }
}

impl FromStr for Arith {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree(&top)
    }
}

impl FromTree for Box<Arith> {
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        Arith::from_tree(top).map(Box::new)
    }
}

impl FromTree for Arith {
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        match (top.name, top.args.len()) {
            // Disambiguiate with num_eq to avoid confusion with asset_eq
            ("num_eq", 2) => expression::binary(top, Arith::Eq),
            ("geq", 2) => expression::binary(top, Arith::Geq),
            ("ge", 2) => expression::binary(top, Arith::Ge),
            ("le", 2) => expression::binary(top, Arith::Le),
            ("leq", 2) => expression::binary(top, Arith::Leq),
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Extension",
                top.name,
                top.args.len(),
            ))),
        }
    }
}

impl fmt::Display for Arith {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Arith::Eq(x, y) => write!(f, "num_eq({},{})", x, y),
            Arith::Leq(x, y) => write!(f, "leq({},{})", x, y),
            Arith::Le(x, y) => write!(f, "le({},{})", x, y),
            Arith::Geq(x, y) => write!(f, "geq({},{})", x, y),
            Arith::Ge(x, y) => write!(f, "ge({},{})", x, y),
        }
    }
}

impl fmt::Debug for Arith {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Arith::Eq(x, y) => write!(f, "num_eq({:?},{:?})", x, y),
            Arith::Leq(x, y) => write!(f, "leq({:?},{:?})", x, y),
            Arith::Le(x, y) => write!(f, "le({:?},{:?})", x, y),
            Arith::Geq(x, y) => write!(f, "geq({:?},{:?})", x, y),
            Arith::Ge(x, y) => write!(f, "ge({:?},{:?})", x, y),
        }
    }
}

impl Extension for Arith {
    fn corr_prop(&self) -> Correctness {
        Correctness {
            base: Base::B,
            input: Input::Zero, // No input from stack
            dissatisfiable: true,
            unit: true,
        }
    }

    fn mall_prop(&self) -> Malleability {
        Malleability {
            dissat: Dissat::Unknown, // many dissatisfactions possible
            safe: false,             // Unsafe as a top fragment
            non_malleable: true,
        }
    }

    fn extra_prop(&self) -> ExtData {
        ExtData {
            pk_cost: self.script_size(), // 1 opcodes, 1 key push, msg, 1 msg push
            has_free_verify: false,
            stack_elem_count_sat: Some(0),
            stack_elem_count_dissat: Some(0),
            max_sat_size: Some((0, 0)),
            max_dissat_size: Some((0, 0)),
            timelock_info: TimelockInfo::default(),
            exec_stack_elem_count_sat: Some(self.depth()),
            exec_stack_elem_count_dissat: Some(self.depth()),
            ops: OpLimits {
                // Opcodes are really not relevant in tapscript as BIP342 removes all rules on them
                // So, don't make any effort in trying to compute and cache them.
                count: 0,
                sat: Some(0),
                nsat: Some(0),
            },
        }
    }

    fn script_size(&self) -> usize {
        self.script_size()
    }

    fn segwit_ctx_checks(&self) -> Result<(), miniscript::context::ScriptContextError> {
        // New opcodes only supported in taproot context
        Err(ScriptContextError::ExtensionError(
            "Arith opcodes only available in Taproot".to_string(),
        ))
    }

    fn from_name_tree(name: &str, children: &[expression::Tree<'_>]) -> Result<Self, ()> {
        let tree = Tree {
            name,
            args: children.to_vec(), // Cloning two references here, it is possible to avoid the to_vec() here,
                                     // but it requires lot of refactor.
        };
        Self::from_tree(&tree).map_err(|_| ())
    }
}

impl ParseableExt for Arith {
    fn satisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let (tx, utxos) = match (sat.lookup_tx(), sat.lookup_spent_utxos()) {
            (Some(tx), Some(utxos)) => (tx, utxos),
            _ => {
                return Satisfaction {
                    stack: Witness::Impossible,
                    has_sig: false,
                }
            }
        };
        let wit = match self.eval(tx, utxos) {
            Ok(false) => Witness::Unavailable,
            Ok(true) => Witness::empty(),
            Err(_e) => Witness::Impossible,
        };
        Satisfaction {
            stack: wit,
            has_sig: false,
        }
    }

    fn dissatisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let (tx, utxos) = match (sat.lookup_tx(), sat.lookup_spent_utxos()) {
            (Some(tx), Some(utxos)) => (tx, utxos),
            _ => {
                return Satisfaction {
                    stack: Witness::Impossible,
                    has_sig: false,
                }
            }
        };
        let wit = match self.eval(tx, utxos) {
            Ok(false) => Witness::empty(),
            Ok(true) => Witness::Unavailable,
            Err(_e) => Witness::Impossible,
        };
        Satisfaction {
            stack: wit,
            has_sig: false,
        }
    }

    fn push_to_builder(&self, builder: elements::script::Builder) -> elements::script::Builder {
        self.push_to_builder(builder)
    }

    fn from_token_iter(tokens: &mut TokenIter<'_>) -> Result<Self, ()> {
        let len = tokens.len();
        match Self::from_tokens(&tokens.as_inner_mut()) {
            Some((res, last_pos)) => {
                tokens.advance(len - last_pos).ok_or(())?;
                Ok(res)
            }
            None => Err(()),
        }
    }

    fn evaluate<'intp, 'txin>(
        &'intp self,
        stack: &mut interpreter::Stack<'txin>,
        tx: Option<&Transaction>,
        prevouts: Option<&Prevouts<'txin>>,
    ) -> Result<bool, interpreter::Error> {
        let (tx, utxos) = match (tx, prevouts) {
            (Some(tx), Some(&Prevouts::All(utxos))) => (tx, utxos),
            _ => return Err(interpreter::Error::ArithError(EvalError::TxEnvNotPresent)),
        };
        match self.eval(tx, utxos) {
            Ok(true) => {
                stack.push(interpreter::Element::Satisfied);
                Ok(true)
            }
            Ok(false) => {
                stack.push(interpreter::Element::Dissatisfied);
                Ok(false)
            }
            Err(e) => Err(interpreter::Error::ArithError(e)),
        }
    }
}

/// Evaluation Errors
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum EvalError {
    /// Transaction and utxos not supplied in interpreter
    TxEnvNotPresent,
    /// Utxo index out of bounds (index, uxtos.len())
    UtxoIndexOutOfBounds(usize, usize),
    /// Input at index must be explicit
    NonExplicitInput(usize),
    /// Output index out of bounds (index, tx.outputs.len())
    OutputIndexOutOfBounds(usize, usize),
    /// Output at index must be explicit
    NonExplicitOutput(usize),
    /// Output index out of bounds (index, tx.inputs.len())
    InputIndexOutOfBounds(usize, usize),
    /// Input issuance at index must be explicit
    NonExplicitInputIssuance(usize),
    /// Input reissuance at index must be explicit
    NonExplicitInputReIssuance(usize),
    /// Addition overflow
    AddOverflow(i64, i64),
    /// Addition overflow
    SubOverflow(i64, i64),
    /// Sub overflow
    MulOverflow(i64, i64),
    /// Mul overflow
    DivOverflow(i64, i64),
    /// Mod overflow
    ModOverflow(i64, i64),
    /// Neg overflow
    NegOverflow(i64),
}

impl error::Error for EvalError {}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalError::UtxoIndexOutOfBounds(i, len) => {
                write!(f, "Utxo index {} out of bounds {}", i, len)
            }
            EvalError::NonExplicitInput(i) => write!(f, "Non explicit input {}", i),
            EvalError::OutputIndexOutOfBounds(i, len) => {
                write!(f, "Output index {} out of bounds {}", i, len)
            }
            EvalError::NonExplicitOutput(i) => {
                write!(f, "Non explicit output amount at index {}", i)
            }
            EvalError::InputIndexOutOfBounds(i, len) => {
                write!(f, "Input index {} out of bounds {}", i, len)
            }
            EvalError::NonExplicitInputIssuance(i) => {
                write!(f, "Non explicit input issuance amount at index {}", i)
            }
            EvalError::NonExplicitInputReIssuance(i) => {
                write!(f, "Non explicit input reissuance amount at index {}", i)
            }
            EvalError::AddOverflow(x, y) => write!(f, "Add overflow {} {}", x, y),
            EvalError::SubOverflow(x, y) => write!(f, "Sub overflow {} {}", x, y),
            EvalError::MulOverflow(x, y) => write!(f, "Mul overflow {} {}", x, y),
            EvalError::DivOverflow(x, y) => write!(f, "Div overflow {} {}", x, y),
            EvalError::ModOverflow(x, y) => write!(f, "Mod overflow {} {}", x, y),
            EvalError::NegOverflow(x) => write!(f, "Neg overflow {}", x),
            EvalError::TxEnvNotPresent => write!(
                f,
                "Transaction must be supplied to extension to arithmetic evaluation"
            ),
        }
    }
}

impl<PExt, QExt, PArg, QArg> TranslateExt<PExt, QExt, PArg, QArg> for Arith
where
    PExt: Extension,
    QExt: Extension,
    PArg: ExtParam,
    QArg: ExtParam,
{
    type Output = Arith;

    fn translate_ext<T, E>(&self, _t: &mut T) -> Result<Self::Output, E>
    where
        T: ExtTranslator<PArg, QArg, E>,
    {
        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::XOnlyPublicKey;

    use super::*;
    use crate::test_utils::{StrExtTransalator, StrXOnlyKeyTranslator};
    use crate::{Miniscript, Segwitv0, Tap, TranslatePk};

    #[test]
    fn arith_parse() {
        // This does not test the evaluation
        _arith_parse("num_eq(8,8)");
        _arith_parse("ge(9223372036854775807,9223372036854775806)"); // 2**63-1

        // negatives and comparisons
        _arith_parse("num_eq(-8,-8)"); // negative nums
        _arith_parse("ge(-8,-9)");
        _arith_parse("geq(-8,-8)");
        _arith_parse("leq(-8,-7)");
        _arith_parse("le(-8,-7)");

        // test terminals parsing
        _arith_parse("num_eq(inp_v(0),100)");
        _arith_parse("num_eq(out_v(0),100)");
        _arith_parse("num_eq(inp_issue_v(0),100)");
        _arith_parse("num_eq(inp_reissue_v(0),100)");
        _arith_parse("num_eq(inp_v(0),out_v(0))");
        _arith_parse("num_eq(inp_issue_v(1),inp_reissue_v(1))");

        // test combinator
        _arith_parse("num_eq(add(4,3),mul(1,7))");
        _arith_parse("num_eq(sub(3,3),div(0,9))");
        _arith_parse("num_eq(mod(9,3),0)");
        _arith_parse("num_eq(bitand(0,134),0)");
        _arith_parse("num_eq(bitor(1,3),3)");
        _arith_parse("num_eq(bitxor(1,3),2)");
        _arith_parse("num_eq(bitinv(0),-9223372036854775808)");
        _arith_parse("num_eq(neg(1),-1)");

        // test some misc combinations with other miniscript fragments
        _arith_parse("and_v(v:pk(K),ge(8,7))");
        _arith_parse("and_v(v:pk(K),num_eq(mul(inp_v(0),out_v(1)),sub(add(3,inp_issue_v(1)),-9)))");
    }

    fn _arith_parse(s: &str) {
        type MsExtStr = Miniscript<String, Tap, Arith>;
        type MsExt = Miniscript<XOnlyPublicKey, Tap, Arith>;
        type MsExtSegwitv0 = Miniscript<String, Segwitv0, Arith>;

        // Make sure that parsing this errors in segwit context
        assert!(MsExtSegwitv0::from_str_insane(s).is_err());

        let ms = MsExtStr::from_str_insane(s).unwrap();
        // test string rtt
        assert_eq!(ms.to_string(), s);
        let mut t = StrXOnlyKeyTranslator::default();
        let ms = ms.translate_pk(&mut t).unwrap();
        // script rtt
        assert_eq!(ms, MsExt::parse_insane(&ms.encode()).unwrap());
    }
}
