//! Miniscript Arithmetic expressions:
//! Note that this fragment is only supported for Tapscript context
use std::convert::TryInto;
use std::str::FromStr;
use std::{cmp, error, fmt};

use bitcoin::key::XOnlyPublicKey;
use bitcoin_miniscript::MiniscriptKey;
use elements::opcodes::all::*;
use elements::sighash::Prevouts;
use elements::{opcodes, script, secp256k1_zkp as secp256k1, SchnorrSig, Transaction};

use super::param::{ExtParamTranslator, TranslateExtParam};
use super::{CovExtArgs, CsfsKey, ExtParam, FromTokenIterError, IdxExpr, ParseableExt, TxEnv};
use crate::expression::{FromTree, Tree};
use crate::extensions::check_sig_price_oracle_1;
use crate::miniscript::context::ScriptContextError;
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::limits::MAX_STANDARD_P2WSH_STACK_ITEM_SIZE;
use crate::miniscript::satisfy::{Satisfaction, Witness};
use crate::miniscript::types::extra_props::{OpLimits, TimelockInfo};
use crate::miniscript::types::{Base, Correctness, Dissat, ExtData, Input, Malleability};
use crate::{
    expression, interpreter, miniscript, script_num_size, Error, Extension, Satisfier, ToPublicKey,
    TranslateExt,
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
pub enum ExprInner<T: ExtParam> {
    /* leaf fragments/terminals */
    /// A constant i64 value
    /// Minimal push of this `<i64>`
    Const(i64),
    /// Value under the current executing input
    /// `INSPECTCURRENTINPUTINDEX INPSECTINPUTVALUE <1> EQUALVERIFY`
    CurrInputIdx,
    /// Explicit amount at the given input index
    /// `i INPSECTINPUTVALUE <1> EQUALVERIFY`
    Input(IdxExpr),
    /// Explicit amount at the given output index
    /// `i INPSECTOUTPUTVALUE <1> EQUALVERIFY`
    Output(IdxExpr),
    /// Explicit issuance amount at this input index
    /// `i OP_INSPECTINPUTISSUANCE DROP DROP <1> EQUALVERIFY NIP NIP`
    // NIP drops the second to top stack item
    // issuance stack after push where the right is stack top
    // [<inflation keys> <inflation_pref> <value> <value_pref> <entropy> <blindingnonce>]
    InputIssue(IdxExpr),
    /// Explicit re-issuance amount at this input index
    /// `i OP_INSPECTINPUTISSUANCE DROP DROP DROP DROP <1> EQUALVERIFY`
    // issuance stack after push where the right is stack top
    // [<inflation keys> <inflation_pref> <value> <value_pref> <entropy> <blindingnonce>]
    InputReIssue(IdxExpr),

    /* Two children */
    /// Add two Arith expressions.
    /// `[X] [Y] ADD64 <1> EQUALVERIFY`
    Add(Box<Expr<T>>, Box<Expr<T>>),
    /// Subtract (X-Y)
    /// `[X] [Y] SUB64 <1> EQUALVERIFY`
    Sub(Box<Expr<T>>, Box<Expr<T>>),
    /// Multiply two Expr expressions. (a*b)
    /// `[X] [Y] MUL64 <1> EQUALVERIFY`
    Mul(Box<Expr<T>>, Box<Expr<T>>),
    /// Divide two Expr expressions. (a//b)
    /// The division operation pushes the quotient(a//b) such that the remainder a%b
    /// (must be non-negative and less than |b|).
    /// `[X] [Y] DIV64 <1> EQUALVERIFY NIP`
    Div(Box<Expr<T>>, Box<Expr<T>>),
    /// Modulo operation (a % b)
    /// The division operation the remainder a%b (must be non-negative and less than |b|).
    /// `[X] [Y] DIV64 <1> EQUALVERIFY DROP`
    Mod(Box<Expr<T>>, Box<Expr<T>>),
    /// BitWise And (a & b)
    /// `[X] [Y] AND` (cannot fail)
    BitAnd(Box<Expr<T>>, Box<Expr<T>>),
    /// BitWise or (a | b)
    /// `[X] [Y] OR` (cannot fail)
    BitOr(Box<Expr<T>>, Box<Expr<T>>),
    /// BitWise or (a ^ b)
    /// `[X] [Y] XOR` (cannot fail)
    Xor(Box<Expr<T>>, Box<Expr<T>>),
    /* One child*/
    /// BitWise invert (!a)
    /// `[X] INVERT` (cannot fail)
    Invert(Box<Expr<T>>),
    /// Negate -a
    /// `[X] NEG64 <1> EQUALVERIFY`
    Negate(Box<Expr<T>>),

    /// Push the price as LE64 signed from oracle.
    /// `2DUP TOALTSTACK <T> OP_GREATERTHANEQ VERIFY CAT SHA256 <K> CHECKSIGFROMSTACKVERIFY OP_FROMATLSTACK`
    /// The fragment checks that the input timestamp is less than time at which the price was signed with
    /// the given oracle key. The asset of which price is being checked is implicitly decided by the
    /// public key
    PriceOracle1(T, u64),
    /// Same as [`Self::PriceOracle1`] but wrapped in an `TOALTSTACK` and `FROMALTSTACK` and SWAP
    /// `TOALTSTACK 2DUP TOALTSTACK <T> OP_GREATERTHANEQ VERIFY CAT SHA256 <K> CHECKSIGFROMSTACKVERIFY OP_FROMATLSTACK FROMALTSTACK SWAP`
    /// We need to swap at the end to make sure that the price pushed by this fragment is on top of the stack
    /// In regular miniscript, all operations are commutative, but here some operations like sub and div are not and hence
    /// we need to maintain the exact order of operations.
    PriceOracle1W(T, u64),
}

/// An iterator over [`ExprInner`] that yields the terminal nodes
/// in the expression tree.
#[derive(Debug, Clone)]
pub struct ExprIter<'a, T: ExtParam> {
    stack: Vec<&'a ExprInner<T>>,
}

impl<'a, T: ExtParam> Iterator for ExprIter<'a, T> {
    type Item = &'a ExprInner<T>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(expr) = self.stack.pop() {
            match expr {
                ExprInner::Const(_)
                | ExprInner::CurrInputIdx
                | ExprInner::Input(_)
                | ExprInner::Output(_)
                | ExprInner::InputIssue(_)
                | ExprInner::InputReIssue(_)
                | ExprInner::PriceOracle1(_, _)
                | ExprInner::PriceOracle1W(_, _) => return Some(expr),
                ExprInner::Add(a, b)
                | ExprInner::Sub(a, b)
                | ExprInner::Mul(a, b)
                | ExprInner::Div(a, b)
                | ExprInner::Mod(a, b)
                | ExprInner::BitAnd(a, b)
                | ExprInner::BitOr(a, b)
                | ExprInner::Xor(a, b) => {
                    self.stack.push(b.as_inner());
                    self.stack.push(a.as_inner());
                }
                ExprInner::Invert(a) | ExprInner::Negate(a) => {
                    self.stack.push(a.as_inner());
                }
            }
        }
        None
    }
}

/// [`ExprInner`] with some values cached
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct Expr<T: ExtParam> {
    /// The actual inner expression
    inner: ExprInner<T>,
    /// The cached script size
    script_size: usize,
    /// depth of expression thunk/tree
    depth: usize,
}

impl<T: ExtParam> Expr<T> {
    /// Obtains the inner
    pub fn into_inner(self) -> ExprInner<T> {
        self.inner
    }

    /// Obtains the reference to inner
    pub fn as_inner(&self) -> &ExprInner<T> {
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
    pub fn from_inner(inner: ExprInner<T>) -> Self {
        let (script_size, depth) = match &inner {
            ExprInner::Const(_c) => (8 + 1, 0),
            ExprInner::CurrInputIdx => (4, 0), // INSPECTCURRENTINPUTINDEX INPSECTINPUTVALUE <1> EQUALVERIFY
            ExprInner::Input(i) => (
                i.script_size() + 3, // i INPSECTINPUTVALUE <1> EQUALVERIFY
                0,
            ),
            ExprInner::Output(i) => (
                i.script_size() + 3, // i INPSECTOUTPUTVALUE <1> EQUALVERIFY
                0,
            ),
            ExprInner::InputIssue(i) => (
                i.script_size() + 7, // i OP_INSPECTINPUTISSUANCE DROP DROP <1> EQUALVERIFY NIP NIP
                0,
            ),
            ExprInner::InputReIssue(i) => (
                i.script_size() + 7, // i OP_INSPECTINPUTISSUANCE DROP DROP DROP DROP <1> EQUALVERIFY
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
            ExprInner::PriceOracle1(_pk, _time) => (
                (32 + 1) // 32 byte key + push
                + (8 + 1) // 8 byte time push
                + 8, // opcodes,
                0,
            ),
            ExprInner::PriceOracle1W(_pk, _time) => (
                (32 + 1) // 32 byte key + push
                + (8 + 1) // 8 byte time push
                + 11, // opcodes,
                0,
            ),
        };
        Self {
            inner,
            script_size,
            depth,
        }
    }

    /// Obtains an iterator over terminals nodes
    pub fn iter_terminals(&self) -> impl Iterator<Item = &ExprInner<T>> {
        ExprIter {
            stack: vec![&self.inner],
        }
    }
}

/// Type Check errors in [`Expr`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeError {
    /// PriceOracle1W is the first element in the expression
    PriceOracle1WFirst,
    /// PriceOracle1 is *not* the first element in the expression
    PriceOracle1Missing,
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeError::PriceOracle1WFirst => {
                write!(f, "PriceOracle1W is the first element in the expression")
            }
            TypeError::PriceOracle1Missing => write!(
                f,
                "PriceOracle1 is *not* the first element in the expression"
            ),
        }
    }
}

impl std::error::Error for TypeError {}

impl Expr<CovExtArgs> {
    /// Evaluate this expression
    fn eval(&self, env: &TxEnv, s: &mut interpreter::Stack) -> Result<i64, EvalError> {
        match &self.inner {
            ExprInner::Const(c) => Ok(*c),
            ExprInner::CurrInputIdx => {
                if env.idx >= env.spent_utxos.len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(
                        env.idx,
                        env.spent_utxos.len(),
                    ));
                }
                env.spent_utxos[env.idx]
                    .value
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInput(env.idx))
            }
            ExprInner::Input(i) => {
                let i = i.eval(env)?;
                if i >= env.spent_utxos.len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(i, env.spent_utxos.len()));
                }
                env.spent_utxos[i]
                    .value
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInput(i))
            }
            ExprInner::Output(i) => {
                let i = i.eval(env)?;
                if i >= env.tx.output.len() {
                    return Err(EvalError::OutputIndexOutOfBounds(i, env.tx.output.len()));
                }
                env.tx.output[i]
                    .value
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitOutput(i))
            }
            ExprInner::InputIssue(i) => {
                let i = i.eval(env)?;
                if i >= env.tx.input.len() {
                    return Err(EvalError::InputIndexOutOfBounds(i, env.tx.input.len()));
                }
                env.tx.input[i]
                    .asset_issuance
                    .amount
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInputIssuance(i))
            }
            ExprInner::InputReIssue(i) => {
                let i = i.eval(env)?;
                if i >= env.tx.input.len() {
                    return Err(EvalError::InputIndexOutOfBounds(i, env.tx.input.len()));
                }
                env.tx.input[i]
                    .asset_issuance
                    .inflation_keys
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInputReIssuance(i))
            }
            ExprInner::Add(x, y) => {
                let x = x.eval(env, s)?;
                let y = y.eval(env, s)?;
                x.checked_add(y).ok_or(EvalError::AddOverflow(x, y))
            }
            ExprInner::Sub(x, y) => {
                let x = x.eval(env, s)?;
                let y = y.eval(env, s)?;
                x.checked_sub(y).ok_or(EvalError::SubOverflow(x, y))
            }
            ExprInner::Mul(x, y) => {
                let x = x.eval(env, s)?;
                let y = y.eval(env, s)?;
                x.checked_mul(y).ok_or(EvalError::MulOverflow(x, y))
            }
            ExprInner::Div(x, y) => {
                let x = x.eval(env, s)?;
                let y = y.eval(env, s)?;
                x.checked_div_euclid(y).ok_or(EvalError::DivOverflow(x, y))
            }
            ExprInner::Mod(x, y) => {
                let x = x.eval(env, s)?;
                let y = y.eval(env, s)?;
                x.checked_rem_euclid(y).ok_or(EvalError::ModOverflow(x, y))
            }
            ExprInner::BitAnd(x, y) => {
                let x = x.eval(env, s)?;
                let y = y.eval(env, s)?;
                Ok(x & y)
            }
            ExprInner::BitOr(x, y) => {
                let x = x.eval(env, s)?;
                let y = y.eval(env, s)?;
                Ok(x | y)
            }
            ExprInner::Xor(x, y) => {
                let x = x.eval(env, s)?;
                let y = y.eval(env, s)?;
                Ok(x ^ y)
            }
            ExprInner::Invert(x) => {
                let x = x.eval(env, s)?;
                Ok(!x)
            }
            ExprInner::Negate(x) => {
                let x = x.eval(env, s)?;
                x.checked_neg().ok_or(EvalError::NegOverflow(x))
            }
            ExprInner::PriceOracle1(pk, timestamp) | ExprInner::PriceOracle1W(pk, timestamp) => {
                let x_only_pk = if let CovExtArgs::XOnlyKey(pk) = pk {
                    pk.0
                } else {
                    unreachable!("Construction ensures that Param is only of type XOnlyKey")
                };
                let price = s.pop().ok_or(EvalError::MissingPrice)?;
                let price = price.try_push().map_err(|_| EvalError::Price8BytePush)?;
                let price_u64 =
                    u64::from_le_bytes(price.try_into().map_err(|_| EvalError::Price8BytePush)?);

                let time_signed = s.pop().ok_or(EvalError::MissingTimestamp)?;
                let time_signed = time_signed
                    .try_push()
                    .map_err(|_| EvalError::Timstamp8BytePush)?;
                let time_signed_u64 = u64::from_le_bytes(
                    time_signed
                        .try_into()
                        .map_err(|_| EvalError::Timstamp8BytePush)?,
                );
                let sig = s.pop().ok_or(EvalError::MissingOracleSignature)?;
                let schnorr_sig_sl = sig.try_push().map_err(|_| EvalError::MalformedSig)?;
                let schnorr_sig = secp256k1::schnorr::Signature::from_slice(schnorr_sig_sl)
                    .map_err(|_| EvalError::MalformedSig)?;
                let secp = secp256k1::Secp256k1::verification_only();

                if *timestamp < time_signed_u64 {
                    return Err(EvalError::TimestampInFuture);
                }

                if check_sig_price_oracle_1(&secp, &schnorr_sig, &x_only_pk, *timestamp, price_u64)
                {
                    let price_i64 =
                        u64::try_into(price_u64).map_err(|_| EvalError::PriceOverflow)?;
                    Ok(price_i64)
                } else {
                    Err(EvalError::InvalidSignature)
                }
            }
        }
    }

    /// Evaluate this expression
    fn satisfy<Pk: MiniscriptKey + ToPublicKey>(
        &self,
        env: &TxEnv,
        s: &dyn Satisfier<Pk>,
    ) -> Result<(i64, Satisfaction), EvalError> {
        match &self.inner {
            ExprInner::Const(c) => Ok((*c, Satisfaction::empty())),
            ExprInner::CurrInputIdx => {
                if env.idx >= env.spent_utxos.len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(
                        env.idx,
                        env.spent_utxos.len(),
                    ));
                }
                let res = env.spent_utxos[env.idx]
                    .value
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInput(env.idx))?;
                Ok((res, Satisfaction::empty()))
            }
            ExprInner::Input(i) => {
                let i = i.eval(env)?;
                if i >= env.spent_utxos.len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(i, env.spent_utxos.len()));
                }
                let res = env.spent_utxos[i]
                    .value
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInput(i))?;
                Ok((res, Satisfaction::empty()))
            }
            ExprInner::Output(i) => {
                let i = i.eval(env)?;
                if i >= env.tx.output.len() {
                    return Err(EvalError::OutputIndexOutOfBounds(i, env.tx.output.len()));
                }
                let res = env.tx.output[i]
                    .value
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitOutput(i))?;
                Ok((res, Satisfaction::empty()))
            }
            ExprInner::InputIssue(i) => {
                let i = i.eval(env)?;
                if i >= env.tx.input.len() {
                    return Err(EvalError::InputIndexOutOfBounds(i, env.tx.input.len()));
                }
                let res = env.tx.input[i]
                    .asset_issuance
                    .amount
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInputIssuance(i))?;
                Ok((res, Satisfaction::empty()))
            }
            ExprInner::InputReIssue(i) => {
                let i = i.eval(env)?;
                if i >= env.tx.input.len() {
                    return Err(EvalError::InputIndexOutOfBounds(i, env.tx.input.len()));
                }
                let res = env.tx.input[i]
                    .asset_issuance
                    .inflation_keys
                    .explicit()
                    .map(|x| x as i64) // safe conversion bitcoin values from u64 to i64 because 21 mil
                    .ok_or(EvalError::NonExplicitInputReIssuance(i))?;
                Ok((res, Satisfaction::empty()))
            }
            ExprInner::Add(x, y) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                let (y, sat_y) = y.satisfy(env, s)?;
                let res = x.checked_add(y).ok_or(EvalError::AddOverflow(x, y))?;
                let sat = Satisfaction::combine(sat_y, sat_x);
                Ok((res, sat))
            }
            ExprInner::Sub(x, y) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                let (y, sat_y) = y.satisfy(env, s)?;
                let res = x.checked_sub(y).ok_or(EvalError::SubOverflow(x, y))?;
                let sat = Satisfaction::combine(sat_y, sat_x);
                Ok((res, sat))
            }
            ExprInner::Mul(x, y) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                let (y, sat_y) = y.satisfy(env, s)?;
                let res = x.checked_mul(y).ok_or(EvalError::MulOverflow(x, y))?;
                let sat = Satisfaction::combine(sat_y, sat_x);
                Ok((res, sat))
            }
            ExprInner::Div(x, y) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                let (y, sat_y) = y.satisfy(env, s)?;
                let res = x
                    .checked_div_euclid(y)
                    .ok_or(EvalError::DivOverflow(x, y))?;
                let sat = Satisfaction::combine(sat_y, sat_x);
                Ok((res, sat))
            }
            ExprInner::Mod(x, y) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                let (y, sat_y) = y.satisfy(env, s)?;
                let res = x
                    .checked_rem_euclid(y)
                    .ok_or(EvalError::ModOverflow(x, y))?;
                let sat = Satisfaction::combine(sat_y, sat_x);
                Ok((res, sat))
            }
            ExprInner::BitAnd(x, y) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                let (y, sat_y) = y.satisfy(env, s)?;
                let sat = Satisfaction::combine(sat_y, sat_x);
                Ok((x & y, sat))
            }
            ExprInner::BitOr(x, y) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                let (y, sat_y) = y.satisfy(env, s)?;
                let sat = Satisfaction::combine(sat_y, sat_x);
                Ok((x | y, sat))
            }
            ExprInner::Xor(x, y) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                let (y, sat_y) = y.satisfy(env, s)?;
                let sat = Satisfaction::combine(sat_y, sat_x);
                Ok((x ^ y, sat))
            }
            ExprInner::Invert(x) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                Ok((!x, sat_x))
            }
            ExprInner::Negate(x) => {
                let (x, sat_x) = x.satisfy(env, s)?;
                let res = x.checked_neg().ok_or(EvalError::NegOverflow(x))?;
                Ok((res, sat_x))
            }
            ExprInner::PriceOracle1(pk, time) | ExprInner::PriceOracle1W(pk, time) => {
                let pk = if let CovExtArgs::XOnlyKey(xpk) = pk {
                    xpk.0
                } else {
                    unreachable!("PriceOracle1 constructed with only xonly key")
                };
                match s.lookup_price_oracle_sig(&pk, *time) {
                    Some((sig, price, time)) => {
                        let wit = Witness::Stack(vec![
                            sig.as_ref().to_vec(),
                            time.to_le_bytes().to_vec(),
                            price.to_le_bytes().to_vec(),
                        ]);
                        let sat = Satisfaction {
                            stack: wit,
                            has_sig: false, // Even though this has sig, it is not a signature over the tx and the tx is still malleable
                        };
                        Ok((price, sat))
                    }
                    None => Err(EvalError::MissingOracleSignature),
                }
            }
        }
    }

    /// Push this script to builder
    fn push_to_builder(&self, builder: script::Builder) -> script::Builder {
        match &self.inner {
            ExprInner::Const(c) => builder.push_slice(&c.to_le_bytes()),
            ExprInner::CurrInputIdx => builder
                .push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(OP_INSPECTINPUTVALUE)
                .push_int(1)
                .push_opcode(OP_EQUALVERIFY),
            ExprInner::Input(i) => i
                .push_to_builder(builder)
                .push_opcode(OP_INSPECTINPUTVALUE)
                .push_int(1)
                .push_opcode(OP_EQUALVERIFY),
            ExprInner::Output(i) => i
                .push_to_builder(builder)
                .push_opcode(OP_INSPECTOUTPUTVALUE)
                .push_int(1)
                .push_opcode(OP_EQUALVERIFY),
            ExprInner::InputIssue(i) => i
                .push_to_builder(builder)
                .push_opcode(OP_INSPECTINPUTISSUANCE)
                .push_opcode(OP_DROP)
                .push_opcode(OP_DROP)
                .push_int(1)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_NIP)
                .push_opcode(OP_NIP),
            ExprInner::InputReIssue(i) => i
                .push_to_builder(builder)
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
            ExprInner::PriceOracle1(pk, t) => {
                let xpk = if let CovExtArgs::XOnlyKey(xpk) = pk {
                    xpk.0
                } else {
                    unreachable!("PriceOracle1 constructor ensures that CovExtArgs is XOnlyKey");
                };
                // `2DUP TOALTSTACK <T> OP_GREATERTHANEQ VERIFY CAT SHA256 <K> CHECKSIGFROMSTACKVERIFY OP_FROMATLSTACK`
                builder
                    .push_opcode(OP_2DUP)
                    .push_opcode(OP_TOALTSTACK)
                    .push_slice(&t.to_le_bytes())
                    .push_opcode(OP_GREATERTHANOREQUAL64)
                    .push_opcode(OP_VERIFY)
                    .push_opcode(OP_CAT)
                    .push_opcode(OP_SHA256)
                    .push_slice(&xpk.serialize())
                    .push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
                    .push_opcode(OP_FROMALTSTACK)
            }
            ExprInner::PriceOracle1W(pk, t) => {
                let xpk = if let CovExtArgs::XOnlyKey(xpk) = pk {
                    xpk.0
                } else {
                    unreachable!("PriceOracle1 constructor ensures that CovExtArgs is XOnlyKey");
                };
                // `2DUP TOALTSTACK <T> OP_GREATERTHANEQ VERIFY CAT SHA256 <K> CHECKSIGFROMSTACKVERIFY OP_FROMATLSTACK OP_SWAP`
                builder
                    .push_opcode(OP_TOALTSTACK)
                    .push_opcode(OP_2DUP)
                    .push_opcode(OP_TOALTSTACK)
                    .push_slice(&t.to_le_bytes())
                    .push_opcode(OP_GREATERTHANOREQUAL64)
                    .push_opcode(OP_VERIFY)
                    .push_opcode(OP_CAT)
                    .push_opcode(OP_SHA256)
                    .push_slice(&xpk.serialize())
                    .push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
                    .push_opcode(OP_FROMALTSTACK)
                    .push_opcode(OP_FROMALTSTACK)
                    .push_opcode(OP_SWAP)
            }
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
            le_bytes.copy_from_slice(bytes);
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
        } else if let Some(&[Tk::CurrInp, Tk::InpValue, Tk::Num(1), Tk::Equal, Tk::Verify]) =
            tks.get(e.checked_sub(5)?..e)
        {
            Some((Expr::from_inner(ExprInner::CurrInputIdx), e - 5))
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
        } else if let Some(&[Tk::InpValue, Tk::Num(1), Tk::Equal, Tk::Verify]) =
            tks.get(e.checked_sub(4)?..e)
        {
            let (i, e) = IdxExpr::from_tokens(tks, e - 4)?;
            Some((Expr::from_inner(ExprInner::Input(i)), e))
        } else if let Some(&[Tk::OutValue, Tk::Num(1), Tk::Equal, Tk::Verify]) =
            tks.get(e.checked_sub(4)?..e)
        {
            let (i, e) = IdxExpr::from_tokens(tks, e - 4)?;
            Some((Expr::from_inner(ExprInner::Output(i)), e))
        } else if let Some(
            &[Tk::InpIssue, Tk::Drop, Tk::Drop, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Nip, Tk::Nip],
        ) = tks.get(e.checked_sub(8)?..e)
        {
            let (i, e) = IdxExpr::from_tokens(tks, e - 8)?;
            Some((Expr::from_inner(ExprInner::InputIssue(i)), e))
        } else if let Some(
            &[Tk::InpIssue, Tk::Drop, Tk::Drop, Tk::Drop, Tk::Drop, Tk::Num(1), Tk::Equal, Tk::Verify],
        ) = tks.get(e.checked_sub(8)?..e)
        {
            let (i, e) = IdxExpr::from_tokens(tks, e - 8)?;
            Some((Expr::from_inner(ExprInner::InputReIssue(i)), e))
        } else if let Some(
            &[Tk::Dup2, Tk::ToAltStack, Tk::Bytes8(time), Tk::Geq64, Tk::Verify, Tk::Cat, Tk::Sha256, Tk::Bytes32(xpk), Tk::CheckSigFromStackVerify, Tk::FromAltStack],
        ) = tks.get(e.checked_sub(10)?..e)
        {
            let time = u64::from_le_bytes(time.try_into().expect("8 bytes"));
            let xpk = XOnlyPublicKey::from_slice(xpk).ok()?;
            let key = CovExtArgs::csfs_key(xpk);
            let expr = Expr::from_inner(ExprInner::PriceOracle1(key, time));
            Some((expr, e - 10))
        } else if let Some(
            &[Tk::ToAltStack, Tk::Dup2, Tk::ToAltStack, Tk::Bytes8(time), Tk::Geq64, Tk::Verify, Tk::Cat, Tk::Sha256, Tk::Bytes32(xpk), Tk::CheckSigFromStackVerify, Tk::FromAltStack, Tk::FromAltStack, Tk::Swap],
        ) = tks.get(e.checked_sub(13)?..e)
        {
            let time = u64::from_le_bytes(time.try_into().expect("8 bytes"));
            let xpk = XOnlyPublicKey::from_slice(xpk).ok()?;
            let key = CovExtArgs::csfs_key(xpk);
            let expr = Expr::from_inner(ExprInner::PriceOracle1W(key, time));
            Some((expr, e - 13))
        } else {
            None
        }
    }
}

/// Miniscript Fragment containing arith expressions
/// Expr cannot be directly used a miniscript fragment because it pushes a 64 bit
/// value on stack. Two expressions can be combined with Arith to something is
/// of Base type B to be used in miniscript expressions
///
/// This struct represents unchecked arith expressions that could be invalid.
/// As of now, [`Expr`] can be invalid only if
///     - PriceOracle1 is not the first leaf in the tree
///     - PriceOracle1W is the first leaf in the tree
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Debug)]
pub enum ArithInner<T: ExtParam> {
    /// Eq
    /// `[X] [Y] EQUAL`
    Eq(Expr<T>, Expr<T>),
    /// Lt
    /// `[X] [Y] LESSTHAN`
    Lt(Expr<T>, Expr<T>),
    /// Leq
    /// `[X] [Y] LESSTHANOREQUAL`
    Leq(Expr<T>, Expr<T>),
    /// Gt
    /// `[X] [Y] GREATERTHAN`
    Gt(Expr<T>, Expr<T>),
    /// Geq
    /// `[X] [Y] GREATERTHANOREQUAL`
    Geq(Expr<T>, Expr<T>),
}

/// Wrapper around `ArithInner` that ensures that the expression is valid.
/// See `ArithInner` for more details.
///
/// Note that the library allows construction of unchecked [`Expr], but
/// [`Arith`] is always checked.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct Arith<T: ExtParam> {
    /// The underlying expression
    expr: ArithInner<T>,
}

impl<T: ExtParam> Arith<T> {
    /// Create a new Arith expression. This is the only constructor
    pub fn new(expr: ArithInner<T>) -> Result<Self, TypeError> {
        {
            // Borrow checker scope
            let (a, b) = match &expr {
                ArithInner::Eq(ref a, ref b)
                | ArithInner::Lt(ref a, ref b)
                | ArithInner::Leq(ref a, ref b)
                | ArithInner::Gt(ref a, ref b)
                | ArithInner::Geq(ref a, ref b) => (a, b),
            };
            let mut iter = a.iter_terminals();
            if let Some(ExprInner::PriceOracle1W(_, _)) = iter.next() {
                return Err(TypeError::PriceOracle1WFirst);
            }
            // Note iter here has consumed the first element
            if iter.any(|x| matches!(x, ExprInner::PriceOracle1(..))) {
                return Err(TypeError::PriceOracle1Missing);
            }
            // All the elements in b should be PriceOracle1W
            if b.iter_terminals()
                .any(|x| matches!(x, ExprInner::PriceOracle1(..)))
            {
                return Err(TypeError::PriceOracle1Missing);
            }
        }
        Ok(Arith { expr })
    }

    /// Obtains the inner expression
    pub fn inner(&self) -> &ArithInner<T> {
        &self.expr
    }
}

impl<T: ExtParam> Arith<T> {
    /// Obtains the depth of this expression
    pub fn depth(&self) -> usize {
        match &self.expr {
            ArithInner::Eq(x, y)
            | ArithInner::Lt(x, y)
            | ArithInner::Leq(x, y)
            | ArithInner::Gt(x, y)
            | ArithInner::Geq(x, y) => cmp::max(x.depth, y.depth),
        }
    }

    /// Obtains the script size
    pub fn script_size(&self) -> usize {
        match &self.expr {
            ArithInner::Eq(x, y)
            | ArithInner::Lt(x, y)
            | ArithInner::Leq(x, y)
            | ArithInner::Gt(x, y)
            | ArithInner::Geq(x, y) => x.script_size + y.script_size + 1,
        }
    }
}

impl Arith<CovExtArgs> {
    /// Evaluate this expression with context given transaction and spent utxos
    pub fn eval(&self, env: &TxEnv, s: &mut interpreter::Stack) -> Result<bool, EvalError> {
        let res = match &self.expr {
            ArithInner::Eq(x, y) => x.eval(env, s)? == y.eval(env, s)?,
            ArithInner::Lt(x, y) => x.eval(env, s)? < y.eval(env, s)?,
            ArithInner::Leq(x, y) => x.eval(env, s)? <= y.eval(env, s)?,
            ArithInner::Gt(x, y) => x.eval(env, s)? > y.eval(env, s)?,
            ArithInner::Geq(x, y) => x.eval(env, s)? >= y.eval(env, s)?,
        };
        Ok(res)
    }

    /// Internal satisfaction helper for Arith.
    /// This allows us to cleanly write code that we can use "?" for early
    /// returns.
    /// The trait implementation of satisfy just calls this function with unwrap_or
    /// impossible.
    pub fn satisfy_helper<Pk: ToPublicKey>(
        &self,
        env: &TxEnv,
        sat: &dyn Satisfier<Pk>,
    ) -> Result<Satisfaction, EvalError> {
        let (res, sat_a, sat_b) = match &self.expr {
            ArithInner::Eq(a, b) => {
                let (a, sat_a) = a.satisfy(env, sat)?;
                let (b, sat_b) = b.satisfy(env, sat)?;
                (a == b, sat_a, sat_b)
            }
            ArithInner::Lt(a, b) => {
                let (a, sat_a) = a.satisfy(env, sat)?;
                let (b, sat_b) = b.satisfy(env, sat)?;
                (a < b, sat_a, sat_b)
            }
            ArithInner::Leq(a, b) => {
                let (a, sat_a) = a.satisfy(env, sat)?;
                let (b, sat_b) = b.satisfy(env, sat)?;
                (a <= b, sat_a, sat_b)
            }
            ArithInner::Gt(a, b) => {
                let (a, sat_a) = a.satisfy(env, sat)?;
                let (b, sat_b) = b.satisfy(env, sat)?;
                (a > b, sat_a, sat_b)
            }
            ArithInner::Geq(a, b) => {
                let (a, sat_a) = a.satisfy(env, sat)?;
                let (b, sat_b) = b.satisfy(env, sat)?;
                (a >= b, sat_a, sat_b)
            }
        };
        if res {
            Ok(Satisfaction::combine(sat_b, sat_a))
        } else {
            Ok(Satisfaction::impossible())
        }
    }

    /// Push this script to builder
    pub fn push_to_builder(&self, builder: script::Builder) -> script::Builder {
        match &self.expr {
            ArithInner::Eq(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_EQUAL)
            }
            ArithInner::Lt(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_LESSTHAN64)
            }
            ArithInner::Leq(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_LESSTHANOREQUAL64)
            }
            ArithInner::Gt(x, y) => {
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_GREATERTHAN64)
            }
            ArithInner::Geq(x, y) => {
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
        let (inner, pos) = match last_opcode {
            Tk::Equal => (ArithInner::Eq(x, y), pos),
            Tk::Le64 => (ArithInner::Lt(x, y), pos),
            Tk::Leq64 => (ArithInner::Leq(x, y), pos),
            Tk::Ge64 => (ArithInner::Gt(x, y), pos),
            Tk::Geq64 => (ArithInner::Geq(x, y), pos),
            _ => return None,
        };
        Some((Arith::new(inner).ok()?, pos))
    }
}

impl<T: ExtParam> fmt::Display for Expr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            ExprInner::Const(c) => write!(f, "{}", c),
            ExprInner::CurrInputIdx => write!(f, "curr_inp_v"),
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
            ExprInner::PriceOracle1(pk, t) => write!(f, "price_oracle1({},{})", pk, t),
            ExprInner::PriceOracle1W(pk, t) => write!(f, "price_oracle1_w({},{})", pk, t), // same syntax
        }
    }
}

impl<T: ExtParam> fmt::Debug for Expr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            ExprInner::Const(c) => write!(f, "{:?}", c),
            ExprInner::CurrInputIdx => write!(f, "curr_inp_v"),
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
            ExprInner::PriceOracle1(pk, t) => write!(f, "price_oracle1({:?},{:?})", pk, t),
            ExprInner::PriceOracle1W(pk, t) => write!(f, "price_oracle1_w({:?},{:?})", pk, t), // same syntax as price_oracle1
        }
    }
}

impl<T: ExtParam> FromStr for Expr<T> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree(&top)
    }
}

impl<T: ExtParam> FromTree for Box<Expr<T>> {
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        expression::FromTree::from_tree(top).map(Box::new)
    }
}

impl<T: ExtParam> FromTree for Expr<T> {
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        fn unary<F, T: ExtParam>(top: &expression::Tree<'_>, frag: F) -> Result<Expr<T>, Error>
        where
            F: FnOnce(Box<Expr<T>>) -> ExprInner<T>,
        {
            let l: Expr<T> = FromTree::from_tree(&top.args[0])?;
            Ok(Expr::from_inner(frag(Box::new(l))))
        }

        fn binary<F, T: ExtParam>(top: &expression::Tree<'_>, frag: F) -> Result<Expr<T>, Error>
        where
            F: FnOnce(Box<Expr<T>>, Box<Expr<T>>) -> ExprInner<T>,
        {
            let l: Expr<T> = FromTree::from_tree(&top.args[0])?;
            let r: Expr<T> = FromTree::from_tree(&top.args[1])?;
            Ok(Expr::from_inner(frag(Box::new(l), Box::new(r))))
        }
        match (top.name, top.args.len()) {
            ("inp_v", 1) => Ok(Expr::from_inner(expression::unary(top, ExprInner::Input)?)),
            ("curr_inp_v", 0) => Ok(Expr::from_inner(ExprInner::CurrInputIdx)),
            ("out_v", 1) => Ok(Expr::from_inner(expression::unary(top, ExprInner::Output)?)),
            ("inp_issue_v", 1) => Ok(Expr::from_inner(expression::unary(
                top,
                ExprInner::InputIssue,
            )?)),
            ("inp_reissue_v", 1) => Ok(Expr::from_inner(expression::unary(
                top,
                ExprInner::InputReIssue,
            )?)),
            ("price_oracle1", 2) | ("price_oracle1_w", 2) => {
                if !top.args[0].args.is_empty() || !top.args[1].args.is_empty() {
                    return Err(Error::Unexpected(String::from(
                        "price_oracle1 expects 2 terminal arguments",
                    )));
                }
                let pk = T::arg_from_str(top.args[0].name, top.name, 0)?;
                let t: u64 = expression::parse_num::<u64>(top.args[1].name)?;
                if top.name == "price_oracle1" {
                    Ok(Expr::from_inner(ExprInner::PriceOracle1(pk, t)))
                } else {
                    Ok(Expr::from_inner(ExprInner::PriceOracle1W(pk, t)))
                }
            }
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

impl<T: ExtParam> FromStr for ArithInner<T> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree(&top)
    }
}

impl<T: ExtParam> FromStr for Arith<T> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = ArithInner::from_str(s)?;
        Arith::new(inner).map_err(|_| Error::Unexpected(String::from("Arith::new")))
    }
}

impl<T: ExtParam> FromTree for Box<ArithInner<T>> {
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        ArithInner::from_tree(top).map(Box::new)
    }
}

impl<T: ExtParam> FromTree for ArithInner<T> {
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        match (top.name, top.args.len()) {
            // Disambiguiate with num64_eq to avoid confusion with asset_eq
            ("num64_eq", 2) => expression::binary(top, ArithInner::Eq),
            ("num64_geq", 2) => expression::binary(top, ArithInner::Geq),
            ("num64_gt", 2) => expression::binary(top, ArithInner::Gt),
            ("num64_lt", 2) => expression::binary(top, ArithInner::Lt),
            ("num64_leq", 2) => expression::binary(top, ArithInner::Leq),
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Extension",
                top.name,
                top.args.len(),
            ))),
        }
    }
}

impl<T: ExtParam> fmt::Display for Arith<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.expr {
            ArithInner::Eq(x, y) => write!(f, "num64_eq({},{})", x, y),
            ArithInner::Leq(x, y) => write!(f, "num64_leq({},{})", x, y),
            ArithInner::Lt(x, y) => write!(f, "num64_lt({},{})", x, y),
            ArithInner::Geq(x, y) => write!(f, "num64_geq({},{})", x, y),
            ArithInner::Gt(x, y) => write!(f, "num64_gt({},{})", x, y),
        }
    }
}

impl<T: ExtParam> fmt::Debug for Arith<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.expr {
            ArithInner::Eq(x, y) => write!(f, "num64_eq({:?},{:?})", x, y),
            ArithInner::Leq(x, y) => write!(f, "num64_leq({:?},{:?})", x, y),
            ArithInner::Lt(x, y) => write!(f, "num64_lt({:?},{:?})", x, y),
            ArithInner::Geq(x, y) => write!(f, "num64_geq({:?},{:?})", x, y),
            ArithInner::Gt(x, y) => write!(f, "num64_gt({:?},{:?})", x, y),
        }
    }
}

impl<T: ExtParam> Extension for Arith<T> {
    fn corr_prop(&self) -> Correctness {
        Correctness {
            base: Base::B,
            input: Input::Zero,    // No input from stack
            dissatisfiable: false, // No dissatisfactions from stack
            unit: true,
        }
    }

    fn mall_prop(&self) -> Malleability {
        Malleability {
            dissat: Dissat::None, // No dissatisfactions from stack inputs
            safe: false,          // Unsafe as a top fragment
            non_malleable: true, // There can exist multiple satisfactions for expressions. inp_v(0) = out_v(0), but
                                 // we only deal with script satisfactions here.
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

    fn from_name_tree(
        name: &str,
        children: &[expression::Tree<'_>],
    ) -> Result<Self, FromTokenIterError> {
        let tree = Tree {
            name,
            args: children.to_vec(), // Cloning two references here, it is possible to avoid the to_vec() here,
                                     // but it requires lot of refactor.
        };
        let inner = ArithInner::from_tree(&tree).map_err(|_| FromTokenIterError)?;
        Arith::new(inner).map_err(|_e| FromTokenIterError)
    }
}

impl ParseableExt for Arith<CovExtArgs> {
    fn satisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let (tx, utxos, curr_idx) = match (
            sat.lookup_tx(),
            sat.lookup_spent_utxos(),
            sat.lookup_curr_inp(),
        ) {
            (Some(tx), Some(utxos), Some(curr_idx)) => (tx, utxos, curr_idx),
            _ => return Satisfaction::impossible(),
        };
        let env = match TxEnv::new(tx, utxos, curr_idx) {
            Some(env) => env,
            None => return Satisfaction::impossible(),
        };
        self.satisfy_helper(&env, sat)
            .unwrap_or(Satisfaction::empty())
    }

    fn dissatisfy<Pk, S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        // Impossible
        Satisfaction::impossible()
    }

    fn push_to_builder(&self, builder: elements::script::Builder) -> elements::script::Builder {
        self.push_to_builder(builder)
    }

    fn from_token_iter(tokens: &mut TokenIter<'_>) -> Result<Self, FromTokenIterError> {
        let len = tokens.len();
        match Self::from_tokens(tokens.as_inner_mut()) {
            Some((res, last_pos)) => {
                tokens.advance(len - last_pos).ok_or(FromTokenIterError)?;
                Ok(res)
            }
            None => Err(FromTokenIterError),
        }
    }

    fn evaluate(
        &self,
        stack: &mut interpreter::Stack,
        txenv: Option<&TxEnv>,
    ) -> Result<bool, interpreter::Error> {
        let txenv = txenv
            .as_ref()
            .ok_or(interpreter::Error::ArithError(EvalError::TxEnvNotPresent))?;

        match self.eval(txenv, stack) {
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
    /// Missing price
    MissingPrice,
    /// Price 8 byte push
    Price8BytePush,
    /// Missing timestamp
    MissingTimestamp,
    /// Timestamp 8 byte push
    Timstamp8BytePush,
    /// Missing Oracle signature
    MissingOracleSignature,
    /// Missing Oracle pubkey
    MalformedSig,
    /// Timestamp in future
    TimestampInFuture,
    /// Invalid oracle signature
    InvalidSignature,
    /// Price overflow
    PriceOverflow,
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
            EvalError::MissingPrice => write!(f, "Missing price"),
            EvalError::Price8BytePush => write!(f, "Price 8 byte push"),
            EvalError::MissingTimestamp => write!(f, "Missing timestamp"),
            EvalError::Timstamp8BytePush => write!(f, "Timestamp 8 byte push"),
            EvalError::MissingOracleSignature => write!(f, "Missing price oracle signature"),
            EvalError::MalformedSig => write!(f, "Malformed price oracle signature"),
            EvalError::TimestampInFuture => write!(f, "Oracle Timestamp in future"),
            EvalError::InvalidSignature => write!(f, "Invalid price oracle signature"),
            EvalError::PriceOverflow => write!(f, "Price overflow (must be 64 bit integer)"),
        }
    }
}

impl<PArg, QArg> TranslateExtParam<PArg, QArg> for Arith<PArg>
where
    PArg: ExtParam,
    QArg: ExtParam,
{
    type Output = Arith<QArg>;

    fn translate_ext<T, E>(&self, t: &mut T) -> Result<Self::Output, E>
    where
        T: ExtParamTranslator<PArg, QArg, E>,
    {
        let res = match &self.expr {
            ArithInner::Eq(a, b) => ArithInner::Eq(a.translate_ext(t)?, b.translate_ext(t)?),
            ArithInner::Lt(a, b) => ArithInner::Lt(a.translate_ext(t)?, b.translate_ext(t)?),
            ArithInner::Leq(a, b) => ArithInner::Leq(a.translate_ext(t)?, b.translate_ext(t)?),
            ArithInner::Gt(a, b) => ArithInner::Gt(a.translate_ext(t)?, b.translate_ext(t)?),
            ArithInner::Geq(a, b) => ArithInner::Geq(a.translate_ext(t)?, b.translate_ext(t)?),
        };
        Ok(Arith::new(res).expect("Type check must succeed"))
    }
}

impl<PArg, QArg> TranslateExtParam<PArg, QArg> for Expr<PArg>
where
    PArg: ExtParam,
    QArg: ExtParam,
{
    type Output = Expr<QArg>;

    fn translate_ext<T, E>(&self, t: &mut T) -> Result<Self::Output, E>
    where
        T: ExtParamTranslator<PArg, QArg, E>,
    {
        match &self.inner {
            ExprInner::Const(c) => Ok(Expr::from_inner(ExprInner::Const(*c))),
            ExprInner::CurrInputIdx => Ok(Expr::from_inner(ExprInner::CurrInputIdx)),
            ExprInner::Input(i) => Ok(Expr::from_inner(ExprInner::Input(i.clone()))),
            ExprInner::Output(i) => Ok(Expr::from_inner(ExprInner::Output(i.clone()))),
            ExprInner::InputIssue(i) => Ok(Expr::from_inner(ExprInner::InputIssue(i.clone()))),
            ExprInner::InputReIssue(i) => Ok(Expr::from_inner(ExprInner::InputReIssue(i.clone()))),
            ExprInner::Add(a, b) => Ok(Expr::from_inner(ExprInner::Add(
                Box::new(a.translate_ext(t)?),
                Box::new(b.translate_ext(t)?),
            ))),
            ExprInner::Sub(a, b) => Ok(Expr::from_inner(ExprInner::Sub(
                Box::new(a.translate_ext(t)?),
                Box::new(b.translate_ext(t)?),
            ))),
            ExprInner::Mul(a, b) => Ok(Expr::from_inner(ExprInner::Mul(
                Box::new(a.translate_ext(t)?),
                Box::new(b.translate_ext(t)?),
            ))),
            ExprInner::Div(a, b) => Ok(Expr::from_inner(ExprInner::Div(
                Box::new(a.translate_ext(t)?),
                Box::new(b.translate_ext(t)?),
            ))),
            ExprInner::Mod(a, b) => Ok(Expr::from_inner(ExprInner::Mod(
                Box::new(a.translate_ext(t)?),
                Box::new(b.translate_ext(t)?),
            ))),
            ExprInner::BitAnd(a, b) => Ok(Expr::from_inner(ExprInner::BitAnd(
                Box::new(a.translate_ext(t)?),
                Box::new(b.translate_ext(t)?),
            ))),
            ExprInner::BitOr(a, b) => Ok(Expr::from_inner(ExprInner::BitOr(
                Box::new(a.translate_ext(t)?),
                Box::new(b.translate_ext(t)?),
            ))),
            ExprInner::Xor(a, b) => Ok(Expr::from_inner(ExprInner::Xor(
                Box::new(a.translate_ext(t)?),
                Box::new(b.translate_ext(t)?),
            ))),
            ExprInner::Invert(a) => Ok(Expr::from_inner(ExprInner::Invert(Box::new(
                a.translate_ext(t)?,
            )))),
            ExprInner::Negate(a) => Ok(Expr::from_inner(ExprInner::Negate(Box::new(
                a.translate_ext(t)?,
            )))),
            ExprInner::PriceOracle1(pk, time) => {
                Ok(Expr::from_inner(ExprInner::PriceOracle1(t.ext(pk)?, *time)))
            }
            ExprInner::PriceOracle1W(pk, time) => Ok(Expr::from_inner(ExprInner::PriceOracle1W(
                t.ext(pk)?,
                *time,
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::key::XOnlyPublicKey;

    use super::*;
    use crate::extensions::check_sig_price_oracle_1;
    use crate::test_utils::{StrExtTranslator, StrXOnlyKeyTranslator};
    use crate::{CovenantExt, Miniscript, Segwitv0, Tap, TranslatePk};

    #[test]
    fn test_index_ops_with_arith() {
        // index ops tests with different index types
        _arith_parse("num64_eq(out_v(idx_sub(5,curr_idx)),inp_v(idx_add(0,curr_idx)))");
        _arith_parse("num64_eq(out_v(idx_mul(5,curr_idx)),inp_v(idx_div(0,curr_idx)))");

        _arith_parse(
            "num64_eq(inp_issue_v(idx_sub(5,curr_idx)),inp_reissue_v(idx_add(0,curr_idx)))",
        );
        _arith_parse(
            "num64_eq(inp_issue_v(idx_sub(5,curr_idx)),inp_reissue_v(idx_add(0,curr_idx)))",
        );
    }

    #[test]
    fn arith_parse() {
        _arith_parse("num64_geq(sub(mul(1,0),mul(0,curr_inp_v)),0)");
        _arith_parse("num64_gt(curr_inp_v,mul(1,out_v(0)))");
        // This does not test the evaluation
        _arith_parse("num64_eq(8,8)");
        _arith_parse("num64_gt(9223372036854775807,9223372036854775806)"); // 2**63-1

        // negatives and comparisons
        _arith_parse("num64_eq(-8,-8)"); // negative nums
        _arith_parse("num64_gt(-8,-9)");
        _arith_parse("num64_geq(-8,-8)");
        _arith_parse("num64_leq(-8,-7)");
        _arith_parse("num64_lt(-8,-7)");

        // test terminals parsing
        _arith_parse("num64_eq(inp_v(0),100)");
        _arith_parse("num64_eq(out_v(0),100)");
        _arith_parse("num64_eq(inp_issue_v(0),100)");
        _arith_parse("num64_eq(inp_reissue_v(0),100)");
        _arith_parse("num64_eq(inp_v(0),out_v(0))");
        _arith_parse("num64_eq(inp_issue_v(1),inp_reissue_v(1))");

        // test combinator
        _arith_parse("num64_eq(add(4,3),mul(1,7))");
        _arith_parse("num64_eq(sub(3,3),div(0,9))");
        _arith_parse("num64_eq(mod(9,3),0)");
        _arith_parse("num64_eq(bitand(0,134),0)");
        _arith_parse("num64_eq(bitor(1,3),3)");
        _arith_parse("num64_eq(bitxor(1,3),2)");
        _arith_parse("num64_eq(bitinv(0),-9223372036854775808)");
        _arith_parse("num64_eq(neg(1),-1)");

        // test some misc combinations with other miniscript fragments
        _arith_parse("and_v(v:pk(K),num64_gt(8,7))");
        _arith_parse(
            "and_v(v:pk(K),num64_eq(mul(inp_v(0),out_v(1)),sub(add(3,inp_issue_v(1)),-9)))",
        );

        // test price oracles
        _arith_parse("num64_eq(price_oracle1(K,123213),28004)");
        _arith_parse("num64_eq(price_oracle1(K,123213),price_oracle1_w(K,4318743))");
        _arith_parse(
            "and_v(v:pk(K),num64_eq(mul(inp_v(0),out_v(1)),sub(add(3,inp_issue_v(1)),price_oracle1_w(K,123213))))",
        );
        _arith_parse("and_v(v:pk(X2),num64_eq(add(price_oracle1(K,1),0),50000))");
    }

    fn _arith_parse(s: &str) {
        type MsExtStr = Miniscript<String, Tap, CovenantExt<String>>;
        type MsExt = Miniscript<XOnlyPublicKey, Tap, CovenantExt<CovExtArgs>>;
        type MsExtSegwitv0 = Miniscript<String, Segwitv0, CovenantExt<String>>;

        // Make sure that parsing this errors in segwit context
        assert!(MsExtSegwitv0::from_str_insane(s).is_err());

        let ms = MsExtStr::from_str_insane(s).unwrap();
        // test string rtt
        assert_eq!(ms.to_string(), s);
        let mut t = StrXOnlyKeyTranslator::default();
        let mut ext_t = StrExtTranslator::default();
        ext_t.ext_map.insert(
            String::from("K"),
            CovExtArgs::csfs_key(
                XOnlyPublicKey::from_str(
                    "c304c3b5805eecff054c319c545dc6ac2ad44eb70f79dd9570e284c5a62c0f9e",
                )
                .unwrap(),
            ),
        );
        // use crate::extensions::param::TranslateExtParam;
        let ms = ms.translate_pk(&mut t).unwrap();
        let ms = TranslateExt::translate_ext(&ms, &mut ext_t).unwrap();
        // script rtt
        assert_eq!(ms, MsExt::parse_insane(&ms.encode()).unwrap());
    }

    #[test]
    fn test_fuji_fixed_signs() {
        // Test Vector obtained from curl queries
        let sig = elements::secp256k1_zkp::schnorr::Signature::from_str("8fc6e217b0e1d3481855cdb97cfe333999d4cf48b9f58b4f299ad86fd768a345e97a953d6efa1ca5971f18810deedcfddc4c2bd4e8f9d1431c1ad6ebafa013a9").unwrap();
        let pk = elements::secp256k1_zkp::XOnlyPublicKey::from_str(
            "c304c3b5805eecff054c319c545dc6ac2ad44eb70f79dd9570e284c5a62c0f9e",
        )
        .unwrap();

        let timestamp: u64 = 1679531858733;
        let price: u64 = 27365;
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        assert!(check_sig_price_oracle_1(&secp, &sig, &pk, timestamp, price))
    }
}
