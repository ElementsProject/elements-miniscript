//! Extensions to elements-miniscript
//! Users should implement the [`Extension`] trait to extend miniscript to have newer leaf nodes
//! Look at examples for implementation of ver_eq fragment

use std::{fmt, hash};

use bitcoin::hashes::Hash;
use elements::script::Builder;
use elements::{secp256k1_zkp, Transaction, TxOut};

use crate::expression::Tree;
use crate::interpreter::{self, Stack};
use crate::miniscript::context::ScriptContextError;
use crate::miniscript::lex::TokenIter;
use crate::miniscript::satisfy::Satisfaction;
use crate::miniscript::types::{Correctness, ExtData, Malleability};
use crate::policy::Liftable;
use crate::{policy, Error, ExtTranslator, MiniscriptKey, Satisfier, ToPublicKey, TranslateExt};

#[allow(unused_imports)]
mod arith;
mod csfs;
mod index_ops;
mod introspect_ops;
mod outputs_pref;
pub mod param;
mod tx_ver;

pub use arith::{Arith, EvalError, Expr, ExprInner};
pub use csfs::{CheckSigFromStack, CsfsKey, CsfsMsg};
pub use index_ops::IdxExpr;
pub use introspect_ops::{AssetExpr, CovOps, Spk, SpkExpr, ValueExpr};

pub use self::outputs_pref::LegacyOutputsPref;
pub use self::param::{ArgFromStr, CovExtArgs, ExtParam, NoExtParam};
pub use self::tx_ver::LegacyVerEq;

/// Extensions to elements-miniscript.
/// Refer to implementations(unimplemented!) for example and tutorials
pub trait Extension: Clone + Eq + Ord + fmt::Debug + fmt::Display + hash::Hash {
    /// Calculate the correctness property for the leaf fragment.
    /// See miniscript reference for more info on different types
    fn corr_prop(&self) -> Correctness;

    /// Calculate the malleability property for the leaf fragment.
    /// See miniscript reference for more info on different types
    fn mall_prop(&self) -> Malleability;

    /// Calculate the Extra properties property for the leaf fragment.
    /// See current implementation for different fragments in extra_props.rs
    fn extra_prop(&self) -> ExtData;

    /// Get the script size of the current fragment
    fn script_size(&self) -> usize;

    /// Validity rules for fragment in segwit context
    fn segwit_ctx_checks(&self) -> Result<(), ScriptContextError>;

    /// Validity rules for fragment in tap context
    fn tap_ctx_checks(&self) -> Result<(), ScriptContextError> {
        Ok(())
    }

    /// Create an instance of this object from a Tree with root name and children as
    /// `Vec<Tree>`.
    // Ideally, we would want a FromTree implementation here, but that is not possible
    // as we would need to create a new Tree by removing wrappers from root.
    fn from_name_tree(_name: &str, children: &[Tree<'_>]) -> Result<Self, ()>;
}

/// Support for parsing/serializing/satisfaction of extensions.
/// [`Extension`] trait reasons about extension in abstract way whereas
/// this trait reasons about the concrete data structures.
/// Extension is similar to [`MiniscriptKey`], whereas ParseableExt is similar to
/// [`ToPublicKey`].
//
// Come up with better name for this trait
pub trait ParseableExt:
    Extension + Clone + Eq + Ord + fmt::Debug + fmt::Display + hash::Hash
{
    /// Parse the terminal from [`TokenIter`]. Implementers of this trait are responsible
    /// for making sure tokens is mutated correctly. If parsing is not successful, the tokens
    /// should not be consumed.
    fn from_token_iter(_tokens: &mut TokenIter<'_>) -> Result<Self, ()>;

    /// Interpreter support
    /// Evaluate the fragment based on inputs from stack. If an implementation of this
    /// is provided the user can use the interpreter API to parse scripts from blockchain
    /// and check which constraints are satisfied
    /// Output Ok(true) when the ext fragment is satisfied.
    /// Output Ok(false) when the ext fragment is dissatisfied,
    /// Output Some(Err) when there is an error in interpreter value.
    fn evaluate<'intp, 'txin>(
        &'intp self,
        stack: &mut Stack<'txin>,
        txenv: Option<&TxEnv>,
    ) -> Result<bool, interpreter::Error>;

    /// Encoding of the current fragment
    fn push_to_builder(&self, builder: Builder) -> Builder;

    /// Produce a satisfaction for this from satisfier.
    /// See satisfaction code in satisfy.rs for example
    /// Note that the [`Satisfaction`] struct also covers the case when
    /// satisfaction is impossible/unavailable
    fn satisfy<Pk, S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>;

    /// Produce a satisfaction for this from satisfier.
    /// See satisfaction code in satisfy.rs for example
    /// Note that the [`Satisfaction`] struct also covers the case when
    /// dissatisfaction is impossible/unavailable
    fn dissatisfy<Pk, S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>;
}

/// No Extensions for elements-miniscript
/// All the implementations for the this function are unreachable
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub enum NoExt {}

impl Extension for NoExt {
    fn corr_prop(&self) -> Correctness {
        match *self {}
    }

    fn mall_prop(&self) -> Malleability {
        match *self {}
    }

    fn extra_prop(&self) -> ExtData {
        match *self {}
    }

    fn script_size(&self) -> usize {
        match *self {}
    }

    fn from_name_tree(_name: &str, _children: &[Tree<'_>]) -> Result<Self, ()> {
        // No extensions should not parse any extensions from String
        Err(())
    }

    fn segwit_ctx_checks(&self) -> Result<(), ScriptContextError> {
        Ok(())
    }
}

impl ParseableExt for NoExt {
    fn satisfy<Pk, S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        match *self {}
    }

    fn dissatisfy<Pk, S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        match *self {}
    }

    fn evaluate<'intp, 'txin>(
        &'intp self,
        _stack: &mut Stack<'txin>,
        _txenv: Option<&TxEnv>,
    ) -> Result<bool, interpreter::Error> {
        match *self {}
    }

    fn push_to_builder(&self, _builder: Builder) -> Builder {
        match *self {}
    }

    fn from_token_iter(_tokens: &mut TokenIter<'_>) -> Result<Self, ()> {
        // No extensions should return Err on parsing
        Err(())
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for NoExt {
    fn lift(&self) -> Result<policy::Semantic<Pk>, Error> {
        match *self {}
    }
}

impl fmt::Display for NoExt {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}

impl<PExt, QExt> TranslateExt<PExt, QExt> for NoExt
where
    PExt: Extension,
    QExt: Extension,
{
    type Output = NoExt;

    fn translate_ext<T, E>(&self, _t: &mut T) -> Result<Self::Output, E>
    where
        T: ExtTranslator<PExt, QExt, E>,
    {
        match *self {}
    }
}

/// All known Extensions for elements-miniscript
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum CovenantExt<T: ExtParam> {
    /// Version Equal
    LegacyVerEq(LegacyVerEq),
    /// Outputs Prefix equal
    LegacyOutputsPref(LegacyOutputsPref),
    /// CSFS
    Csfs(CheckSigFromStack<T>),
    /// Arith opcodes
    Arith(Arith<T>),
    /// Cov opcodes
    Introspect(CovOps<T>),
}

// Apply the function on each arm
macro_rules! all_arms_fn {
    ($slf: ident, $trt: ident, $f: ident, $($args:ident, )* ) => {
        match $slf {
            CovenantExt::LegacyVerEq(v) => <LegacyVerEq as $trt>::$f(v, $($args, )*),
            CovenantExt::LegacyOutputsPref(p) => <LegacyOutputsPref as $trt>::$f(p, $($args, )*),
            CovenantExt::Csfs(csfs) => csfs.$f($($args, )*),
            CovenantExt::Arith(e) => e.$f($($args, )*),
            CovenantExt::Introspect(e) => e.$f($($args, )*),
        }
    };
}

// try all extensions one by one
// Self::$f(args)
macro_rules! try_from_arms {
    ( $trt: ident, $ext_arg: ident, $f: ident, $($args: ident, )*) => {
        if let Ok(v) = <LegacyVerEq as $trt>::$f($($args, )*) {
            Ok(CovenantExt::LegacyVerEq(v))
        } else if let Ok(v) = <LegacyOutputsPref as $trt>::$f($($args, )*) {
            Ok(CovenantExt::LegacyOutputsPref(v))
        } else if let Ok(v) = <CheckSigFromStack<$ext_arg> as $trt>::$f($($args, )*) {
            Ok(CovenantExt::Csfs(v))
        } else if let Ok(v) = <Arith<$ext_arg> as $trt>::$f($($args, )*) {
            Ok(CovenantExt::Arith(v))
        } else if let Ok(v) = <CovOps<$ext_arg> as $trt>::$f($($args, )*) {
            Ok(CovenantExt::Introspect(v))
        }else {
            Err(())
        }
    };
}

impl<T: ExtParam> Extension for CovenantExt<T> {
    fn corr_prop(&self) -> Correctness {
        all_arms_fn!(self, Extension, corr_prop,)
    }

    fn mall_prop(&self) -> Malleability {
        all_arms_fn!(self, Extension, mall_prop,)
    }

    fn extra_prop(&self) -> ExtData {
        all_arms_fn!(self, Extension, extra_prop,)
    }

    fn script_size(&self) -> usize {
        all_arms_fn!(self, Extension, script_size,)
    }

    fn from_name_tree(name: &str, children: &[Tree<'_>]) -> Result<Self, ()> {
        try_from_arms!(Extension, T, from_name_tree, name, children,)
    }

    fn segwit_ctx_checks(&self) -> Result<(), ScriptContextError> {
        all_arms_fn!(self, Extension, segwit_ctx_checks,)
    }
}

impl ParseableExt for CovenantExt<CovExtArgs> {
    fn satisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        all_arms_fn!(self, ParseableExt, satisfy, sat,)
    }

    fn dissatisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        all_arms_fn!(self, ParseableExt, dissatisfy, sat,)
    }

    fn evaluate<'intp, 'txin>(
        &self,
        stack: &mut Stack<'txin>,
        txenv: Option<&TxEnv>,
    ) -> Result<bool, interpreter::Error> {
        all_arms_fn!(self, ParseableExt, evaluate, stack, txenv,)
    }

    fn push_to_builder(&self, builder: Builder) -> Builder {
        all_arms_fn!(self, ParseableExt, push_to_builder, builder,)
    }

    fn from_token_iter(tokens: &mut TokenIter<'_>) -> Result<Self, ()> {
        try_from_arms!(ParseableExt, CovExtArgs, from_token_iter, tokens,)
    }
}

impl<T: ExtParam> fmt::Display for CovenantExt<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CovenantExt::LegacyVerEq(v) => v.fmt(f),
            CovenantExt::LegacyOutputsPref(p) => p.fmt(f),
            CovenantExt::Csfs(c) => c.fmt(f),
            CovenantExt::Arith(e) => e.fmt(f),
            CovenantExt::Introspect(e) => e.fmt(f),
        }
    }
}

impl<PArg, QArg> TranslateExt<CovenantExt<PArg>, CovenantExt<QArg>> for CovenantExt<PArg>
where
    CovenantExt<PArg>: Extension,
    CovenantExt<QArg>: Extension,
    PArg: ExtParam,
    QArg: ExtParam,
{
    type Output = CovenantExt<QArg>;

    fn translate_ext<T, E>(&self, t: &mut T) -> Result<Self::Output, E>
    where
        T: ExtTranslator<CovenantExt<PArg>, CovenantExt<QArg>, E>,
    {
        t.ext(self)
    }
}

/// A satisfier for Covenant descriptors
/// that can do transaction introspection
/// 'tx denotes the lifetime of the transaction
/// being satisfied and 'ptx denotes the lifetime
/// of the previous transaction inputs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEnv<'tx, 'ptx> {
    /// The transaction being spent
    tx: &'tx Transaction,
    /// Spent utxos
    spent_utxos: &'ptx [TxOut],
    /// The input index being spent
    idx: usize,
}

impl<'tx, 'ptx> TxEnv<'tx, 'ptx> {
    /// Returns None when spent_utos.len() != tx.input.len()
    pub fn new(tx: &'tx Transaction, spent_utxos: &'ptx [TxOut], idx: usize) -> Option<Self> {
        if tx.input.len() != spent_utxos.len() {
            None
        } else {
            Some(Self {
                tx,
                spent_utxos,
                idx,
            })
        }
    }

    /// Obtains the tx
    pub fn tx(&self) -> &Transaction {
        self.tx
    }

    /// Obtains the spend utxos
    pub fn spent_utxos(&self) -> &[TxOut] {
        self.spent_utxos
    }

    /// Obtains the current input index
    pub fn idx(&self) -> usize {
        self.idx
    }
}

impl<'tx, 'ptx, Pk: ToPublicKey> Satisfier<Pk> for TxEnv<'tx, 'ptx> {
    fn lookup_tx(&self) -> Option<&elements::Transaction> {
        Some(self.tx)
    }

    fn lookup_spent_utxos(&self) -> Option<&[elements::TxOut]> {
        Some(self.spent_utxos)
    }

    fn lookup_curr_inp(&self) -> Option<usize> {
        Some(self.idx)
    }
}

/// API to check sig from fragment `price_oracle_1`
pub fn check_sig_price_oracle_1<C: secp256k1_zkp::Verification>(
    secp: &secp256k1_zkp::Secp256k1<C>,
    sig: &elements::secp256k1_zkp::schnorr::Signature,
    pk: &elements::secp256k1_zkp::XOnlyPublicKey,
    timestamp: u64,
    price: u64,
) -> bool {
    let mut buf = Vec::with_capacity(16);
    buf.extend(&timestamp.to_le_bytes());
    buf.extend(&price.to_le_bytes());
    let sha_msg = elements::hashes::sha256::Hash::hash(&buf);

    let msg = elements::secp256k1_zkp::Message::from_slice(&sha_msg[..]).unwrap();
    secp.verify_schnorr(&sig, &msg, &pk).is_ok()
}

/// [`secp256k1_zkp::Message`] for fragment `price_oracle_1`.
/// To be used in for signing with schnorr signatures.
pub fn sighash_msg_price_oracle_1(timestamp: u64, price: u64) -> secp256k1_zkp::Message {
    let mut buf = Vec::with_capacity(16);
    buf.extend(&timestamp.to_le_bytes());
    buf.extend(&price.to_le_bytes());
    let sha_msg = elements::hashes::sha256::Hash::hash(&buf);

    elements::secp256k1_zkp::Message::from_slice(&sha_msg[..]).unwrap()
}
