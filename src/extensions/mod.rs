//! Extensions to elements-miniscript
//! Users should implement the [`Extension`] trait to extend miniscript to have newer leaf nodes
//! Look at examples for implementation of ver_eq fragment

use std::{fmt, hash};

use elements::script::Builder;
use policy;
use Error;
use MiniscriptKey;
use ToPublicKey;
use {ForEach, TranslatePk};

use {expression::Tree, policy::Liftable, Satisfier};

use miniscript::{
    context::ScriptContextError,
    lex::TokenIter,
    satisfy::Satisfaction,
    types::{Correctness, ExtData, Malleability},
};

use interpreter::{self, Stack};
mod outputs_pref;
mod tx_ver;
pub use self::outputs_pref::OutputsPref;
pub use self::tx_ver::VerEq;

/// Extensions to elements-miniscript.
/// Refer to implementations(unimplemented!) for example and tutorials
pub trait Extension<Pk: MiniscriptKey>:
    Clone + Eq + Ord + fmt::Debug + fmt::Display + hash::Hash + Liftable<Pk>
{
    /// Calculate the correctness property for the leaf fragment.
    /// See miniscript reference for more info on different types
    fn corr_prop(&self) -> Correctness;

    /// Calculate the malleability property for the leaf fragment.
    /// See miniscript reference for more info on different types
    fn mall_prop(&self) -> Malleability;

    /// Calculate the Extra properties property for the leaf fragment.
    /// See current implementation for different fragments in extra_props.rs
    fn extra_prop(&self) -> ExtData;

    /// Produce a satisfaction for this from satisfier.
    /// See satisfaction code in satisfy.rs for example
    /// Note that the [`Satisfaction`] struct also covers the case when
    /// satisfaction is impossible/unavailable
    fn satisfy<S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>;

    /// Produce a satisfaction for this from satisfier.
    /// See satisfaction code in satisfy.rs for example
    /// Note that the [`Satisfaction`] struct also covers the case when
    /// dissatisfaction is impossible/unavailable
    fn dissatisfy<S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>;

    /// Check if the predicate holds for all keys
    fn real_for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, _pred: &mut F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a;

    /// Encoding of the current fragment
    fn push_to_builder(&self, builder: Builder) -> Builder
    where
        Pk: ToPublicKey;

    /// Get the script size of the current fragment
    fn script_size(&self) -> usize;

    /// Validity rules for fragment in segwit context
    fn segwit_ctx_checks(&self) -> Result<(), ScriptContextError> {
        Ok(())
    }

    //unimplemented: Add checks after we introduce Tap ctx

    /// Parse the terminal from [`TokenIter`]. Implementers of this trait are responsible
    /// for making sure tokens is mutated correctly. If parsing is not successful, the tokens
    /// should not be consumed.
    fn from_token_iter(_tokens: &mut TokenIter) -> Result<Self, ()>;

    /// Create an instance of this object from a Tree with root name and children as
    /// Vec<Tree>.
    // Ideally, we would want a FromTree implementation here, but that is not possible
    // as we would need to create a new Tree by removing wrappers from root.
    fn from_name_tree(_name: &str, children: &[Tree]) -> Result<Self, ()>;

    /// Interpreter support
    /// Evaluate the fragment based on inputs from stack. If an implementation of this
    /// is provided the user can use the interpreter API to parse scripts from blockchain
    /// and check which constraints are satisfied
    /// Output [`None`] when the ext fragment is dissatisfied, output Some(Err) when there is
    /// an error in interpreter value. Finally, if the evaluation is successful output Some(Ok())
    /// After taproot this should also access to the transaction data
    fn evaluate<'intp, 'txin>(
        &'intp self,
        stack: &mut Stack<'txin>,
    ) -> Option<Result<(), interpreter::Error>>;
}

/// No Extensions for elements-miniscript
/// All the implementations for the this function are unreachable
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub struct NoExt;

impl<Pk: MiniscriptKey> Extension<Pk> for NoExt {
    fn corr_prop(&self) -> Correctness {
        unreachable!()
    }

    fn mall_prop(&self) -> Malleability {
        unreachable!()
    }

    fn extra_prop(&self) -> ExtData {
        unreachable!()
    }

    fn satisfy<S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        unreachable!()
    }

    fn dissatisfy<S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        unreachable!()
    }

    fn real_for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, _pred: &mut F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        unreachable!()
    }

    fn push_to_builder(&self, _builder: Builder) -> Builder
    where
        Pk: ToPublicKey,
    {
        unreachable!()
    }

    fn script_size(&self) -> usize {
        unreachable!()
    }

    fn from_token_iter(_tokens: &mut TokenIter) -> Result<Self, ()> {
        // No extensions should return Err on parsing
        Err(())
    }

    fn from_name_tree(_name: &str, _children: &[Tree]) -> Result<Self, ()> {
        // No extensions should not parse any extensions from String
        Err(())
    }

    fn evaluate<'intp, 'txin>(
        &'intp self,
        _stack: &mut Stack<'txin>,
    ) -> Option<Result<(), interpreter::Error>> {
        unreachable!()
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for NoExt {
    fn lift(&self) -> Result<policy::Semantic<Pk>, Error> {
        unreachable!()
    }
}

impl fmt::Display for NoExt {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unreachable!()
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for NoExt {
    type Output = NoExt;

    fn translate_pk<Fpk, Fpkh, E>(
        &self,
        mut _translatefpk: Fpk,
        _translatefpkh: Fpkh,
    ) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        unreachable!()
    }
}

/// All known Extensions for elements-miniscript
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum AllExt {
    /// Version Equal
    VerEq(VerEq),
    /// Outputs Prefix equal
    OutputsPref(OutputsPref),
}

// Apply the function on each arm
macro_rules! all_arms_fn {
    ($slf: ident, $f: ident, $($args:ident, )* ) => {
        match $slf {
            AllExt::VerEq(v) => <VerEq as Extension<Pk>>::$f(v, $($args, )*),
            AllExt::OutputsPref(p) => <OutputsPref as Extension<Pk>>::$f(p, $($args, )*),
        }
    };
}

// try all extensions one by one
// Self::$f(args)
macro_rules! try_from_arms {
    ($f: ident, $($args: ident, )*) => {
        if let Ok(v) = <VerEq as Extension<Pk>>::$f($($args, )*) {
            Ok(AllExt::VerEq(v))
        } else if let Ok(v) = <OutputsPref as Extension<Pk>>::$f($($args, )*) {
            Ok(AllExt::OutputsPref(v))
        } else {
            Err(())
        }
    };
}

impl<Pk> Extension<Pk> for AllExt
where
    Pk: MiniscriptKey,
{
    fn corr_prop(&self) -> Correctness {
        all_arms_fn!(self, corr_prop,)
    }

    fn mall_prop(&self) -> Malleability {
        all_arms_fn!(self, mall_prop,)
    }

    fn extra_prop(&self) -> ExtData {
        all_arms_fn!(self, extra_prop,)
    }

    fn satisfy<S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        all_arms_fn!(self, satisfy, sat,)
    }

    fn dissatisfy<S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        all_arms_fn!(self, dissatisfy, sat,)
    }

    fn real_for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, pred: &mut F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        all_arms_fn!(self, real_for_each_key, pred,)
    }

    fn push_to_builder(&self, builder: Builder) -> Builder
    where
        Pk: ToPublicKey,
    {
        all_arms_fn!(self, push_to_builder, builder,)
    }

    fn script_size(&self) -> usize {
        all_arms_fn!(self, script_size,)
    }

    fn from_token_iter(tokens: &mut TokenIter) -> Result<Self, ()> {
        try_from_arms!(from_token_iter, tokens,)
    }

    fn from_name_tree(name: &str, children: &[Tree]) -> Result<Self, ()> {
        try_from_arms!(from_name_tree, name, children,)
    }

    fn evaluate<'intp, 'txin>(
        &'intp self,
        stack: &mut Stack<'txin>,
    ) -> Option<Result<(), interpreter::Error>> {
        all_arms_fn!(self, evaluate, stack,)
    }
}

impl fmt::Display for AllExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllExt::VerEq(v) => v.fmt(f),
            AllExt::OutputsPref(p) => p.fmt(f),
        }
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for AllExt {
    fn lift(&self) -> Result<policy::Semantic<Pk>, Error> {
        match self {
            AllExt::VerEq(v) => v.lift(),
            AllExt::OutputsPref(p) => p.lift(),
        }
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for AllExt {
    type Output = AllExt;

    fn translate_pk<Fpk, Fpkh, E>(
        &self,
        translatefpk: Fpk,
        translatefpkh: Fpkh,
    ) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        let ext = match self {
            AllExt::VerEq(v) => AllExt::VerEq(v.translate_pk(translatefpk, translatefpkh)?),
            AllExt::OutputsPref(p) => {
                AllExt::OutputsPref(p.translate_pk(translatefpk, translatefpkh)?)
            }
        };
        Ok(ext)
    }
}
