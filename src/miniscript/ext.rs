//! Extensions to elements-miniscript
//! Users should implement the [`Extension`] trait to extend miniscript to have newer leaf nodes
//! Look at examples for implementation of ver_eq fragment

// use elements::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
// use std::marker::PhantomData;
// use {bitcoin, Miniscript};

use std::{fmt, hash};

use elements::script::Builder;
use miniscript::{ForEach, TranslatePk};
// use miniscript::lex::{Token as Tk, TokenIter};
// use miniscript::types::extra_props::ExtData;
// use miniscript::types::Property;
// use miniscript::types::Type;
// use std::sync::Arc;
// use Error;
use policy;
use Error;
use MiniscriptKey;
use ToPublicKey;

use {expression::Tree, policy::Liftable, Satisfier};

use super::{
    context::ScriptContextError,
    lex::TokenIter,
    satisfy::Satisfaction,
    types::{Correctness, ExtData, Malleability},
};

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
        Pk::Hash: 'a,
    {
        false
    }

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
    fn from_name_tree(_name: &str, _child: &Vec<Tree>) -> Result<Self, ()>;
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

    fn from_name_tree(_name: &str, _child: &Vec<Tree>) -> Result<Self, ()> {
        // No extensions should not parse any extensions from String
        Err(())
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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub struct AllExt;

impl<Pk> Extension<Pk> for AllExt
where
    Pk: MiniscriptKey,
{
    fn corr_prop(&self) -> Correctness {
        unimplemented!()
    }

    fn mall_prop(&self) -> Malleability {
        unimplemented!()
    }

    fn extra_prop(&self) -> ExtData {
        unimplemented!()
    }

    fn satisfy<S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        unimplemented!()
    }

    fn dissatisfy<S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        unimplemented!()
    }

    fn real_for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, _pred: &mut F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        unimplemented!()
    }

    fn push_to_builder(&self, _builder: Builder) -> Builder
    where
        Pk: ToPublicKey,
    {
        unimplemented!()
    }

    fn script_size(&self) -> usize {
        unimplemented!()
    }

    fn from_token_iter(_tokens: &mut TokenIter) -> Result<Self, ()> {
        Err(())
    }

    fn from_name_tree(_name: &str, _child: &Vec<Tree>) -> Result<Self, ()> {
        Err(())
    }
}

impl fmt::Display for AllExt {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for AllExt {
    fn lift(&self) -> Result<policy::Semantic<Pk>, Error> {
        unimplemented!()
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for AllExt {
    type Output = AllExt;

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
        unimplemented!()
    }
}
