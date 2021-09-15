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

use crate::{policy::Liftable, Satisfier};

use super::{
    satisfy::Satisfaction,
    types::{Correctness, ExtData, Malleability},
};

/// Extensions to elements-miniscript.
/// Refer to implementations(todo!) for example and tutorials
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
        todo!()
    }

    fn mall_prop(&self) -> Malleability {
        todo!()
    }

    fn extra_prop(&self) -> ExtData {
        todo!()
    }

    fn satisfy<S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        todo!()
    }

    fn dissatisfy<S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        todo!()
    }

    fn real_for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, _pred: &mut F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        todo!()
    }

    fn push_to_builder(&self, _builder: Builder) -> Builder
    where
        Pk: ToPublicKey,
    {
        todo!()
    }

    fn script_size(&self) -> usize {
        todo!()
    }
}

impl fmt::Display for AllExt {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for AllExt {
    fn lift(&self) -> Result<policy::Semantic<Pk>, Error> {
        todo!()
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
        todo!()
    }
}
