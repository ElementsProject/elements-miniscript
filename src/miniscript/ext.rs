//! Extensions to elements-miniscript
//! Users should implement the [`Extension`] trait to extend miniscript to have newer leaf nodes
//! Look at examples for implementation of ver_eq fragment

// use elements::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
// use std::marker::PhantomData;
// use {bitcoin, Miniscript};

use std::{fmt, hash};

// use miniscript::lex::{Token as Tk, TokenIter};
// use miniscript::types::extra_props::ExtData;
// use miniscript::types::Property;
// use miniscript::types::Type;
// use std::sync::Arc;
// use Error;
use MiniscriptKey;

use super::types::{Correctness, ExtData, Malleability};

/// Extensions to elements-miniscript.
pub trait Extension<Pk: MiniscriptKey>:
    Clone + Eq + Ord + fmt::Debug + fmt::Display + hash::Hash
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
}

/// No Extensions for elements-miniscript
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
}

impl fmt::Display for NoExt {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unreachable!()
    }
}

/// All known Extensions for elements-miniscript
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub struct AllExt;

impl<Pk: MiniscriptKey> Extension<Pk> for AllExt {
    fn corr_prop(&self) -> Correctness {
        todo!()
    }

    fn mall_prop(&self) -> Malleability {
        todo!()
    }

    fn extra_prop(&self) -> ExtData {
        todo!()
    }
}

impl fmt::Display for AllExt {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
