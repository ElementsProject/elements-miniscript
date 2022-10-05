// Miniscript
// Written in 2020 by rust-miniscript developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Bare Output Descriptors
//!
//! Implementation of Bare Descriptors (i.e descriptors that are)
//! wrapped inside wsh, or sh fragments.
//! Also includes pk, and pkh descriptors
//!

use std::fmt;

use elements::{self, Script};

use super::checksum::{desc_checksum, strip_checksum, verify_checksum};
use super::{Descriptor, TranslatePk};
use crate::expression::{self, FromTree};
use crate::extensions::{CovenantExt, CovExtArgs};
use crate::policy::{semantic, Liftable};
use crate::{Error, MiniscriptKey, Satisfier, ToPublicKey, Translator};

/// Create a Bare Descriptor. That is descriptor that is
/// not wrapped in sh or wsh. This covers the Pk descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Blinded<Pk: MiniscriptKey> {
    /// The blinding key
    blinder: Pk,
    /// underlying descriptor
    /// Must be unblinded as blinding is only
    /// permitted at the root level.
    ///
    /// TODO: Add blinding support to descriptor extensions
    desc: Descriptor<Pk, CovenantExt<CovExtArgs>>,
}

impl<Pk: MiniscriptKey> Blinded<Pk> {
    /// Create a new blinded descriptor from a descriptor and blinder
    pub fn new(blinder: Pk, desc: Descriptor<Pk, CovenantExt<CovExtArgs>>) -> Self {
        Self { blinder, desc }
    }

    /// get the blinder
    pub fn blinder(&self) -> &Pk {
        &self.blinder
    }

    /// get the unblinded descriptor
    pub fn as_unblinded(&self) -> &Descriptor<Pk, CovenantExt<CovExtArgs>> {
        &self.desc
    }

    /// get the unblinded descriptor
    pub fn into_unblinded(self) -> Descriptor<Pk, CovenantExt<CovExtArgs>> {
        self.desc
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Blinded<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blinded({:?},{:?})", self.blinder, self.desc)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Blinded<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // strip thec checksum from display
        let desc = format!("{}", self.desc);
        let desc = format!("blinded({},{})", self.blinder, strip_checksum(&desc));
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Blinded<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        self.desc.lift()
    }
}

impl_from_tree!(
    Blinded<Pk>,
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        if top.name == "blinded" && top.args.len() == 2 {
            let blinder = expression::terminal(&top.args[0], |pk| Pk::from_str(pk))?;
            let desc = Descriptor::<Pk, CovenantExt<CovExtArgs>>::from_tree(&top.args[1])?;
            if top.args[1].name == "blinded" {
                return Err(Error::BadDescriptor(
                    "Blinding only permitted at root level".to_string(),
                ));
            }
            Ok(Blinded { blinder, desc })
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing sh descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
);

impl_from_str!(
    Blinded<Pk>,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(&top)
    }
);

impl<Pk: MiniscriptKey> Blinded<Pk> {
    /// Sanity checks for the underlying descriptor.
    pub fn sanity_check(&self) -> Result<(), Error> {
        self.desc.sanity_check()?;
        Ok(())
    }

    /// Obtains the blinded address for this descriptor.
    pub fn address(
        &self,
        params: &'static elements::AddressParams,
    ) -> Result<elements::Address, Error>
    where
        Pk: ToPublicKey,
    {
        self.desc
            .blinded_address(self.blinder.to_public_key().inner, params)
    }

    /// Obtains the script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.desc.script_pubkey()
    }

    /// Computes the scriptSig that will be in place for an unsigned input
    /// spending an output with this descriptor.
    pub fn unsigned_script_sig(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.desc.unsigned_script_sig()
    }

    /// Computes the the underlying script before any hashing is done.
    pub fn explicit_script(&self) -> Result<Script, Error>
    where
        Pk: ToPublicKey,
    {
        self.desc.explicit_script()
    }

    /// Returns satisfying non-malleable witness and scriptSig to spend an
    /// output controlled by the given descriptor if it possible to
    /// construct one using the satisfier S.
    pub fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        self.desc.get_satisfaction(satisfier)
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction.
    pub fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        self.desc.max_satisfaction_weight()
    }

    /// Computes the `scriptCode` of a transaction output.
    pub fn script_code(&self) -> Result<Script, Error>
    where
        Pk: ToPublicKey,
    {
        self.desc.script_code()
    }

    /// Returns a possilbly mallable satisfying non-malleable witness and scriptSig to spend an
    /// output controlled by the given descriptor if it possible to
    /// construct one using the satisfier S.
    pub fn get_satisfaction_mall<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        self.desc.get_satisfaction_mall(satisfier)
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for Blinded<P> {
    type Output = Blinded<Q>;

    fn translate_pk<T, E>(&self, t: &mut T) -> Result<Self::Output, E>
    where
        T: Translator<P, Q, E>,
    {
        Ok(Blinded::new(
            t.pk(&self.blinder)?,
            self.desc.translate_pk(t)?,
        ))
    }
}
