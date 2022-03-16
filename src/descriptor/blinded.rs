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

use std::{fmt, str::FromStr};

use bitcoin::secp256k1;
use elements::{self, Script};

use expression::{self, FromTree};
use policy::{semantic, Liftable};
use {Error, MiniscriptKey, Satisfier, ToPublicKey};

use super::{
    checksum::{desc_checksum, strip_checksum, verify_checksum},
    Descriptor, DescriptorTrait, ElementsTrait, TranslatePk,
};

/// Create a Bare Descriptor. That is descriptor that is
/// not wrapped in sh or wsh. This covers the Pk descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Blinded<Pk: MiniscriptKey> {
    /// The blinding key
    blinder: Pk,
    /// underlying descriptor
    /// Must be unblinded as blinding is only
    /// permitted at the root level.
    desc: Descriptor<Pk>,
}

impl<Pk: MiniscriptKey> Blinded<Pk> {
    /// Create a new blinded descriptor from a descriptor and blinder
    pub fn new(blinder: Pk, desc: Descriptor<Pk>) -> Self {
        Self { blinder, desc }
    }

    /// get the blinder
    pub fn blinder(&self) -> &Pk {
        &self.blinder
    }

    /// get the unblinded descriptor
    pub fn as_unblinded(&self) -> &Descriptor<Pk> {
        &self.desc
    }

    /// get the unblinded descriptor
    pub fn into_unblinded(self) -> Descriptor<Pk> {
        self.desc
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Blinded<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "blinded({:?},{:?})", self.blinder, self.desc)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Blinded<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

impl<Pk: MiniscriptKey> FromTree for Blinded<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "blinded" && top.args.len() == 2 {
            let blinder = expression::terminal(&top.args[0], |pk| Pk::from_str(pk))?;
            let desc = Descriptor::<Pk>::from_tree(&top.args[1])?;
            if top.args[1].name == "blinded" {
                return Err(Error::BadDescriptor(format!(
                    "Blinding only permitted at root level"
                )));
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
}

impl<Pk: MiniscriptKey> FromStr for Blinded<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> ElementsTrait<Pk> for Blinded<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    /// Overides the blinding key in descriptor with the one
    /// provided in the argument.
    fn blind_addr(
        &self,
        blinder: Option<secp256k1::PublicKey>,
        params: &'static elements::AddressParams,
    ) -> Result<elements::Address, Error>
    where
        Pk: ToPublicKey,
    {
        self.desc.blind_addr(blinder, params)
    }
}

impl<Pk: MiniscriptKey> DescriptorTrait<Pk> for Blinded<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn sanity_check(&self) -> Result<(), Error> {
        self.desc.sanity_check()?;
        Ok(())
    }

    fn address(&self, params: &'static elements::AddressParams) -> Result<elements::Address, Error>
    where
        Pk: ToPublicKey,
    {
        self.desc
            .blind_addr(Some(self.blinder.to_public_key().inner), params)
    }

    fn script_pubkey(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.desc.script_pubkey()
    }

    fn unsigned_script_sig(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.desc.unsigned_script_sig()
    }

    fn explicit_script(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.desc.explicit_script()
    }

    fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        self.desc.get_satisfaction(satisfier)
    }

    fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        self.desc.max_satisfaction_weight()
    }

    fn script_code(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.script_pubkey()
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for Blinded<P> {
    type Output = Blinded<Q>;

    fn translate_pk<Fpk, Fpkh, E>(
        &self,
        mut translatefpk: Fpk,
        mut translatefpkh: Fpkh,
    ) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        Ok(Blinded::new(
            translatefpk(&self.blinder)?,
            self.desc
                .translate_pk(&mut translatefpk, &mut translatefpkh)?,
        ))
    }
}
