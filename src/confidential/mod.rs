// Miniscript
// Written in 2022 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Confidential Descriptors
//!
//! Implements ELIP ????, described at `URL`
//!

pub mod bare;
pub mod slip77;

use std::fmt;

use elements::secp256k1_zkp;

use crate::descriptor::checksum::{desc_checksum, verify_checksum};
use crate::expression::FromTree;
use crate::extensions::{CovExtArgs, CovenantExt, Extension, ParseableExt};
use crate::{expression, Error, MiniscriptKey, ToPublicKey};

/// A description of a blinding key
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Key<Pk: MiniscriptKey> {
    /// Blinding key is computed using SLIP77 with the given master key
    Slip77(slip77::MasterBlindingKey),
    /// Blinding key is given directly
    Bare(Pk),
}

impl<Pk: MiniscriptKey> fmt::Display for Key<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Key::Slip77(data) => write!(f, "slip77({})", data),
            Key::Bare(pk) => fmt::Display::fmt(pk, f),
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Key<Pk> {
    fn to_public_key<C: secp256k1_zkp::Signing + secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
        spk: &elements::Script,
    ) -> secp256k1_zkp::PublicKey {
        match *self {
            Key::Slip77(ref mbk) => mbk.blinding_key(secp, spk),
            Key::Bare(ref pk) => bare::tweak_key(secp, spk, pk),
        }
    }
}

/// A confidential descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Descriptor<Pk: MiniscriptKey, T: Extension = CovenantExt<CovExtArgs>> {
    /// The blinding key
    pub key: Key<Pk>,
    /// The script descriptor
    pub descriptor: crate::Descriptor<Pk, T>,
}

impl<Pk: MiniscriptKey, T: Extension> Descriptor<Pk, T> {
    /// Sanity checks for the underlying descriptor.
    pub fn sanity_check(&self) -> Result<(), Error> {
        self.descriptor.sanity_check()?;
        Ok(())
    }
}

impl<Pk: MiniscriptKey + ToPublicKey, T: Extension + ParseableExt> Descriptor<Pk, T> {
    /// Obtains the unblinded address for this descriptor.
    pub fn unconfidential_address(
        &self,
        params: &'static elements::AddressParams,
    ) -> Result<elements::Address, Error> {
        self.descriptor.address(params)
    }

    /// Obtains the blinded address for this descriptor.
    pub fn address<C: secp256k1_zkp::Signing + secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
        params: &'static elements::AddressParams,
    ) -> Result<elements::Address, Error> {
        let spk = self.descriptor.script_pubkey();
        self.descriptor
            .blinded_address(self.key.to_public_key(secp, &spk), params)
    }
}

impl<Pk: MiniscriptKey, T: Extension> fmt::Display for Descriptor<Pk, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc_str = format!("ct({},{:#})", self.key, self.descriptor);
        let checksum = desc_checksum(&desc_str).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", desc_str, checksum)
    }
}

impl_from_str!(
    ;T; Extension,
    Descriptor<Pk, T>,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Descriptor<Pk, T>, Error> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;

        if top.name != "ct" {
            return Err(Error::BadDescriptor(String::from(
                "Not a CT Descriptor",
            )));
        }
        if top.args.len() != 2 {
            return Err(Error::BadDescriptor(
                format!("CT descriptor had {} arguments rather than 2", top.args.len())
            ));
        }

        let keyexpr = &top.args[0];
        Ok(Descriptor {
            key: match (keyexpr.name, keyexpr.args.len()) {
                ("slip77", 1) => Key::Slip77(expression::terminal(&keyexpr.args[0], slip77::MasterBlindingKey::from_str)?),
                ("slip77", _) => return Err(Error::BadDescriptor(
                    "slip77() must have exactly one argument".to_owned()
                )),
                _ => Key::Bare(expression::terminal(keyexpr, Pk::from_str)?),
            },
            descriptor: crate::Descriptor::from_tree(&top.args[1])?,
        })
    }
);
