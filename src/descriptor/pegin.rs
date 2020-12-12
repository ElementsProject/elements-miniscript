// Miniscript
// Written in 2018 by
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

//! Legacy Pegin Descriptor Support
//!
//! Traits and implementations for Legacy Pegin descriptors
//! Note that this is a bitcoin descriptor and thus cannot be
//! added to elements Descriptor. Upstream rust-miniscript does
//! has a Descriptor enum which should ideally have it, but
//! bitcoin descriptors cannot depend on elements descriptors
//! Thus, as a simple solution we implement these as a separate
//! struct with it's own API.

use bitcoin;
use bitcoin::Address as BtcAddress;
use bitcoin::Script as BtcScript;
use std::{fmt::Debug, fmt::Display, str::FromStr};
use Descriptor;
use Error;
use {BtcDescriptor, BtcLiftable, BtcSatisfier};
use {MiniscriptKey, ToPublicKey};

/// A general trait for Bitcoin descriptor
/// We want the descriptor to support the sanity_checks, address
/// creations, script code etc.
/// It should also support FromStr, fmt::Display and should be liftable
/// to bitcoin Semantic Policy
// Unfortunately, the translation function cannot be added to trait
// because of traits cannot know underlying generic of Self.
// Thus, we must remember to also implement a translate function
// whenever we create a new descriptor.
pub trait PeginDescriptor<Pk: MiniscriptKey>:
    FromStr + Display + Debug + Clone + Eq + PartialEq + PartialOrd + Ord + BtcLiftable<Pk>
{
    /// Sanity check for resource limits, timelock mixes etc.
    fn sanity_check(&self) -> Result<(), Error>;

    /// Compute the bitcoin address for the descriptor
    fn address<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> Option<BtcAddress>
    where
        Pk: ToPublicKey<ToPkCtx>;
    /// Compute the bitcoin script_pubkey
    fn script_pubkey<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> Option<BtcScript>
    where
        Pk: ToPublicKey<ToPkCtx>;

    /// Unsigned script_sig, script sig that will be used in unsigned input when
    /// spending this descriptor
    fn unsigned_script_sig<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>;

    /// Computes the "witness script" of the descriptor, i.e. the underlying
    /// script before any hashing is done. For `Bare`, `Pkh` and `Wpkh` this
    /// is the scriptPubkey; for `ShWpkh` and `Sh` this is the redeemScript;
    /// for the others it is the witness script.
    fn witness_script<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>;

    /// Get a satisfaction for the descriptor
    fn get_satisfication<ToPkCtx, S>(
        &self,
        satisfier: S,
        to_pk_ctx: ToPkCtx,
    ) -> Result<(Vec<Vec<u8>>, BtcScript), Error>
    where
        ToPkCtx: Copy,
        Pk: ToPublicKey<ToPkCtx>,
        S: BtcSatisfier<ToPkCtx, Pk>;

    /// Attempts to produce a satisfying witness and scriptSig to spend an
    /// output controlled by the given descriptor; add the data to a given
    /// bitcoin `TxIn` output.
    fn satisfy<ToPkCtx, S>(
        &self,
        txin: &mut bitcoin::TxIn,
        satisfier: S,
        to_pk_ctx: ToPkCtx,
    ) -> Result<(), Error>
    where
        ToPkCtx: Copy,
        Pk: ToPublicKey<ToPkCtx>,
        S: BtcSatisfier<ToPkCtx, Pk>,
    {
        // easy default implementation
        let (witness, script_sig) = self.get_satisfication(satisfier, to_pk_ctx)?;
        txin.witness = witness;
        txin.script_sig = script_sig;
        Ok(())
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction. Assumes all signatures are 73 bytes, including push opcode
    /// and sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    fn max_satisfaction_weight<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> Option<usize>
    where
        Pk: ToPublicKey<ToPkCtx>;

    /// The script code used in sighash
    fn script_code<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>;
}

/// Legacy Pegin Descriptor
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct LegacyPegin<Pk: MiniscriptKey> {
    /// The federation pks
    pub fed_pks: Vec<Pk>,
    /// The emergency pks
    pub emergency_pks: Vec<Pk>,
    /// The elements descriptor required to redeem
    pub desc: Descriptor<Pk>,
}

impl<Pk: MiniscriptKey> LegacyPegin<Pk> {
    /// Create a new LegacyPegin descriptor
    pub fn new(fed_pks: Vec<Pk>, emergency_pks: Vec<Pk>, desc: Descriptor<Pk>) -> Self {
        Self {
            fed_pks,
            emergency_pks,
            desc,
        }
    }

    /// Create a new descriptor with hard coded values for the
    /// legacy federation and emergency keys
    pub fn new_legacy_fed(_desc: Descriptor<Pk>) -> Self {
        unimplemented!()
    }
}

// Implementation of Pegin Descriptor for Legacy Pegin
// impl<Pk: MiniscriptKey> PeginDescriptor<Pk> for LegacyPegin{}

/// New Pegin Descriptor with Miniscript support
/// Useful with dynamic federations
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Pegin<Pk: MiniscriptKey> {
    /// The untweaked pegin bitcoin descriptor
    pub fed_desc: BtcDescriptor<Pk>,
    /// The redeem elements descriptor
    pub elem_desc: Descriptor<Pk>,
}

impl<Pk: MiniscriptKey> Pegin<Pk> {
    /// Create a new LegacyPegin descriptor
    pub fn new(fed_desc: BtcDescriptor<Pk>, elem_desc: Descriptor<Pk>) -> Self {
        Self {
            fed_desc,
            elem_desc,
        }
    }
}

// Implementation of PeginDescriptor for Pegin
// impl<Pk: MiniscriptKey> PeginDescriptor<Pk> for Pegin<Pk>{}
