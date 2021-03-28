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

//! Pegin Descriptor Support
//!
//! Traits and implementations for Pegin descriptors
//! Note that this is a bitcoin descriptor and thus cannot be
//! added to elements Descriptor. Upstream rust-miniscript does
//! has a Descriptor enum which should ideally have it, but
//! bitcoin descriptors cannot depend on elements descriptors
//! Thus, as a simple solution we implement these as a separate
//! struct with it's own API.

use bitcoin::blockdata::opcodes;
use bitcoin::hashes::Hash;
use bitcoin::Script as BtcScript;
use bitcoin::{self, blockdata::script, hashes};
use bitcoin::{hashes::hash160, Address as BtcAddress};
use elements::secp256k1_zkp;
use expression::{self, FromTree};
use policy::{semantic, Liftable};
use std::{
    fmt::Debug,
    fmt::{self, Display},
    marker::PhantomData,
    str::FromStr,
    sync::Arc,
};
use Descriptor;
use Error;
use Miniscript;
use {
    BtcDescriptor, BtcDescriptorTrait, BtcError, BtcFromTree, BtcLiftable, BtcMiniscript,
    BtcPolicy, BtcSatisfier, BtcSegwitv0, BtcTerminal, BtcTree,
};

use {DescriptorTrait, Segwitv0, TranslatePk};

use {tweak_key, util::varint_len};

use super::checksum::{desc_checksum, verify_checksum};
use {MiniscriptKey, ToPublicKey};

mod dynafed_pegin;
mod legacy_pegin;
pub use self::legacy_pegin::{LegacyPegin, LegacyPeginKey};
/// A general trait for Pegin Bitcoin descriptor.
/// It should also support FromStr, fmt::Display and should be liftable
/// to bitcoin Semantic Policy.
/// Offers function for witness cost estimation, script pubkey creation
/// satisfaction using the [Satisfier] trait.
// Unfortunately, the translation function cannot be added to trait
// because of traits cannot know underlying generic of Self.
// Thus, we must implement additional trait for translate function
pub trait PeginTrait<Pk: MiniscriptKey> {
    /// Whether the descriptor is safe
    /// Checks whether all the spend paths in the descriptor are possible
    /// on the bitcoin network under the current standardness and consensus rules
    /// Also checks whether the descriptor requires signauture on all spend paths
    /// And whether the script is malleable.
    /// In general, all the guarantees of miniscript hold only for safe scripts.
    /// All the analysis guarantees of miniscript only hold safe scripts.
    /// The signer may not be able to find satisfactions even if one exists
    fn sanity_check(&self) -> Result<(), Error>;

    /// Computes the Bitcoin address of the pegin descriptor, if one exists.
    /// Requires the secp context to compute the tweak
    fn bitcoin_address<C: secp256k1_zkp::Verification>(
        &self,
        network: bitcoin::Network,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> Result<bitcoin::Address, Error>
    where
        Pk: ToPublicKey;

    /// Computes the bitcoin scriptpubkey of the descriptor.
    /// Requires the secp context to compute the tweak
    fn bitcoin_script_pubkey<C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> BtcScript
    where
        Pk: ToPublicKey;

    /// Computes the scriptSig that will be in place for an unsigned
    /// input spending an output with this descriptor. For pre-segwit
    /// descriptors, which use the scriptSig for signatures, this
    /// returns the empty script.
    ///
    /// This is used in Segwit transactions to produce an unsigned
    /// transaction whose txid will not change during signing (since
    /// only the witness data will change).
    /// Requires the secp context to compute the tweak
    fn bitcoin_unsigned_script_sig<C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> BtcScript
    where
        Pk: ToPublicKey;

    /// Computes the bitcoin "witness script" of the descriptor, i.e. the underlying
    /// script before any hashing is done. For `Bare`, `Pkh` and `Wpkh` this
    /// is the scriptPubkey; for `ShWpkh` and `Sh` this is the redeemScript;
    /// for the others it is the witness script.
    /// `to_pk_ctx` denotes the ToPkCtx required for deriving bitcoin::PublicKey
    /// from MiniscriptKey using [ToPublicKey].
    /// If MiniscriptKey is already is [bitcoin::PublicKey], then the context
    /// would be [NullCtx] and [descriptor.DescriptorPublicKeyCtx] if MiniscriptKey is [descriptor.DescriptorPublicKey]
    ///
    /// In general, this is defined by generic for the trait [ToPublicKey]
    fn bitcoin_witness_script<C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> BtcScript
    where
        Pk: ToPublicKey;

    /// Returns satisfying witness and scriptSig to spend an
    /// output controlled by the given descriptor if it possible to
    /// construct one using the satisfier S.
    /// `to_pk_ctx` denotes the ToPkCtx required for deriving bitcoin::PublicKey
    /// from MiniscriptKey using [ToPublicKey].
    /// If MiniscriptKey is already is [bitcoin::PublicKey], then the context
    /// would be [NullCtx] and [descriptor.DescriptorPublicKeyCtx] if MiniscriptKey is [descriptor.DescriptorPublicKey]
    ///
    /// In general, this is defined by generic for the trait [ToPublicKey]
    fn get_bitcoin_satisfaction<S, C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
        satisfier: S,
    ) -> Result<(Vec<Vec<u8>>, BtcScript), Error>
    where
        S: BtcSatisfier<bitcoin::PublicKey>,
        Pk: ToPublicKey;

    /// Attempts to produce a satisfying witness and scriptSig to spend an
    /// output controlled by the given descriptor; add the data to a given
    /// `TxIn` output.
    fn bitcoin_satisfy<S, C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
        txin: &mut bitcoin::TxIn,
        satisfier: S,
    ) -> Result<(), Error>
    where
        Pk: ToPublicKey,
        S: BtcSatisfier<bitcoin::PublicKey>,
    {
        // easy default implementation
        let (witness, script_sig) = self.get_bitcoin_satisfaction(secp, satisfier)?;
        txin.witness = witness;
        txin.script_sig = script_sig;
        Ok(())
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction. Assumes all signatures are 73 bytes, including push opcode
    /// and sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    fn max_satisfaction_weight(&self) -> Result<usize, Error>;

    /// Get the `scriptCode` of a transaction output.
    ///
    /// The `scriptCode` is the Script of the previous transaction output being serialized in the
    /// sighash when evaluating a `CHECKSIG` & co. OP code.
    /// `to_pk_ctx` denotes the ToPkCtx required for deriving bitcoin::PublicKey
    /// from MiniscriptKey using [ToPublicKey].
    /// If MiniscriptKey is already is [bitcoin::PublicKey], then the context
    /// would be [NullCtx] and [descriptor.DescriptorPublicKeyCtx] if MiniscriptKey is [descriptor.DescriptorPublicKey]
    ///
    /// In general, this is defined by generic for the trait [ToPublicKey]
    fn script_code<C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> BtcScript
    where
        Pk: ToPublicKey;

    /// Get the corresponding elements descriptor that would be used
    /// at redeem time by the user.
    /// Users can use the DescrpitorTrait operations on the output Descriptor
    /// to obtain the characteristics of the elements descriptor.
    fn into_user_descriptor(self) -> Descriptor<Pk>;
}
