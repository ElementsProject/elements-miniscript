// Written in 2018 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! # Satisfaction and Dissatisfaction
//!
//! Traits and implementations to support producing witnesses for Miniscript
//! scriptpubkeys.
//!

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::{cmp, mem};

use bitcoin::hashes::hash160;
use bitcoin::secp256k1::XOnlyPublicKey;
use elements::hashes::sha256d;
use elements::secp256k1_zkp::schnorr;
use elements::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use elements::{self, confidential, secp256k1_zkp, LockTime, OutPoint, Script, Sequence};

use super::context::SigType;
use crate::extensions::{CsfsMsg, ParseableExt};
use crate::util::witness_size;
use crate::{Miniscript, MiniscriptKey, ScriptContext, Terminal, ToPublicKey};

/// Type alias for a signature/hashtype pair
pub type ElementsSig = (secp256k1_zkp::ecdsa::Signature, elements::EcdsaSighashType);
/// Type alias for 32 byte Preimage.
pub type Preimage32 = [u8; 32];

/// Convert to raw sig
pub fn elementssig_to_rawsig(sig: &ElementsSig) -> Vec<u8> {
    let ser_sig = sig.0.serialize_der();
    let mut raw_sig = Vec::from(&ser_sig[..]);
    raw_sig.push(sig.1 as u8);
    raw_sig
}

/// Helper function to create ElementsSig from Rawsig
/// Useful for downstream when implementing Satisfier.
/// Returns underlying secp if the Signature is not of correct format
pub fn elementssig_from_rawsig(rawsig: &[u8]) -> Result<ElementsSig, crate::interpreter::Error> {
    let (flag, sig) = rawsig.split_last().unwrap();
    let flag = elements::EcdsaSighashType::from_u32(u32::from(*flag));
    let sig = secp256k1_zkp::ecdsa::Signature::from_der(sig)?;
    Ok((sig, flag))
}
/// Trait describing a lookup table for signatures, hash preimages, etc.
/// Every method has a default implementation that simply returns `None`
/// on every query. Users are expected to override the methods that they
/// have data for.
pub trait Satisfier<Pk: MiniscriptKey + ToPublicKey> {
    /// Given a public key, look up an ECDSA signature with that key
    fn lookup_ecdsa_sig(&self, _: &Pk) -> Option<ElementsSig> {
        None
    }

    /// Lookup the tap key spend sig
    fn lookup_tap_key_spend_sig(&self) -> Option<elements::SchnorrSig> {
        None
    }

    /// Given a public key and a associated leaf hash, look up an schnorr signature with that key
    fn lookup_tap_leaf_script_sig(&self, _: &Pk, _: &TapLeafHash) -> Option<elements::SchnorrSig> {
        None
    }

    /// Obtain a reference to the control block for a ver and script
    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (elements::Script, LeafVersion)>> {
        None
    }

    /// Given a raw `Pkh`, lookup corresponding [`bitcoin::PublicKey`]
    fn lookup_raw_pkh_pk(&self, _: &hash160::Hash) -> Option<bitcoin::PublicKey> {
        None
    }

    /// Given a raw `Pkh`, lookup corresponding [`bitcoin::key::XOnlyPublicKey`]
    fn lookup_raw_pkh_x_only_pk(&self, _: &hash160::Hash) -> Option<XOnlyPublicKey> {
        None
    }

    /// Given a keyhash, look up the EC signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        _: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        None
    }

    /// Given a keyhash, look up the schnorr signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        _: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, elements::SchnorrSig)> {
        None
    }

    /// Given a SHA256 hash, look up its preimage
    fn lookup_sha256(&self, _: &Pk::Sha256) -> Option<Preimage32> {
        None
    }

    /// Given a HASH256 hash, look up its preimage
    fn lookup_hash256(&self, _: &Pk::Hash256) -> Option<Preimage32> {
        None
    }

    /// Given a RIPEMD160 hash, look up its preimage
    fn lookup_ripemd160(&self, _: &Pk::Ripemd160) -> Option<Preimage32> {
        None
    }

    /// Given a HASH160 hash, look up its preimage
    fn lookup_hash160(&self, _: &Pk::Hash160) -> Option<Preimage32> {
        None
    }

    /// Assert whether an relative locktime is satisfied
    fn check_older(&self, _: Sequence) -> bool {
        false
    }

    /// Assert whether a absolute locktime is satisfied
    fn check_after(&self, _: LockTime) -> bool {
        false
    }

    /// Introspection Data for Covenant support
    /// #1 Version
    fn lookup_nversion(&self) -> Option<u32> {
        None
    }

    /// Item 2: hashprevouts
    fn lookup_hashprevouts(&self) -> Option<sha256d::Hash> {
        None
    }

    /// Item 3: hashsequence
    fn lookup_hashsequence(&self) -> Option<sha256d::Hash> {
        None
    }

    /// ELEMENTS EXTRA: Item 3b: hashsequence
    fn lookup_hashissuances(&self) -> Option<sha256d::Hash> {
        None
    }

    /// Item 4: outpoint
    fn lookup_outpoint(&self) -> Option<OutPoint> {
        None
    }

    /// Item 5: scriptcode
    fn lookup_scriptcode(&self) -> Option<&Script> {
        None
    }

    /// Item 6: value
    fn lookup_value(&self) -> Option<confidential::Value> {
        None
    }

    /// Item 7: sequence
    fn lookup_nsequence(&self) -> Option<u32> {
        None
    }

    /// Item 8: hashoutputs
    fn lookup_outputs(&self) -> Option<&[elements::TxOut]> {
        None
    }

    /// Item 9: nlocktime
    fn lookup_nlocktime(&self) -> Option<u32> {
        None
    }

    /// Item 10: sighash type as u32
    fn lookup_sighashu32(&self) -> Option<u32> {
        None
    }

    /// Lookup spending transaction. Required for introspection
    // TODO: cleanup some of lookup_* methods as they are subsumed by this
    fn lookup_tx(&self) -> Option<&elements::Transaction> {
        None
    }

    /// Lookup spent txouts. Required for introspection
    fn lookup_spent_utxos(&self) -> Option<&[elements::TxOut]> {
        None
    }

    /// Lookup spent txouts. Required for introspection
    fn lookup_curr_inp(&self) -> Option<usize> {
        None
    }

    /// Lookup (msg, sig) for CSFS fragment
    fn lookup_csfs_sig(&self, _pk: &XOnlyPublicKey, _msg: &CsfsMsg) -> Option<schnorr::Signature> {
        None
    }

    /// Lookup price oracle signature
    fn lookup_price_oracle_sig(
        &self,
        _pk: &XOnlyPublicKey,
        _time: u64,
    ) -> Option<(schnorr::Signature, i64, u64)> {
        None
    }
}

// Allow use of `()` as a "no conditions available" satisfier
impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for () {}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for Sequence {
    fn check_older(&self, n: Sequence) -> bool {
        if !self.is_relative_lock_time() {
            return false;
        }

        // We need a relative lock time type in rust-bitcoin to clean this up.

        /* If nSequence encodes a relative lock-time, this mask is
         * applied to extract that lock-time from the sequence field. */
        const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
        const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 0x00400000;

        let mask = SEQUENCE_LOCKTIME_MASK | SEQUENCE_LOCKTIME_TYPE_FLAG;
        let masked_n = n.to_consensus_u32() & mask;
        let masked_seq = self.to_consensus_u32() & mask;
        if masked_n < SEQUENCE_LOCKTIME_TYPE_FLAG && masked_seq >= SEQUENCE_LOCKTIME_TYPE_FLAG {
            false
        } else {
            masked_n <= masked_seq
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for LockTime {
    fn check_after(&self, n: LockTime) -> bool {
        use LockTime::*;

        match (n, *self) {
            (Blocks(n), Blocks(lock_time)) => n <= lock_time,
            (Seconds(n), Seconds(lock_time)) => n <= lock_time,
            _ => false, // Not the same units.
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for HashMap<Pk, ElementsSig> {
    fn lookup_ecdsa_sig(&self, key: &Pk) -> Option<ElementsSig> {
        self.get(key).copied()
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk>
    for HashMap<(Pk, TapLeafHash), elements::SchnorrSig>
{
    fn lookup_tap_leaf_script_sig(
        &self,
        key: &Pk,
        h: &TapLeafHash,
    ) -> Option<elements::SchnorrSig> {
        // Unfortunately, there is no way to get a &(a, b) from &a and &b without allocating
        // If we change the signature the of lookup_tap_leaf_script_sig to accept a tuple. We would
        // face the same problem while satisfying PkK.
        // We use this signature to optimize for the psbt common use case.
        self.get(&(key.clone(), *h)).copied()
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for HashMap<hash160::Hash, (Pk, ElementsSig)>
where
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_ecdsa_sig(&self, key: &Pk) -> Option<ElementsSig> {
        self.get(&key.to_pubkeyhash(SigType::Ecdsa)).map(|x| x.1)
    }

    fn lookup_raw_pkh_pk(&self, pk_hash: &hash160::Hash) -> Option<bitcoin::PublicKey> {
        self.get(pk_hash).map(|x| x.0.to_public_key())
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pk_hash: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        self.get(pk_hash)
            .map(|&(ref pk, sig)| (pk.to_public_key(), sig))
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk>
    for HashMap<(hash160::Hash, TapLeafHash), (Pk, elements::SchnorrSig)>
where
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_tap_leaf_script_sig(
        &self,
        key: &Pk,
        h: &TapLeafHash,
    ) -> Option<elements::SchnorrSig> {
        self.get(&(key.to_pubkeyhash(SigType::Schnorr), *h))
            .map(|x| x.1)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pk_hash: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, elements::SchnorrSig)> {
        self.get(pk_hash)
            .map(|&(ref pk, sig)| (pk.to_x_only_pubkey(), sig))
    }
}

impl<Pk: MiniscriptKey + ToPublicKey, S: Satisfier<Pk>> Satisfier<Pk> for &'_ S {
    fn lookup_ecdsa_sig(&self, p: &Pk) -> Option<ElementsSig> {
        (**self).lookup_ecdsa_sig(p)
    }

    fn lookup_tap_leaf_script_sig(&self, p: &Pk, h: &TapLeafHash) -> Option<elements::SchnorrSig> {
        (**self).lookup_tap_leaf_script_sig(p, h)
    }

    fn lookup_raw_pkh_pk(&self, pkh: &hash160::Hash) -> Option<bitcoin::PublicKey> {
        (**self).lookup_raw_pkh_pk(pkh)
    }

    fn lookup_raw_pkh_x_only_pk(&self, pkh: &hash160::Hash) -> Option<XOnlyPublicKey> {
        (**self).lookup_raw_pkh_x_only_pk(pkh)
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pkh: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        (**self).lookup_raw_pkh_ecdsa_sig(pkh)
    }

    fn lookup_tap_key_spend_sig(&self) -> Option<elements::SchnorrSig> {
        (**self).lookup_tap_key_spend_sig()
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pkh: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, elements::SchnorrSig)> {
        (**self).lookup_raw_pkh_tap_leaf_script_sig(pkh)
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (elements::Script, LeafVersion)>> {
        (**self).lookup_tap_control_block_map()
    }

    fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
        (**self).lookup_sha256(h)
    }

    fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
        (**self).lookup_hash256(h)
    }

    fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
        (**self).lookup_ripemd160(h)
    }

    fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
        (**self).lookup_hash160(h)
    }

    fn check_older(&self, t: Sequence) -> bool {
        (**self).check_older(t)
    }

    fn check_after(&self, n: LockTime) -> bool {
        (**self).check_after(n)
    }

    fn lookup_nversion(&self) -> Option<u32> {
        (**self).lookup_nversion()
    }

    fn lookup_hashprevouts(&self) -> Option<sha256d::Hash> {
        (**self).lookup_hashprevouts()
    }

    fn lookup_hashsequence(&self) -> Option<sha256d::Hash> {
        (**self).lookup_hashsequence()
    }

    fn lookup_hashissuances(&self) -> Option<sha256d::Hash> {
        (**self).lookup_hashissuances()
    }

    fn lookup_outpoint(&self) -> Option<OutPoint> {
        (**self).lookup_outpoint()
    }

    fn lookup_scriptcode(&self) -> Option<&Script> {
        (**self).lookup_scriptcode()
    }

    fn lookup_value(&self) -> Option<confidential::Value> {
        (**self).lookup_value()
    }

    fn lookup_nsequence(&self) -> Option<u32> {
        (**self).lookup_nsequence()
    }

    fn lookup_outputs(&self) -> Option<&[elements::TxOut]> {
        (**self).lookup_outputs()
    }

    fn lookup_nlocktime(&self) -> Option<u32> {
        (**self).lookup_nlocktime()
    }

    fn lookup_sighashu32(&self) -> Option<u32> {
        (**self).lookup_sighashu32()
    }

    fn lookup_spent_utxos(&self) -> Option<&[elements::TxOut]> {
        (**self).lookup_spent_utxos()
    }

    fn lookup_tx(&self) -> Option<&elements::Transaction> {
        (**self).lookup_tx()
    }

    fn lookup_curr_inp(&self) -> Option<usize> {
        (**self).lookup_curr_inp()
    }

    fn lookup_csfs_sig(&self, pk: &XOnlyPublicKey, msg: &CsfsMsg) -> Option<schnorr::Signature> {
        (**self).lookup_csfs_sig(pk, msg)
    }

    fn lookup_price_oracle_sig(
        &self,
        pk: &XOnlyPublicKey,
        time: u64,
    ) -> Option<(schnorr::Signature, i64, u64)> {
        (**self).lookup_price_oracle_sig(pk, time)
    }
}

impl<Pk: MiniscriptKey + ToPublicKey, S: Satisfier<Pk>> Satisfier<Pk> for &'_ mut S {
    fn lookup_ecdsa_sig(&self, p: &Pk) -> Option<ElementsSig> {
        (**self).lookup_ecdsa_sig(p)
    }

    fn lookup_tap_leaf_script_sig(&self, p: &Pk, h: &TapLeafHash) -> Option<elements::SchnorrSig> {
        (**self).lookup_tap_leaf_script_sig(p, h)
    }

    fn lookup_tap_key_spend_sig(&self) -> Option<elements::SchnorrSig> {
        (**self).lookup_tap_key_spend_sig()
    }

    fn lookup_raw_pkh_pk(&self, pkh: &hash160::Hash) -> Option<bitcoin::PublicKey> {
        (**self).lookup_raw_pkh_pk(pkh)
    }

    fn lookup_raw_pkh_x_only_pk(&self, pkh: &hash160::Hash) -> Option<XOnlyPublicKey> {
        (**self).lookup_raw_pkh_x_only_pk(pkh)
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pkh: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        (**self).lookup_raw_pkh_ecdsa_sig(pkh)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pkh: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, elements::SchnorrSig)> {
        (**self).lookup_raw_pkh_tap_leaf_script_sig(pkh)
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (elements::Script, LeafVersion)>> {
        (**self).lookup_tap_control_block_map()
    }

    fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
        (**self).lookup_sha256(h)
    }

    fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
        (**self).lookup_hash256(h)
    }

    fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
        (**self).lookup_ripemd160(h)
    }

    fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
        (**self).lookup_hash160(h)
    }

    fn check_older(&self, t: Sequence) -> bool {
        (**self).check_older(t)
    }

    fn check_after(&self, n: LockTime) -> bool {
        (**self).check_after(n)
    }

    fn lookup_nversion(&self) -> Option<u32> {
        (**self).lookup_nversion()
    }

    fn lookup_hashprevouts(&self) -> Option<sha256d::Hash> {
        (**self).lookup_hashprevouts()
    }

    fn lookup_hashsequence(&self) -> Option<sha256d::Hash> {
        (**self).lookup_hashsequence()
    }

    fn lookup_hashissuances(&self) -> Option<sha256d::Hash> {
        (**self).lookup_hashissuances()
    }

    fn lookup_outpoint(&self) -> Option<OutPoint> {
        (**self).lookup_outpoint()
    }

    fn lookup_scriptcode(&self) -> Option<&Script> {
        (**self).lookup_scriptcode()
    }

    fn lookup_value(&self) -> Option<confidential::Value> {
        (**self).lookup_value()
    }

    fn lookup_nsequence(&self) -> Option<u32> {
        (**self).lookup_nsequence()
    }

    fn lookup_outputs(&self) -> Option<&[elements::TxOut]> {
        (**self).lookup_outputs()
    }

    fn lookup_nlocktime(&self) -> Option<u32> {
        (**self).lookup_nlocktime()
    }

    fn lookup_sighashu32(&self) -> Option<u32> {
        (**self).lookup_sighashu32()
    }

    fn lookup_spent_utxos(&self) -> Option<&[elements::TxOut]> {
        (**self).lookup_spent_utxos()
    }

    fn lookup_tx(&self) -> Option<&elements::Transaction> {
        (**self).lookup_tx()
    }

    fn lookup_curr_inp(&self) -> Option<usize> {
        (**self).lookup_curr_inp()
    }

    fn lookup_csfs_sig(&self, pk: &XOnlyPublicKey, msg: &CsfsMsg) -> Option<schnorr::Signature> {
        (**self).lookup_csfs_sig(pk, msg)
    }

    fn lookup_price_oracle_sig(
        &self,
        pk: &XOnlyPublicKey,
        time: u64,
    ) -> Option<(schnorr::Signature, i64, u64)> {
        (**self).lookup_price_oracle_sig(pk, time)
    }
}

macro_rules! impl_tuple_satisfier {
    ($($ty:ident),*) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* Pk> Satisfier<Pk> for ($($ty,)*)
        where
            Pk: MiniscriptKey + ToPublicKey,
            $($ty: Satisfier< Pk>,)*
        {
            fn lookup_ecdsa_sig(&self, key: &Pk) -> Option<ElementsSig> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_ecdsa_sig(key) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_tap_key_spend_sig(&self) -> Option<elements::SchnorrSig> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_tap_key_spend_sig() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_tap_leaf_script_sig(&self, key: &Pk, h: &TapLeafHash) -> Option<elements::SchnorrSig> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_tap_leaf_script_sig(key, h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_raw_pkh_ecdsa_sig(
                &self,
                key_hash: &hash160::Hash,
            ) -> Option<(bitcoin::PublicKey, ElementsSig)> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_raw_pkh_ecdsa_sig(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_raw_pkh_tap_leaf_script_sig(
                &self,
                key_hash: &(hash160::Hash, TapLeafHash),
            ) -> Option<(XOnlyPublicKey, elements::SchnorrSig)> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_raw_pkh_tap_leaf_script_sig(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_raw_pkh_pk(
                &self,
                key_hash: &hash160::Hash,
            ) -> Option<bitcoin::PublicKey> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_raw_pkh_pk(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_raw_pkh_x_only_pk(
                &self,
                key_hash: &hash160::Hash,
            ) -> Option<XOnlyPublicKey> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_raw_pkh_x_only_pk(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_tap_control_block_map(
                &self,
            ) -> Option<&BTreeMap<ControlBlock, (elements::Script, LeafVersion)>> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_tap_control_block_map() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_sha256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hash256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_ripemd160(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hash160(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn check_older(&self, n: Sequence) -> bool {
                let &($(ref $ty,)*) = self;
                $(
                    if $ty.check_older(n) {
                        return true;
                    }
                )*
                false
            }

            fn check_after(&self, n: LockTime) -> bool {
                let &($(ref $ty,)*) = self;
                $(
                    if $ty.check_after(n) {
                        return true;
                    }
                )*
                false
            }

            fn lookup_nversion(&self) -> Option<u32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_nversion() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hashprevouts(&self) -> Option<sha256d::Hash> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hashprevouts() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hashsequence(&self) -> Option<sha256d::Hash> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hashsequence() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hashissuances(&self) -> Option<sha256d::Hash> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hashissuances() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_outpoint(&self) -> Option<OutPoint> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_outpoint() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_scriptcode(&self) -> Option<&Script> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_scriptcode() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_value(&self) -> Option<confidential::Value> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_value() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_nsequence(&self) -> Option<u32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_nsequence() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_outputs(&self) -> Option<&[elements::TxOut]> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_outputs() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_nlocktime(&self) -> Option<u32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_nlocktime() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_sighashu32(&self) -> Option<u32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_sighashu32() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_spent_utxos(&self) -> Option<&[elements::TxOut]> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_spent_utxos() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_curr_inp(&self) -> Option<usize> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_curr_inp() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_tx(&self) -> Option<&elements::Transaction> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_tx() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_csfs_sig(&self, pk: &XOnlyPublicKey, msg: &CsfsMsg) -> Option<schnorr::Signature> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_csfs_sig(pk, msg) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_price_oracle_sig(&self, pk: &XOnlyPublicKey, time: u64) -> Option<(schnorr::Signature, i64, u64)> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_price_oracle_sig(pk, time) {
                        return Some(result);
                    }
                )*
                None
            }
        }
    }
}

impl_tuple_satisfier!(A);
impl_tuple_satisfier!(A, B);
impl_tuple_satisfier!(A, B, C);
impl_tuple_satisfier!(A, B, C, D);
impl_tuple_satisfier!(A, B, C, D, E);
impl_tuple_satisfier!(A, B, C, D, E, F);
impl_tuple_satisfier!(A, B, C, D, E, F, G);
impl_tuple_satisfier!(A, B, C, D, E, F, G, H);

/// A witness, if available, for a Miniscript fragment
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Witness {
    /// Witness Available and the value of the witness
    Stack(Vec<Vec<u8>>),
    /// Third party can possibly satisfy the fragment but we cannot
    /// Witness Unavailable
    Unavailable,
    /// No third party can produce a satisfaction without private key
    /// Witness Impossible
    Impossible,
}

impl PartialOrd for Witness {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Witness {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (Witness::Stack(v1), Witness::Stack(v2)) => {
                let w1 = witness_size(v1);
                let w2 = witness_size(v2);
                w1.cmp(&w2)
            }
            (Witness::Stack(_), _) => cmp::Ordering::Less,
            (_, Witness::Stack(_)) => cmp::Ordering::Greater,
            (Witness::Impossible, Witness::Unavailable) => cmp::Ordering::Less,
            (Witness::Unavailable, Witness::Impossible) => cmp::Ordering::Greater,
            (Witness::Impossible, Witness::Impossible) => cmp::Ordering::Equal,
            (Witness::Unavailable, Witness::Unavailable) => cmp::Ordering::Equal,
        }
    }
}

impl Witness {
    /// Turn a signature into (part of) a satisfaction
    fn signature<Pk: ToPublicKey, S: Satisfier<Pk>, Ctx: ScriptContext>(
        sat: S,
        pk: &Pk,
        leaf_hash: &TapLeafHash,
    ) -> Self {
        match Ctx::sig_type() {
            super::context::SigType::Ecdsa => match sat.lookup_ecdsa_sig(pk) {
                Some(sig) => Witness::Stack(vec![elementssig_to_rawsig(&sig)]),
                // Signatures cannot be forged
                None => Witness::Impossible,
            },
            super::context::SigType::Schnorr => match sat.lookup_tap_leaf_script_sig(pk, leaf_hash)
            {
                Some(sig) => Witness::Stack(vec![sig.to_vec()]),
                // Signatures cannot be forged
                None => Witness::Impossible,
            },
        }
    }

    /// Turn a public key related to a pkh into (part of) a satisfaction
    fn pkh_public_key<Pk: ToPublicKey, S: Satisfier<Pk>, Ctx: ScriptContext>(
        sat: S,
        pkh: &hash160::Hash,
    ) -> Self {
        // public key hashes are assumed to be unavailable
        // instead of impossible since it is the same as pub-key hashes
        match Ctx::sig_type() {
            SigType::Ecdsa => match sat.lookup_raw_pkh_pk(pkh) {
                Some(pk) => Witness::Stack(vec![pk.to_bytes()]),
                None => Witness::Unavailable,
            },
            SigType::Schnorr => match sat.lookup_raw_pkh_x_only_pk(pkh) {
                Some(pk) => Witness::Stack(vec![pk.serialize().to_vec()]),
                None => Witness::Unavailable,
            },
        }
    }

    /// Turn a key/signature pair related to a pkh into (part of) a satisfaction
    fn pkh_signature<Pk: ToPublicKey, S: Satisfier<Pk>, Ctx: ScriptContext>(
        sat: S,
        pkh: &hash160::Hash,
        leaf_hash: &TapLeafHash,
    ) -> Self {
        match Ctx::sig_type() {
            SigType::Ecdsa => match sat.lookup_raw_pkh_ecdsa_sig(pkh) {
                Some((pk, sig)) => {
                    let ser_sig = elementssig_to_rawsig(&sig);
                    Witness::Stack(vec![ser_sig, pk.to_public_key().to_bytes()])
                }
                None => Witness::Impossible,
            },
            SigType::Schnorr => match sat.lookup_raw_pkh_tap_leaf_script_sig(&(*pkh, *leaf_hash)) {
                Some((pk, sig)) => Witness::Stack(vec![
                    sig.to_vec(),
                    pk.to_x_only_pubkey().serialize().to_vec(),
                ]),
                None => Witness::Impossible,
            },
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    pub fn ripemd160_preimage<Pk: ToPublicKey, S: Satisfier<Pk>>(
        sat: S,
        h: &Pk::Ripemd160,
    ) -> Self {
        match sat.lookup_ripemd160(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            // Note hash preimages are unavailable instead of impossible
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    pub fn hash160_preimage<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, h: &Pk::Hash160) -> Self {
        match sat.lookup_hash160(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            // Note hash preimages are unavailable instead of impossible
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    pub fn sha256_preimage<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, h: &Pk::Sha256) -> Self {
        match sat.lookup_sha256(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            // Note hash preimages are unavailable instead of impossible
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    pub fn hash256_preimage<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, h: &Pk::Hash256) -> Self {
        match sat.lookup_hash256(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            // Note hash preimages are unavailable instead of impossible
            None => Witness::Unavailable,
        }
    }
}

impl Witness {
    /// Produce something like a 32-byte 0 push
    pub fn hash_dissatisfaction() -> Self {
        Witness::Stack(vec![vec![0; 32]])
    }

    /// Construct a satisfaction equivalent to an empty stack
    pub fn empty() -> Self {
        Witness::Stack(vec![])
    }

    /// Construct a satisfaction equivalent to `OP_1`
    pub fn push_1() -> Self {
        Witness::Stack(vec![vec![1]])
    }

    /// Construct a satisfaction equivalent to a single empty push
    pub fn push_0() -> Self {
        Witness::Stack(vec![vec![]])
    }

    /// Concatenate, or otherwise combine, two satisfactions
    pub fn combine(one: Self, two: Self) -> Self {
        match (one, two) {
            (Witness::Impossible, _) | (_, Witness::Impossible) => Witness::Impossible,
            (Witness::Unavailable, _) | (_, Witness::Unavailable) => Witness::Unavailable,
            (Witness::Stack(mut a), Witness::Stack(b)) => {
                a.extend(b);
                Witness::Stack(a)
            }
        }
    }
}

/// A (dis)satisfaction of a Miniscript fragment
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Satisfaction {
    /// The actual witness stack
    pub stack: Witness,
    /// Whether or not this (dis)satisfaction has a signature somewhere
    /// in it
    pub has_sig: bool,
}

impl Satisfaction {
    /// Construct a satisfaction that is impossible to satisfy with no sig
    pub fn impossible() -> Self {
        Satisfaction {
            stack: Witness::Impossible,
            has_sig: false,
        }
    }

    /// Construct a satisfaction that is impossible to satisfy with no sig
    pub fn empty() -> Self {
        Satisfaction {
            stack: Witness::empty(),
            has_sig: false,
        }
    }

    /// Combines two satisfactions
    pub fn combine(one: Self, two: Self) -> Self {
        Satisfaction {
            stack: Witness::combine(one.stack, two.stack),
            has_sig: one.has_sig || two.has_sig,
        }
    }

    // produce a non-malleable satisafaction for thesh frag
    fn thresh<Pk, Ctx, Sat, Ext, F>(
        k: usize,
        subs: &[Arc<Miniscript<Pk, Ctx, Ext>>],
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
        min_fn: &mut F,
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: ParseableExt,
        F: FnMut(Satisfaction, Satisfaction) -> Satisfaction,
    {
        let mut sats = subs
            .iter()
            .map(|s| {
                Self::satisfy_helper(
                    &s.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    &mut Self::thresh,
                )
            })
            .collect::<Vec<_>>();
        // Start with the to-return stack set to all dissatisfactions
        let mut ret_stack = subs
            .iter()
            .map(|s| {
                Self::dissatisfy_helper(
                    &s.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    &mut Self::thresh,
                )
            })
            .collect::<Vec<_>>();

        // Sort everything by (sat cost - dissat cost), except that
        // satisfactions without signatures beat satisfactions with
        // signatures
        let mut sat_indices = (0..subs.len()).collect::<Vec<_>>();
        sat_indices.sort_by_key(|&i| {
            let stack_weight = match (&sats[i].stack, &ret_stack[i].stack) {
                (Witness::Unavailable, _) | (Witness::Impossible, _) => i64::MAX,
                // This can only be the case when we have PkH without the corresponding
                // Pubkey.
                (_, Witness::Unavailable) | (_, Witness::Impossible) => i64::MIN,
                (Witness::Stack(ref s), Witness::Stack(ref d)) => {
                    witness_size(s) as i64 - witness_size(d) as i64
                }
            };
            let is_impossible = sats[i].stack == Witness::Impossible;
            // First consider the candidates that are not impossible to satisfy
            // by any party. Among those first consider the ones that have no sig
            // because third party can malleate them if they are not chosen.
            // Lastly, choose by weight.
            (is_impossible, sats[i].has_sig, stack_weight)
        });

        for i in 0..k {
            mem::swap(&mut ret_stack[sat_indices[i]], &mut sats[sat_indices[i]]);
        }

        // We preferably take satisfactions that are not impossible
        // If we cannot find `k` satisfactions that are not impossible
        // then the threshold branch is impossible to satisfy
        // For example, the fragment thresh(2, hash, 0, 0, 0)
        // is has an impossible witness
        assert!(k > 0);
        if sats[sat_indices[k - 1]].stack == Witness::Impossible {
            Satisfaction {
                stack: Witness::Impossible,
                // If the witness is impossible, we don't care about the
                // has_sig flag
                has_sig: false,
            }
        }
        // We are now guaranteed that all elements in `k` satisfactions
        // are not impossible(we sort by is_impossible bool).
        // The above loop should have taken everything without a sig
        // (since those were sorted higher than non-sigs). If there
        // are remaining non-sig satisfactions this indicates a
        // malleability vector
        // For example, the fragment thresh(2, hash, hash, 0, 0)
        // is uniquely satisfyiable because there is no satisfaction
        // for the 0 fragment
        else if k < sat_indices.len()
            && !sats[sat_indices[k]].has_sig
            && sats[sat_indices[k]].stack != Witness::Impossible
        {
            // All arguments should be `d`, so dissatisfactions have no
            // signatures; and in this branch we assume too many weak
            // arguments, so none of the satisfactions should have
            // signatures either.
            for sat in &ret_stack {
                assert!(!sat.has_sig);
            }
            Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
            }
        } else {
            // Otherwise flatten everything out
            Satisfaction {
                has_sig: ret_stack.iter().any(|sat| sat.has_sig),
                stack: ret_stack.into_iter().fold(Witness::empty(), |acc, next| {
                    Witness::combine(next.stack, acc)
                }),
            }
        }
    }

    // produce a possily malleable satisafaction for thesh frag
    fn thresh_mall<Pk, Ctx, Sat, Ext, F>(
        k: usize,
        subs: &[Arc<Miniscript<Pk, Ctx, Ext>>],
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
        min_fn: &mut F,
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: ParseableExt,
        F: FnMut(Satisfaction, Satisfaction) -> Satisfaction,
    {
        let mut sats = subs
            .iter()
            .map(|s| {
                Self::satisfy_helper(
                    &s.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    &mut Self::thresh_mall,
                )
            })
            .collect::<Vec<_>>();
        // Start with the to-return stack set to all dissatisfactions
        let mut ret_stack = subs
            .iter()
            .map(|s| {
                Self::dissatisfy_helper(
                    &s.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    &mut Self::thresh_mall,
                )
            })
            .collect::<Vec<_>>();

        // Sort everything by (sat cost - dissat cost), except that
        // satisfactions without signatures beat satisfactions with
        // signatures
        let mut sat_indices = (0..subs.len()).collect::<Vec<_>>();
        sat_indices.sort_by_key(|&i| {
            // For malleable satifactions, directly choose smallest weights
            match (&sats[i].stack, &ret_stack[i].stack) {
                (Witness::Unavailable, _) | (Witness::Impossible, _) => i64::MAX,
                // This is only possible when one of the branches has PkH
                (_, Witness::Unavailable) | (_, Witness::Impossible) => i64::MIN,
                (Witness::Stack(ref s), Witness::Stack(ref d)) => {
                    witness_size(s) as i64 - witness_size(d) as i64
                }
            }
        });

        // swap the satisfactions
        for i in 0..k {
            mem::swap(&mut ret_stack[sat_indices[i]], &mut sats[sat_indices[i]]);
        }

        // combine the witness
        // no non-malleability checks needed
        Satisfaction {
            has_sig: ret_stack.iter().any(|sat| sat.has_sig),
            stack: ret_stack.into_iter().fold(Witness::empty(), |acc, next| {
                Witness::combine(next.stack, acc)
            }),
        }
    }

    fn minimum(sat1: Self, sat2: Self) -> Self {
        // If there is only one available satisfaction, we must choose that
        // regardless of has_sig marker.
        // This handles the case where both are impossible.
        match (&sat1.stack, &sat2.stack) {
            (&Witness::Impossible, _) => return sat2,
            (_, &Witness::Impossible) => return sat1,
            _ => {}
        }
        match (sat1.has_sig, sat2.has_sig) {
            // If neither option has a signature, this is a malleability
            // vector, so choose neither one.
            (false, false) => Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
            },
            // If only one has a signature, take the one that doesn't; a
            // third party could malleate by removing the signature, but
            // can't malleate if he'd have to add it
            (false, true) => Satisfaction {
                stack: sat1.stack,
                has_sig: false,
            },
            (true, false) => Satisfaction {
                stack: sat2.stack,
                has_sig: false,
            },
            // If both have a signature associated with them, choose the
            // cheaper one (where "cheaper" is defined such that available
            // things are cheaper than unavailable ones)
            (true, true) => Satisfaction {
                stack: cmp::min(sat1.stack, sat2.stack),
                has_sig: true,
            },
        }
    }

    // calculate the minimum witness allowing witness malleability
    fn minimum_mall(sat1: Self, sat2: Self) -> Self {
        match (&sat1.stack, &sat2.stack) {
            // If there is only one possible satisfaction, use it regardless
            // of the other one
            (&Witness::Impossible, _) | (&Witness::Unavailable, _) => return sat2,
            (_, &Witness::Impossible) | (_, &Witness::Unavailable) => return sat1,
            _ => {}
        }
        Satisfaction {
            stack: cmp::min(sat1.stack, sat2.stack),
            // The fragment is has_sig only if both of the
            // fragments are has_sig
            has_sig: sat1.has_sig && sat2.has_sig,
        }
    }

    // produce a non-malleable satisfaction
    fn satisfy_helper<Pk, Ctx, Sat, Ext, F, G>(
        term: &Terminal<Pk, Ctx, Ext>,
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
        min_fn: &mut F,
        thresh_fn: &mut G,
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: ParseableExt,
        F: FnMut(Satisfaction, Satisfaction) -> Satisfaction,
        G: FnMut(
            usize,
            &[Arc<Miniscript<Pk, Ctx, Ext>>],
            &Sat,
            bool,
            &TapLeafHash,
            &mut F,
        ) -> Satisfaction,
    {
        match *term {
            Terminal::PkK(ref pk) => Satisfaction {
                stack: Witness::signature::<_, _, Ctx>(stfr, pk, leaf_hash),
                has_sig: true,
            },
            Terminal::PkH(ref pk) => {
                let wit = Witness::signature::<_, _, Ctx>(stfr, pk, leaf_hash);
                let pk_bytes = match Ctx::sig_type() {
                    SigType::Ecdsa => pk.to_public_key().to_bytes(),
                    SigType::Schnorr => pk.to_x_only_pubkey().serialize().to_vec(),
                };
                Satisfaction {
                    stack: Witness::combine(wit, Witness::Stack(vec![pk_bytes])),
                    has_sig: true,
                }
            }
            Terminal::RawPkH(ref pkh) => Satisfaction {
                stack: Witness::pkh_signature::<_, _, Ctx>(stfr, pkh, leaf_hash),
                has_sig: true,
            },
            Terminal::After(t) => Satisfaction {
                stack: if stfr.check_after(t.into()) {
                    Witness::empty()
                } else if root_has_sig {
                    // If the root terminal has signature, the
                    // signature covers the nLockTime and nSequence
                    // values. The sender of the transaction should
                    // take care that it signs the value such that the
                    // timelock is not met
                    Witness::Impossible
                } else {
                    Witness::Unavailable
                },
                has_sig: false,
            },
            Terminal::Older(t) => Satisfaction {
                stack: if stfr.check_older(t) {
                    Witness::empty()
                } else if root_has_sig {
                    // If the root terminal has signature, the
                    // signature covers the nLockTime and nSequence
                    // values. The sender of the transaction should
                    // take care that it signs the value such that the
                    // timelock is not met
                    Witness::Impossible
                } else {
                    Witness::Unavailable
                },

                has_sig: false,
            },
            Terminal::Ripemd160(ref h) => Satisfaction {
                stack: Witness::ripemd160_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::Hash160(ref h) => Satisfaction {
                stack: Witness::hash160_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::Sha256(ref h) => Satisfaction {
                stack: Witness::sha256_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::Hash256(ref h) => Satisfaction {
                stack: Witness::hash256_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::True => Satisfaction {
                stack: Witness::empty(),
                has_sig: false,
            },
            Terminal::False => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
            },
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::Verify(ref sub)
            | Terminal::NonZero(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => {
                Self::satisfy_helper(&sub.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn)
            }
            Terminal::DupIf(ref sub) => {
                let sat = Self::satisfy_helper(
                    &sub.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                Satisfaction {
                    stack: Witness::combine(sat.stack, Witness::push_1()),
                    has_sig: sat.has_sig,
                }
            }
            Terminal::AndV(ref l, ref r) | Terminal::AndB(ref l, ref r) => {
                let l_sat =
                    Self::satisfy_helper(&l.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let r_sat =
                    Self::satisfy_helper(&r.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                Satisfaction {
                    stack: Witness::combine(r_sat.stack, l_sat.stack),
                    has_sig: l_sat.has_sig || r_sat.has_sig,
                }
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                let a_sat =
                    Self::satisfy_helper(&a.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let a_nsat = Self::dissatisfy_helper(
                    &a.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let b_sat =
                    Self::satisfy_helper(&b.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let c_sat =
                    Self::satisfy_helper(&c.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);

                min_fn(
                    Satisfaction {
                        stack: Witness::combine(b_sat.stack, a_sat.stack),
                        has_sig: a_sat.has_sig || b_sat.has_sig,
                    },
                    Satisfaction {
                        stack: Witness::combine(c_sat.stack, a_nsat.stack),
                        has_sig: a_nsat.has_sig || c_sat.has_sig,
                    },
                )
            }
            Terminal::OrB(ref l, ref r) => {
                let l_sat =
                    Self::satisfy_helper(&l.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let r_sat =
                    Self::satisfy_helper(&r.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let l_nsat = Self::dissatisfy_helper(
                    &l.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let r_nsat = Self::dissatisfy_helper(
                    &r.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );

                assert!(!l_nsat.has_sig);
                assert!(!r_nsat.has_sig);

                min_fn(
                    Satisfaction {
                        stack: Witness::combine(r_sat.stack, l_nsat.stack),
                        has_sig: r_sat.has_sig,
                    },
                    Satisfaction {
                        stack: Witness::combine(r_nsat.stack, l_sat.stack),
                        has_sig: l_sat.has_sig,
                    },
                )
            }
            Terminal::OrD(ref l, ref r) | Terminal::OrC(ref l, ref r) => {
                let l_sat =
                    Self::satisfy_helper(&l.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let r_sat =
                    Self::satisfy_helper(&r.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let l_nsat = Self::dissatisfy_helper(
                    &l.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );

                assert!(!l_nsat.has_sig);

                min_fn(
                    l_sat,
                    Satisfaction {
                        stack: Witness::combine(r_sat.stack, l_nsat.stack),
                        has_sig: r_sat.has_sig,
                    },
                )
            }
            Terminal::OrI(ref l, ref r) => {
                let l_sat =
                    Self::satisfy_helper(&l.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let r_sat =
                    Self::satisfy_helper(&r.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                min_fn(
                    Satisfaction {
                        stack: Witness::combine(l_sat.stack, Witness::push_1()),
                        has_sig: l_sat.has_sig,
                    },
                    Satisfaction {
                        stack: Witness::combine(r_sat.stack, Witness::push_0()),
                        has_sig: r_sat.has_sig,
                    },
                )
            }
            Terminal::Thresh(k, ref subs) => {
                thresh_fn(k, subs, stfr, root_has_sig, leaf_hash, min_fn)
            }
            Terminal::Multi(k, ref keys) => {
                // Collect all available signatures
                let mut sig_count = 0;
                let mut sigs = Vec::with_capacity(k);
                for pk in keys {
                    match Witness::signature::<_, _, Ctx>(stfr, pk, leaf_hash) {
                        Witness::Stack(sig) => {
                            sigs.push(sig);
                            sig_count += 1;
                        }
                        Witness::Impossible => {}
                        Witness::Unavailable => unreachable!(
                            "Signature satisfaction without witness must be impossible"
                        ),
                    }
                }

                if sig_count < k {
                    Satisfaction {
                        stack: Witness::Impossible,
                        has_sig: false,
                    }
                } else {
                    // Throw away the most expensive ones
                    for _ in 0..sig_count - k {
                        let max_idx = sigs
                            .iter()
                            .enumerate()
                            .max_by_key(|&(_, v)| v.len())
                            .unwrap()
                            .0;
                        sigs[max_idx] = vec![];
                    }

                    Satisfaction {
                        stack: sigs.into_iter().fold(Witness::push_0(), |acc, sig| {
                            Witness::combine(acc, Witness::Stack(sig))
                        }),
                        has_sig: true,
                    }
                }
            }
            Terminal::MultiA(k, ref keys) => {
                // Collect all available signatures
                let mut sig_count = 0;
                let mut sigs = vec![vec![vec![]]; keys.len()];
                for (i, pk) in keys.iter().rev().enumerate() {
                    match Witness::signature::<_, _, Ctx>(stfr, pk, leaf_hash) {
                        Witness::Stack(sig) => {
                            sigs[i] = sig;
                            sig_count += 1;
                            // This a privacy issue, we are only selecting the first available
                            // sigs. Incase pk at pos 1 is not selected, we know we did not have access to it
                            // bitcoin core also implements the same logic for MULTISIG, so I am not bothering
                            // permuting the sigs for now
                            if sig_count == k {
                                break;
                            }
                        }
                        Witness::Impossible => {}
                        Witness::Unavailable => unreachable!(
                            "Signature satisfaction without witness must be impossible"
                        ),
                    }
                }

                if sig_count < k {
                    Satisfaction {
                        stack: Witness::Impossible,
                        has_sig: false,
                    }
                } else {
                    Satisfaction {
                        stack: sigs.into_iter().fold(Witness::empty(), |acc, sig| {
                            Witness::combine(acc, Witness::Stack(sig))
                        }),
                        has_sig: true,
                    }
                }
            }
            Terminal::Ext(ref e) => e.satisfy(stfr),
        }
    }

    // Helper function to produce a dissatisfaction
    fn dissatisfy_helper<Pk, Ctx, Sat, Ext, F, G>(
        term: &Terminal<Pk, Ctx, Ext>,
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
        min_fn: &mut F,
        thresh_fn: &mut G,
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: ParseableExt,
        F: FnMut(Satisfaction, Satisfaction) -> Satisfaction,
        G: FnMut(
            usize,
            &[Arc<Miniscript<Pk, Ctx, Ext>>],
            &Sat,
            bool,
            &TapLeafHash,
            &mut F,
        ) -> Satisfaction,
    {
        match *term {
            Terminal::PkK(..) => Satisfaction {
                stack: Witness::push_0(),
                has_sig: false,
            },
            Terminal::PkH(ref pk) => {
                let pk_bytes = match Ctx::sig_type() {
                    SigType::Ecdsa => pk.to_public_key().to_bytes(),
                    SigType::Schnorr => pk.to_x_only_pubkey().serialize().to_vec(),
                };
                Satisfaction {
                    stack: Witness::combine(Witness::push_0(), Witness::Stack(vec![pk_bytes])),
                    has_sig: false,
                }
            }
            Terminal::RawPkH(ref pkh) => Satisfaction {
                stack: Witness::combine(
                    Witness::push_0(),
                    Witness::pkh_public_key::<_, _, Ctx>(stfr, pkh),
                ),
                has_sig: false,
            },
            Terminal::False => Satisfaction {
                stack: Witness::empty(),
                has_sig: false,
            },
            Terminal::True => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
            },
            Terminal::Older(_) => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
            },
            Terminal::After(_) => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
            },
            Terminal::Sha256(_)
            | Terminal::Hash256(_)
            | Terminal::Ripemd160(_)
            | Terminal::Hash160(_) => Satisfaction {
                stack: Witness::hash_dissatisfaction(),
                has_sig: false,
            },
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => {
                Self::dissatisfy_helper(&sub.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn)
            }
            Terminal::DupIf(_) | Terminal::NonZero(_) => Satisfaction {
                stack: Witness::push_0(),
                has_sig: false,
            },
            Terminal::Verify(_) => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
            },
            Terminal::AndV(ref v, ref other) => {
                let vsat =
                    Self::satisfy_helper(&v.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let odissat = Self::dissatisfy_helper(
                    &other.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                Satisfaction {
                    stack: Witness::combine(odissat.stack, vsat.stack),
                    has_sig: vsat.has_sig || odissat.has_sig,
                }
            }
            Terminal::AndB(ref l, ref r)
            | Terminal::OrB(ref l, ref r)
            | Terminal::OrD(ref l, ref r)
            | Terminal::AndOr(ref l, _, ref r) => {
                let lnsat = Self::dissatisfy_helper(
                    &l.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let rnsat = Self::dissatisfy_helper(
                    &r.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                Satisfaction {
                    stack: Witness::combine(rnsat.stack, lnsat.stack),
                    has_sig: rnsat.has_sig || lnsat.has_sig,
                }
            }
            Terminal::OrC(..) => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
            },
            Terminal::OrI(ref l, ref r) => {
                let lnsat = Self::dissatisfy_helper(
                    &l.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let dissat_1 = Satisfaction {
                    stack: Witness::combine(lnsat.stack, Witness::push_1()),
                    has_sig: lnsat.has_sig,
                };

                let rnsat = Self::dissatisfy_helper(
                    &r.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let dissat_2 = Satisfaction {
                    stack: Witness::combine(rnsat.stack, Witness::push_0()),
                    has_sig: rnsat.has_sig,
                };

                // Dissatisfactions don't need to non-malleable. Use minimum_mall always
                Satisfaction::minimum_mall(dissat_1, dissat_2)
            }
            Terminal::Thresh(_, ref subs) => Satisfaction {
                stack: subs.iter().fold(Witness::empty(), |acc, sub| {
                    let nsat = Self::dissatisfy_helper(
                        &sub.node,
                        stfr,
                        root_has_sig,
                        leaf_hash,
                        min_fn,
                        thresh_fn,
                    );
                    assert!(!nsat.has_sig);
                    Witness::combine(nsat.stack, acc)
                }),
                has_sig: false,
            },
            Terminal::Multi(k, _) => Satisfaction {
                stack: Witness::Stack(vec![vec![]; k + 1]),
                has_sig: false,
            },
            Terminal::MultiA(_, ref pks) => Satisfaction {
                stack: Witness::Stack(vec![vec![]; pks.len()]),
                has_sig: false,
            },
            Terminal::Ext(ref e) => e.dissatisfy(stfr),
        }
    }

    /// Produce a satisfaction non-malleable satisfaction
    pub(super) fn satisfy<Pk, Ctx, Sat, Ext>(
        term: &Terminal<Pk, Ctx, Ext>,
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: ParseableExt,
    {
        Self::satisfy_helper(
            term,
            stfr,
            root_has_sig,
            leaf_hash,
            &mut Satisfaction::minimum,
            &mut Satisfaction::thresh,
        )
    }

    /// Produce a satisfaction(possibly malleable)
    pub(super) fn satisfy_mall<
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: ParseableExt,
    >(
        term: &Terminal<Pk, Ctx, Ext>,
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
    ) -> Self {
        Self::satisfy_helper(
            term,
            stfr,
            root_has_sig,
            leaf_hash,
            &mut Satisfaction::minimum_mall,
            &mut Satisfaction::thresh_mall,
        )
    }
}
