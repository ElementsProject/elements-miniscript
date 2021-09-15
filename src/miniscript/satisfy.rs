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

//! # Satisfaction and Dissatisfaction
//!
//! Traits and implementations to support producing witnesses for Miniscript
//! scriptpubkeys.
//!

use std::collections::HashMap;
use std::sync::Arc;
use std::{cmp, i64, mem};

use bitcoin;
use elements::{self, secp256k1_zkp};
use elements::{confidential, OutPoint, Script};
use elements::{
    encode::serialize,
    hashes::{hash160, ripemd160, sha256, sha256d},
};
use {MiniscriptKey, ToPublicKey};

use miniscript::limits::{
    HEIGHT_TIME_THRESHOLD, MAX_SCRIPT_ELEMENT_SIZE, MAX_STANDARD_P2WSH_STACK_ITEM_SIZE,
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
};
use util::witness_size;
use Error;
use Miniscript;
use ScriptContext;
use Terminal;

use super::ext::Extension;

/// Type alias for a signature/hashtype pair
pub type ElementsSig = (secp256k1_zkp::Signature, elements::SigHashType);
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
pub fn elementssig_from_rawsig(rawsig: &[u8]) -> Result<ElementsSig, Error> {
    let (flag, sig) = rawsig.split_last().unwrap();
    let flag = elements::SigHashType::from_u32(*flag as u32);
    let sig = secp256k1_zkp::Signature::from_der(sig)?;
    Ok((sig, flag))
}
/// Trait describing a lookup table for signatures, hash preimages, etc.
/// Every method has a default implementation that simply returns `None`
/// on every query. Users are expected to override the methods that they
/// have data for.
pub trait Satisfier<Pk: MiniscriptKey + ToPublicKey> {
    /// Given a public key, look up a signature with that key
    fn lookup_sig(&self, _: &Pk) -> Option<ElementsSig> {
        None
    }

    /// Given a `Pkh`, lookup corresponding `Pk`
    fn lookup_pkh_pk(&self, _: &Pk::Hash) -> Option<Pk> {
        None
    }

    /// Given a keyhash, look up the signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_pkh_sig(&self, _: &Pk::Hash) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        None
    }

    /// Given a SHA256 hash, look up its preimage
    fn lookup_sha256(&self, _: sha256::Hash) -> Option<Preimage32> {
        None
    }

    /// Given a HASH256 hash, look up its preimage
    fn lookup_hash256(&self, _: sha256d::Hash) -> Option<Preimage32> {
        None
    }

    /// Given a RIPEMD160 hash, look up its preimage
    fn lookup_ripemd160(&self, _: ripemd160::Hash) -> Option<Preimage32> {
        None
    }

    /// Given a HASH160 hash, look up its preimage
    fn lookup_hash160(&self, _: hash160::Hash) -> Option<Preimage32> {
        None
    }

    /// Assert whether an relative locktime is satisfied
    fn check_older(&self, _: u32) -> bool {
        false
    }

    /// Assert whether a absolute locktime is satisfied
    fn check_after(&self, _: u32) -> bool {
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
}

// Allow use of `()` as a "no conditions available" satisfier
impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for () {}

/// Newtype around `u32` which implements `Satisfier` using `n` as an
/// relative locktime
pub struct Older(pub u32);

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for Older {
    fn check_older(&self, n: u32) -> bool {
        if self.0 & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return true;
        }

        /* If nSequence encodes a relative lock-time, this mask is
         * applied to extract that lock-time from the sequence field. */
        const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

        let mask = SEQUENCE_LOCKTIME_MASK | SEQUENCE_LOCKTIME_TYPE_FLAG;
        let masked_n = n & mask;
        let masked_seq = self.0 & mask;
        if masked_n < SEQUENCE_LOCKTIME_TYPE_FLAG && masked_seq >= SEQUENCE_LOCKTIME_TYPE_FLAG {
            false
        } else {
            masked_n <= masked_seq
        }
    }
}

/// Newtype around `u32` which implements `Satisfier` using `n` as an
/// absolute locktime
pub struct After(pub u32);

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for After {
    fn check_after(&self, n: u32) -> bool {
        // if n > self.0; we will be returning false anyways
        if n < HEIGHT_TIME_THRESHOLD && self.0 >= HEIGHT_TIME_THRESHOLD {
            false
        } else {
            n <= self.0
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for HashMap<Pk, ElementsSig> {
    fn lookup_sig(&self, key: &Pk) -> Option<ElementsSig> {
        self.get(key).map(|x| *x)
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for HashMap<Pk::Hash, (Pk, ElementsSig)>
where
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_sig(&self, key: &Pk) -> Option<ElementsSig> {
        self.get(&key.to_pubkeyhash()).map(|x| x.1)
    }

    fn lookup_pkh_pk(&self, pk_hash: &Pk::Hash) -> Option<Pk> {
        self.get(pk_hash).map(|x| x.0.clone())
    }

    fn lookup_pkh_sig(&self, pk_hash: &Pk::Hash) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        self.get(pk_hash)
            .map(|&(ref pk, sig)| (pk.to_public_key(), sig))
    }
}

impl<'a, Pk: MiniscriptKey + ToPublicKey, S: Satisfier<Pk>> Satisfier<Pk> for &'a S {
    fn lookup_sig(&self, p: &Pk) -> Option<ElementsSig> {
        (**self).lookup_sig(p)
    }

    fn lookup_pkh_pk(&self, pkh: &Pk::Hash) -> Option<Pk> {
        (**self).lookup_pkh_pk(pkh)
    }

    fn lookup_pkh_sig(&self, pkh: &Pk::Hash) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        (**self).lookup_pkh_sig(pkh)
    }

    fn lookup_sha256(&self, h: sha256::Hash) -> Option<Preimage32> {
        (**self).lookup_sha256(h)
    }

    fn lookup_hash256(&self, h: sha256d::Hash) -> Option<Preimage32> {
        (**self).lookup_hash256(h)
    }

    fn lookup_ripemd160(&self, h: ripemd160::Hash) -> Option<Preimage32> {
        (**self).lookup_ripemd160(h)
    }

    fn lookup_hash160(&self, h: hash160::Hash) -> Option<Preimage32> {
        (**self).lookup_hash160(h)
    }

    fn check_older(&self, t: u32) -> bool {
        (**self).check_older(t)
    }

    fn check_after(&self, t: u32) -> bool {
        (**self).check_after(t)
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
}

impl<'a, Pk: MiniscriptKey + ToPublicKey, S: Satisfier<Pk>> Satisfier<Pk> for &'a mut S {
    fn lookup_sig(&self, p: &Pk) -> Option<ElementsSig> {
        (**self).lookup_sig(p)
    }

    fn lookup_pkh_pk(&self, pkh: &Pk::Hash) -> Option<Pk> {
        (**self).lookup_pkh_pk(pkh)
    }

    fn lookup_pkh_sig(&self, pkh: &Pk::Hash) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        (**self).lookup_pkh_sig(pkh)
    }

    fn lookup_sha256(&self, h: sha256::Hash) -> Option<Preimage32> {
        (**self).lookup_sha256(h)
    }

    fn lookup_hash256(&self, h: sha256d::Hash) -> Option<Preimage32> {
        (**self).lookup_hash256(h)
    }

    fn lookup_ripemd160(&self, h: ripemd160::Hash) -> Option<Preimage32> {
        (**self).lookup_ripemd160(h)
    }

    fn lookup_hash160(&self, h: hash160::Hash) -> Option<Preimage32> {
        (**self).lookup_hash160(h)
    }

    fn check_older(&self, t: u32) -> bool {
        (**self).check_older(t)
    }

    fn check_after(&self, t: u32) -> bool {
        (**self).check_after(t)
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
}

macro_rules! impl_tuple_satisfier {
    ($($ty:ident),*) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* Pk> Satisfier<Pk> for ($($ty,)*)
        where
            Pk: MiniscriptKey + ToPublicKey,
            $($ty: Satisfier< Pk>,)*
        {
            fn lookup_sig(&self, key: &Pk) -> Option<ElementsSig> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_sig(key) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_pkh_sig(
                &self,
                key_hash: &Pk::Hash,
            ) -> Option<(bitcoin::PublicKey, ElementsSig)> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_pkh_sig(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_pkh_pk(
                &self,
                key_hash: &Pk::Hash,
            ) -> Option<Pk> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_pkh_pk(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_sha256(&self, h: sha256::Hash) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_sha256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash256(&self, h: sha256d::Hash) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hash256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_ripemd160(&self, h: ripemd160::Hash) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_ripemd160(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash160(&self, h: hash160::Hash) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hash160(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn check_older(&self, n: u32) -> bool {
                let &($(ref $ty,)*) = self;
                $(
                    if $ty.check_older(n) {
                        return true;
                    }
                )*
                false
            }

            fn check_after(&self, n: u32) -> bool {
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
            (&Witness::Stack(ref v1), &Witness::Stack(ref v2)) => {
                let w1 = witness_size(v1);
                let w2 = witness_size(v2);
                w1.cmp(&w2)
            }
            (&Witness::Stack(_), _) => cmp::Ordering::Less,
            (_, &Witness::Stack(_)) => cmp::Ordering::Greater,
            (&Witness::Impossible, &Witness::Unavailable) => cmp::Ordering::Less,
            (&Witness::Unavailable, &Witness::Impossible) => cmp::Ordering::Greater,
            (&Witness::Impossible, &Witness::Impossible) => cmp::Ordering::Equal,
            (&Witness::Unavailable, &Witness::Unavailable) => cmp::Ordering::Equal,
        }
    }
}

impl Witness {
    /// Turn a signature into (part of) a satisfaction
    fn signature<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, pk: &Pk) -> Self {
        match sat.lookup_sig(pk) {
            Some((sig, hashtype)) => {
                let mut ret = sig.serialize_der().to_vec();
                ret.push(hashtype.as_u32() as u8);
                Witness::Stack(vec![ret])
            }
            // Signatures cannot be forged
            None => Witness::Impossible,
        }
    }

    /// Turn a public key related to a pkh into (part of) a satisfaction
    fn pkh_public_key<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, pkh: &Pk::Hash) -> Self {
        match sat.lookup_pkh_pk(pkh) {
            Some(pk) => Witness::Stack(vec![pk.to_public_key().to_bytes()]),
            // public key hashes are assumed to be unavailable
            // instead of impossible since it is the same as pub-key hashes
            None => Witness::Unavailable,
        }
    }

    /// Turn a key/signature pair related to a pkh into (part of) a satisfaction
    fn pkh_signature<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, pkh: &Pk::Hash) -> Self {
        match sat.lookup_pkh_sig(pkh) {
            Some((pk, (sig, hashtype))) => {
                let mut ret = sig.serialize_der().to_vec();
                ret.push(hashtype.as_u32() as u8);
                Witness::Stack(vec![ret.to_vec(), pk.to_public_key().to_bytes()])
            }
            None => Witness::Impossible,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn ripemd160_preimage<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, h: ripemd160::Hash) -> Self {
        match sat.lookup_ripemd160(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            // Note hash preimages are unavailable instead of impossible
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn hash160_preimage<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, h: hash160::Hash) -> Self {
        match sat.lookup_hash160(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            // Note hash preimages are unavailable instead of impossible
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn sha256_preimage<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, h: sha256::Hash) -> Self {
        match sat.lookup_sha256(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            // Note hash preimages are unavailable instead of impossible
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn hash256_preimage<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, h: sha256d::Hash) -> Self {
        match sat.lookup_hash256(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            // Note hash preimages are unavailable instead of impossible
            None => Witness::Unavailable,
        }
    }

    /// Turn a version into (part of) a satisfaction
    fn ver_eq_satisfy<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, n: u32) -> Self {
        match sat.lookup_nversion() {
            Some(k) => {
                if k == n {
                    Witness::empty()
                } else {
                    Witness::Impossible
                }
            }
            // Note the unavailable instead of impossible because we don't know
            // the version
            None => Witness::Unavailable,
        }
    }

    /// Turn a output prefix into (part of) a satisfaction
    fn output_pref_satisfy<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, pref: &[u8]) -> Self {
        match sat.lookup_outputs() {
            Some(outs) => {
                let mut ser_out = Vec::new();
                let num_wit_elems =
                    MAX_SCRIPT_ELEMENT_SIZE / MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1;
                let mut witness = Vec::with_capacity(num_wit_elems);
                for out in outs {
                    ser_out.extend(serialize(out));
                }
                // We need less than 520 bytes of serialized hashoutputs
                // in order to compute hash256 inside script
                if ser_out.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Witness::Impossible;
                }
                if ser_out.starts_with(pref) {
                    let mut iter = ser_out.into_iter().skip(pref.len()).peekable();

                    while iter.peek().is_some() {
                        let chk_size = MAX_STANDARD_P2WSH_STACK_ITEM_SIZE;
                        let chunk: Vec<u8> = iter.by_ref().take(chk_size).collect();
                        witness.push(chunk);
                    }
                    // Append empty elems to make for extra cats
                    // in the spk
                    while witness.len() < num_wit_elems {
                        witness.push(vec![]);
                    }
                    Witness::Stack(witness)
                } else {
                    Witness::Impossible
                }
            }
            // Note the unavailable instead of impossible because we don't know
            // the hashoutputs yet
            None => Witness::Unavailable,
        }
    }

    /// Dissatisfy ver fragment
    fn ver_eq_dissatisfy<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, n: u32) -> Self {
        if let Some(k) = sat.lookup_nversion() {
            if k == n {
                Witness::Impossible
            } else {
                Witness::empty()
            }
        } else {
            Witness::empty()
        }
    }

    /// Turn a output prefix into (part of) a satisfaction
    fn output_pref_dissatisfy<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, pref: &[u8]) -> Self {
        match sat.lookup_outputs() {
            Some(outs) => {
                let mut ser_out = Vec::new();
                for out in outs {
                    ser_out.extend(serialize(out));
                }
                let num_wit_elems = MAX_SCRIPT_ELEMENT_SIZE / MAX_STANDARD_P2WSH_STACK_ITEM_SIZE;
                let mut witness = Vec::with_capacity(num_wit_elems);
                if pref != ser_out.as_slice() {
                    while witness.len() < num_wit_elems {
                        witness.push(vec![]);
                    }
                    Witness::Stack(witness)
                } else if pref.len() != MAX_SCRIPT_ELEMENT_SIZE {
                    // Case when prefix == ser_out and it is possible
                    // to add more witness
                    witness.push(vec![1]);
                    while witness.len() < num_wit_elems {
                        witness.push(vec![]);
                    }
                    Witness::Stack(witness)
                } else {
                    // case when pref == ser_out and len of both is 520
                    Witness::Impossible
                }
            }
            // Note the unavailable instead of impossible because we don't know
            // the hashoutputs yet
            None => Witness::Unavailable,
        }
    }
}

impl Witness {
    /// Produce something like a 32-byte 0 push
    fn hash_dissatisfaction() -> Self {
        Witness::Stack(vec![vec![0; 32]])
    }

    /// Construct a satisfaction equivalent to an empty stack
    fn empty() -> Self {
        Witness::Stack(vec![])
    }

    /// Construct a satisfaction equivalent to `OP_1`
    fn push_1() -> Self {
        Witness::Stack(vec![vec![1]])
    }

    /// Construct a satisfaction equivalent to a single empty push
    fn push_0() -> Self {
        Witness::Stack(vec![vec![]])
    }

    /// Concatenate, or otherwise combine, two satisfactions
    fn combine(one: Self, two: Self) -> Self {
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
    // produce a non-malleable satisafaction for thesh frag
    fn thresh<Pk, Ctx, Sat, Ext, F>(
        k: usize,
        subs: &[Arc<Miniscript<Pk, Ctx, Ext>>],
        stfr: &Sat,
        root_has_sig: bool,
        min_fn: &mut F,
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: Extension<Pk>,
        F: FnMut(Satisfaction, Satisfaction) -> Satisfaction,
    {
        let mut sats = subs
            .iter()
            .map(|s| Self::satisfy_helper(&s.node, stfr, root_has_sig, min_fn, &mut Self::thresh))
            .collect::<Vec<_>>();
        // Start with the to-return stack set to all dissatisfactions
        let mut ret_stack = subs
            .iter()
            .map(|s| {
                Self::dissatisfy_helper(&s.node, stfr, root_has_sig, min_fn, &mut Self::thresh)
            })
            .collect::<Vec<_>>();

        // Sort everything by (sat cost - dissat cost), except that
        // satisfactions without signatures beat satisfactions with
        // signatures
        let mut sat_indices = (0..subs.len()).collect::<Vec<_>>();
        sat_indices.sort_by_key(|&i| {
            let stack_weight = match (&sats[i].stack, &ret_stack[i].stack) {
                (&Witness::Unavailable, _) | (&Witness::Impossible, _) => i64::MAX,
                // This can only be the case when we have PkH without the corresponding
                // Pubkey.
                (_, &Witness::Unavailable) | (_, &Witness::Impossible) => i64::MIN,
                (&Witness::Stack(ref s), &Witness::Stack(ref d)) => {
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
        min_fn: &mut F,
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: Extension<Pk>,
        F: FnMut(Satisfaction, Satisfaction) -> Satisfaction,
    {
        let mut sats = subs
            .iter()
            .map(|s| {
                Self::satisfy_helper(&s.node, stfr, root_has_sig, min_fn, &mut Self::thresh_mall)
            })
            .collect::<Vec<_>>();
        // Start with the to-return stack set to all dissatisfactions
        let mut ret_stack = subs
            .iter()
            .map(|s| {
                Self::dissatisfy_helper(&s.node, stfr, root_has_sig, min_fn, &mut Self::thresh_mall)
            })
            .collect::<Vec<_>>();

        // Sort everything by (sat cost - dissat cost), except that
        // satisfactions without signatures beat satisfactions with
        // signatures
        let mut sat_indices = (0..subs.len()).collect::<Vec<_>>();
        sat_indices.sort_by_key(|&i| {
            let stack_weight = match (&sats[i].stack, &ret_stack[i].stack) {
                (&Witness::Unavailable, _) | (&Witness::Impossible, _) => i64::MAX,
                // This is only possible when one of the branches has PkH
                (_, &Witness::Unavailable) | (_, &Witness::Impossible) => i64::MIN,
                (&Witness::Stack(ref s), &Witness::Stack(ref d)) => {
                    witness_size(s) as i64 - witness_size(d) as i64
                }
            };
            // For malleable satifactions, directly choose smallest weights
            stack_weight
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
        min_fn: &mut F,
        thresh_fn: &mut G,
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: Extension<Pk>,
        F: FnMut(Satisfaction, Satisfaction) -> Satisfaction,
        G: FnMut(usize, &[Arc<Miniscript<Pk, Ctx, Ext>>], &Sat, bool, &mut F) -> Satisfaction,
    {
        match *term {
            Terminal::PkK(ref pk) => Satisfaction {
                stack: Witness::signature(stfr, pk),
                has_sig: true,
            },
            Terminal::PkH(ref pkh) => Satisfaction {
                stack: Witness::pkh_signature(stfr, pkh),
                has_sig: true,
            },
            Terminal::After(t) => Satisfaction {
                stack: if stfr.check_after(t) {
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
            Terminal::Ripemd160(h) => Satisfaction {
                stack: Witness::ripemd160_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::Hash160(h) => Satisfaction {
                stack: Witness::hash160_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::Sha256(h) => Satisfaction {
                stack: Witness::sha256_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::Hash256(h) => Satisfaction {
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
            Terminal::Version(n) => Satisfaction {
                stack: Witness::ver_eq_satisfy(stfr, n),
                has_sig: false,
            },
            Terminal::OutputsPref(ref pref) => Satisfaction {
                stack: Witness::output_pref_satisfy(stfr, pref),
                has_sig: false,
            },
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::Verify(ref sub)
            | Terminal::NonZero(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => {
                Self::satisfy_helper(&sub.node, stfr, root_has_sig, min_fn, thresh_fn)
            }
            Terminal::DupIf(ref sub) => {
                let sat = Self::satisfy_helper(&sub.node, stfr, root_has_sig, min_fn, thresh_fn);
                Satisfaction {
                    stack: Witness::combine(sat.stack, Witness::push_1()),
                    has_sig: sat.has_sig,
                }
            }
            Terminal::AndV(ref l, ref r) | Terminal::AndB(ref l, ref r) => {
                let l_sat = Self::satisfy_helper(&l.node, stfr, root_has_sig, min_fn, thresh_fn);
                let r_sat = Self::satisfy_helper(&r.node, stfr, root_has_sig, min_fn, thresh_fn);
                Satisfaction {
                    stack: Witness::combine(r_sat.stack, l_sat.stack),
                    has_sig: l_sat.has_sig || r_sat.has_sig,
                }
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                let a_sat = Self::satisfy_helper(&a.node, stfr, root_has_sig, min_fn, thresh_fn);
                let a_nsat =
                    Self::dissatisfy_helper(&a.node, stfr, root_has_sig, min_fn, thresh_fn);
                let b_sat = Self::satisfy_helper(&b.node, stfr, root_has_sig, min_fn, thresh_fn);
                let c_sat = Self::satisfy_helper(&c.node, stfr, root_has_sig, min_fn, thresh_fn);

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
                let l_sat = Self::satisfy_helper(&l.node, stfr, root_has_sig, min_fn, thresh_fn);
                let r_sat = Self::satisfy_helper(&r.node, stfr, root_has_sig, min_fn, thresh_fn);
                let l_nsat =
                    Self::dissatisfy_helper(&l.node, stfr, root_has_sig, min_fn, thresh_fn);
                let r_nsat =
                    Self::dissatisfy_helper(&r.node, stfr, root_has_sig, min_fn, thresh_fn);

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
                let l_sat = Self::satisfy_helper(&l.node, stfr, root_has_sig, min_fn, thresh_fn);
                let r_sat = Self::satisfy_helper(&r.node, stfr, root_has_sig, min_fn, thresh_fn);
                let l_nsat =
                    Self::dissatisfy_helper(&l.node, stfr, root_has_sig, min_fn, thresh_fn);

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
                let l_sat = Self::satisfy_helper(&l.node, stfr, root_has_sig, min_fn, thresh_fn);
                let r_sat = Self::satisfy_helper(&r.node, stfr, root_has_sig, min_fn, thresh_fn);
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
            Terminal::Thresh(k, ref subs) => thresh_fn(k, subs, stfr, root_has_sig, min_fn),
            Terminal::Multi(k, ref keys) => {
                // Collect all available signatures
                let mut sig_count = 0;
                let mut sigs = Vec::with_capacity(k);
                for pk in keys {
                    match Witness::signature(stfr, pk) {
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
                            .max_by_key(|&(_, ref v)| v.len())
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
            Terminal::Ext(ref e) => e.satisfy(stfr),
        }
    }

    // Helper function to produce a dissatisfaction
    fn dissatisfy_helper<Pk, Ctx, Sat, Ext, F, G>(
        term: &Terminal<Pk, Ctx, Ext>,
        stfr: &Sat,
        root_has_sig: bool,
        min_fn: &mut F,
        thresh_fn: &mut G,
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: Extension<Pk>,
        F: FnMut(Satisfaction, Satisfaction) -> Satisfaction,
        G: FnMut(usize, &[Arc<Miniscript<Pk, Ctx, Ext>>], &Sat, bool, &mut F) -> Satisfaction,
    {
        match *term {
            Terminal::PkK(..) => Satisfaction {
                stack: Witness::push_0(),
                has_sig: false,
            },
            Terminal::PkH(ref pkh) => Satisfaction {
                stack: Witness::combine(Witness::push_0(), Witness::pkh_public_key(stfr, pkh)),
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
            Terminal::Version(n) => Satisfaction {
                stack: Witness::ver_eq_dissatisfy(stfr, n),
                has_sig: false,
            },
            Terminal::OutputsPref(ref pref) => Satisfaction {
                stack: Witness::output_pref_dissatisfy(stfr, pref),
                has_sig: false,
            },
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => {
                Self::dissatisfy_helper(&sub.node, stfr, root_has_sig, min_fn, thresh_fn)
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
                let vsat = Self::satisfy_helper(&v.node, stfr, root_has_sig, min_fn, thresh_fn);
                let odissat =
                    Self::dissatisfy_helper(&other.node, stfr, root_has_sig, min_fn, thresh_fn);
                Satisfaction {
                    stack: Witness::combine(odissat.stack, vsat.stack),
                    has_sig: vsat.has_sig || odissat.has_sig,
                }
            }
            Terminal::AndB(ref l, ref r)
            | Terminal::OrB(ref l, ref r)
            | Terminal::OrD(ref l, ref r)
            | Terminal::AndOr(ref l, _, ref r) => {
                let lnsat = Self::dissatisfy_helper(&l.node, stfr, root_has_sig, min_fn, thresh_fn);
                let rnsat = Self::dissatisfy_helper(&r.node, stfr, root_has_sig, min_fn, thresh_fn);
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
                let lnsat = Self::dissatisfy_helper(&l.node, stfr, root_has_sig, min_fn, thresh_fn);
                let dissat_1 = Satisfaction {
                    stack: Witness::combine(lnsat.stack, Witness::push_1()),
                    has_sig: lnsat.has_sig,
                };

                let rnsat = Self::dissatisfy_helper(&r.node, stfr, root_has_sig, min_fn, thresh_fn);
                let dissat_2 = Satisfaction {
                    stack: Witness::combine(rnsat.stack, Witness::push_0()),
                    has_sig: rnsat.has_sig,
                };

                min_fn(dissat_1, dissat_2)
            }
            Terminal::Thresh(_, ref subs) => Satisfaction {
                stack: subs.iter().fold(Witness::empty(), |acc, sub| {
                    let nsat =
                        Self::dissatisfy_helper(&sub.node, stfr, root_has_sig, min_fn, thresh_fn);
                    assert!(!nsat.has_sig);
                    Witness::combine(nsat.stack, acc)
                }),
                has_sig: false,
            },
            Terminal::Multi(k, _) => Satisfaction {
                stack: Witness::Stack(vec![vec![]; k + 1]),
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
    ) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: Extension<Pk>,
    {
        Self::satisfy_helper(
            term,
            stfr,
            root_has_sig,
            &mut Satisfaction::minimum,
            &mut Satisfaction::thresh,
        )
    }

    /// Produce a satisfaction(possibly malleable)
    pub(super) fn satisfy_mall<
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: ScriptContext,
        Sat: Satisfier<Pk>,
        Ext: Extension<Pk>,
    >(
        term: &Terminal<Pk, Ctx, Ext>,
        stfr: &Sat,
        root_has_sig: bool,
    ) -> Self {
        Self::satisfy_helper(
            term,
            stfr,
            root_has_sig,
            &mut Satisfaction::minimum_mall,
            &mut Satisfaction::thresh_mall,
        )
    }
}
