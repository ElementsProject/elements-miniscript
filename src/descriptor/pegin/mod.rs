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

use bitcoin::hashes::Hash;
use bitcoin::{self, blockdata::script, hashes};
use bitcoin::{blockdata::opcodes, util::contracthash};
use bitcoin::{hashes::hash160, Address as BtcAddress};
use bitcoin::{secp256k1, Script as BtcScript};
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
use NullCtx;
use {
    BtcDescriptor, BtcDescriptorTrait, BtcError, BtcFromTree, BtcLiftable, BtcMiniscript,
    BtcPolicy, BtcSatisfier, BtcSegwitv0, BtcTerminal, BtcTree,
};

use {DescriptorTrait, PkTranslate, Segwitv0};

use crate::{tweak_key, util::varint_len, DescriptorPublicKeyCtx};

use super::checksum::{desc_checksum, verify_checksum};
use {MiniscriptKey, ToPublicKey};

mod legacy_pegin;

/// A general trait for Pegin Bitcoin descriptor.
/// It should also support FromStr, fmt::Display and should be liftable
/// to bitcoin Semantic Policy.
/// Offers function for witness cost estimation, script pubkey creation
/// satisfaction using the [Satisfier] trait.
// Unfortunately, the translation function cannot be added to trait
// because of traits cannot know underlying generic of Self.
// Thus, we must implement additional trait for translate function
pub trait PeginTrait<Pk: MiniscriptKey>:
    FromStr + Display + Debug + Clone + Eq + PartialEq + PartialOrd + Ord
{
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
    /// `to_pk_ctx` denotes the ToPkCtx required for deriving bitcoin::PublicKey
    /// from MiniscriptKey using [ToPublicKey].
    /// If MiniscriptKey is already is [bitcoin::PublicKey], then the context
    /// would be [NullCtx] and [descriptor.DescriptorPublicKeyCtx] if MiniscriptKey is [descriptor.DescriptorPublicKey]
    ///
    /// In general, this is defined by generic for the trait [trait.ToPublicKey]
    fn bitcoin_address<ToPkCtx: Copy>(
        &self,
        to_pk_ctx: ToPkCtx,
        network: bitcoin::Network,
    ) -> Option<bitcoin::Address>
    where
        Pk: ToPublicKey<ToPkCtx>;

    /// Computes the bitcoin scriptpubkey of the descriptor.
    /// `to_pk_ctx` denotes the ToPkCtx required for deriving bitcoin::PublicKey
    /// from MiniscriptKey using [ToPublicKey].
    /// If MiniscriptKey is already is [bitcoin::PublicKey], then the context
    /// would be [NullCtx] and [descriptor.DescriptorPublicKeyCtx] if MiniscriptKey is [descriptor.DescriptorPublicKey]
    ///
    /// In general, this is defined by generic for the trait [ToPublicKey]
    fn bitcoin_script_pubkey<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>;

    /// Computes the scriptSig that will be in place for an unsigned
    /// input spending an output with this descriptor. For pre-segwit
    /// descriptors, which use the scriptSig for signatures, this
    /// returns the empty script.
    ///
    /// This is used in Segwit transactions to produce an unsigned
    /// transaction whose txid will not change during signing (since
    /// only the witness data will change).
    /// `to_pk_ctx` denotes the ToPkCtx required for deriving bitcoin::PublicKey
    /// from MiniscriptKey using [ToPublicKey].
    /// If MiniscriptKey is already is [bitcoin::PublicKey], then the context
    /// would be [NullCtx] and [descriptor.DescriptorPublicKeyCtx] if MiniscriptKey is [descriptor.DescriptorPublicKey]
    ///
    /// In general, this is defined by generic for the trait [ToPublicKey]
    fn bitcoin_unsigned_script_sig<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>;

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
    fn bitcoin_witness_script<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>;

    /// Returns satisfying witness and scriptSig to spend an
    /// output controlled by the given descriptor if it possible to
    /// construct one using the satisfier S.
    /// `to_pk_ctx` denotes the ToPkCtx required for deriving bitcoin::PublicKey
    /// from MiniscriptKey using [ToPublicKey].
    /// If MiniscriptKey is already is [bitcoin::PublicKey], then the context
    /// would be [NullCtx] and [descriptor.DescriptorPublicKeyCtx] if MiniscriptKey is [descriptor.DescriptorPublicKey]
    ///
    /// In general, this is defined by generic for the trait [ToPublicKey]
    fn get_satisfaction<S, ToPkCtx>(
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
    /// `TxIn` output.
    fn satisfy<S, ToPkCtx>(
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
        let (witness, script_sig) = self.get_satisfaction(satisfier, to_pk_ctx)?;
        txin.witness = witness;
        txin.script_sig = script_sig;
        Ok(())
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction. Assumes all signatures are 73 bytes, including push opcode
    /// and sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    fn max_satisfaction_weight(&self) -> Option<usize>;

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
    fn script_code<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>;

    /// Get the corresponding elements descriptor that would be used
    /// at redeem time by the user.
    /// Users can use the DescrpitorTrait operations on the output Descriptor
    /// to obtain the characteristics of the elements descriptor.
    fn into_user_descriptor(self) -> Descriptor<Pk>;
}

pub struct PeginCtx {}

// // Implementation of Descriptor for Legacy Pegin
// impl<'secp, C: secp256k1::Verification ,Pk: MiniscriptKey, ToPkCtx: Copy> BtcDescriptorTrait<LegacyPeginKey, LegacyPeginKeyCtx<'secp, C>>
//     for LegacyPegin<Pk, ToPkCtx>
// where
//     <Pk as FromStr>::Err: ToString,
//     <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
//     ToPkCtx: Ord,
//     Pk : ToPublicKey<ToPkCtx>
// {
//     fn sanity_check(&self) -> Result<(), BtcError> {
//         self.ms
//             .sanity_check()
//             .map_err(|_| BtcError::Unexpected(format!("Federation script sanity check failed")))?;
//         self.desc
//             .sanity_check()
//             .map_err(|_| BtcError::Unexpected(format!("Federation script sanity check failed")))?;
//         Ok(())
//     }

//     fn address(&self, to_pk_ctx: ToPkCtx, network: bitcoin::Network) -> Option<BtcAddress>
//     {
//         Some(bitcoin::Address::p2shwsh(
//             &self.witness_script(to_pk_ctx),
//             network,
//         ))
//     }

//     fn script_pubkey(&self, to_pk_ctx: ToPkCtx) -> BtcScript
//     {
//         self.address(to_pk_ctx, bitcoin::Network::Bitcoin)
//             .expect("Address cannot fail for pegin")
//             .script_pubkey()
//     }

//     fn unsigned_script_sig(&self, to_pk_ctx: ToPkCtx) -> BtcScript
//     {
//         let witness_script = self.witness_script(to_pk_ctx);
//         script::Builder::new()
//             .push_slice(&witness_script.to_v0_p2wsh()[..])
//             .into_script()
//     }

//     fn witness_script(&self, to_pk_ctx: ToPkCtx) -> BtcScript
//     {
//         let tweak_vec = self.desc.witness_script(to_pk_ctx).into_bytes();
//         // Hopefully, we never have to use this and dynafed is deployed
//         let mut builder = script::Builder::new()
//             .push_opcode(opcodes::all::OP_DEPTH)
//             .push_int(self.fed_k as i64 + 1)
//             .push_opcode(opcodes::all::OP_EQUAL)
//             .push_opcode(opcodes::all::OP_IF)
//             // manually serialize the left CMS branch, without the OP_CMS
//             .push_int(self.fed_k as i64);
//         // Issue 1:
//         // Creating context is expensive, but sadly our API does not support that
//         // As per the last discussion, ToPkCtx is something that Pk -> bitcoin::PublicKey
//         // But we also additionally need the secp ctx to perform the tweak addition
//         let secp_ctx = secp256k1::Secp256k1::verification_only();
//         let tweak = hashes::sha256::Hash::hash(&tweak_vec);

//         let key_ctx = LegacyPeginKeyCtx::new(&secp_ctx, Some(tweak.into_inner()));
//         for key in &self.fed_pks {
//             let tweaked_pk = key.to_public_key(key_ctx);
//             builder = builder.push_key(&tweaked_pk);
//         }
//         let mut nearly_done = builder
//             .push_int(self.fed_pks.len() as i64)
//             .push_opcode(opcodes::all::OP_ELSE)
//             .into_script()
//             .to_bytes();

//         let right = if let BtcTerminal::OrD(l, right) = &self.ms.node {
//             right
//         } else {
//             unreachable!("Only valid pegin descriptors should be created inside LegacyPegin")
//         };
//         let mut rser = right.encode(key_ctx).into_bytes();
//         // ...and we have an OP_VERIFY style checksequenceverify, which in
//         // Liquid production was encoded with OP_DROP instead...
//         assert_eq!(rser[4], opcodes::all::OP_VERIFY.into_u8());
//         rser[4] = opcodes::all::OP_DROP.into_u8();
//         // ...then we should serialize it by sharing the OP_CMS across
//         // both branches, and add an OP_DEPTH check to distinguish the
//         // branches rather than doing the normal cascade construction
//         nearly_done.extend(rser);

//         let insert_point = nearly_done.len() - 1;
//         nearly_done.insert(insert_point, 0x68);
//         bitcoin::Script::from(nearly_done)
//     }

//     fn get_satisfaction<S>(
//         &self,
//         satisfier: S,
//         to_pk_ctx: ToPkCtx,
//     ) -> Result<(Vec<Vec<u8>>, BtcScript), BtcError>
//     where
//         ToPkCtx: Copy,
//         S: BtcSatisfier<ToPkCtx, Pk>,
//         Pk: ToPublicKey<ToPkCtx>,
//     {
//         let s = self.ms.satisfy(satisfier, to_pk_ctx);
//         todo!()
//         // Issue 2:
//         // satisfaction API is also not consistent.
//         // The trait bound requires S: BtcSatisfier<ToPkCtx, Pk>,
//         // But what we actually need is S: Satisfier<LegacyPeginCtx<'a, T>, LegacyPeginKey>
//         // Which we cannot do because it will impose a stricter bound than trait definition
//         // I am starting to think as per our current definition ToPkCtx is something that
//         // takes Pk into bitcoin::PublicKey to the one that is finally used in script instead
//         // just something that takes into bitcoin::PublicKey.
//         // But we cannot declare the 'a and T in the function definition
//         // because it won't match the trait interface.
//         Err(BtcError::Unexpected(format!(
//             "Satisfaction not supported for pegin descriptors"
//         )))
//     }

//     fn max_satisfaction_weight(&self) -> Option<usize> {
//         let script_size = 628;
//         Some(
//             4 * 36
//                 + varint_len(script_size)
//                 + script_size
//                 + varint_len(self.ms.max_satisfaction_witness_elements()?)
//                 + self.ms.max_satisfaction_size()?,
//         )
//     }

//     fn script_code(&self, to_pk_ctx: ToPkCtx) -> BtcScript
//     {
//         self.witness_script(to_pk_ctx)
//     }
// }

// // /// New Pegin Descriptor with Miniscript support
// // /// Useful with dynamic federations
// // #[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
// // pub struct Pegin<Pk: MiniscriptKey> {
// //     /// The untweaked pegin bitcoin descriptor
// //     pub fed_desc: BtcDescriptor<Pk>,
// //     /// The redeem elements descriptor
// //     pub elem_desc: Descriptor<Pk>,
// // }

// // impl<Pk: MiniscriptKey, ToPkCtx: Copy> Pegin<Pk> {
// //     /// Create a new LegacyPegin descriptor
// //     pub fn new(fed_desc: BtcDescriptor<Pk>, elem_desc: Descriptor<Pk>) -> Self {
// //         Self {
// //             fed_desc,
// //             elem_desc,
// //         }
// //     }
// // }

// // // Implementation of PeginDescriptor for Pegin
// // // impl<Pk: MiniscriptKey, ToPkCtx: Copy> PeginDescriptor<Pk> for Pegin<Pk>{}
