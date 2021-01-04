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

use descriptor::checksum::{desc_checksum, verify_checksum};

use super::PeginTrait;
use {MiniscriptKey, ToPublicKey};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegacyPeginKey {
    // Functionary Key that can be tweaked
    Functionary(bitcoin::PublicKey),
    // Non functionary Key, cannot be tweaked
    NonFunctionary(bitcoin::PublicKey),
}

/// 'f' represents tweakable functionary keys and
/// 'u' represents untweakable keys
impl FromStr for LegacyPeginKey {
    // only allow compressed keys in LegacyPegin
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Err(Error::BadDescriptor(format!("Empty Legacy pegin")))
        } else if &s[0..1] == "f" && s.len() == 67 {
            Ok(LegacyPeginKey::Functionary(bitcoin::PublicKey::from_str(
                &s[1..],
            )?))
        } else if &s[0..1] == "u" && s.len() == 67 {
            Ok(LegacyPeginKey::NonFunctionary(
                bitcoin::PublicKey::from_str(&s[1..])?,
            ))
        } else {
            Err(Error::BadDescriptor(format!(
                "Invalid Legacy Pegin descriptor"
            )))
        }
    }
}

impl fmt::Display for LegacyPeginKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LegacyPeginKey::Functionary(ref pk) => write!(f, "f{}", pk),
            LegacyPeginKey::NonFunctionary(ref pk) => write!(f, "u{}", pk),
        }
    }
}

impl MiniscriptKey for LegacyPeginKey {
    type Hash = hash160::Hash;

    fn is_uncompressed(&self) -> bool {
        false
    }

    fn serialized_len(&self) -> usize {
        33
    }

    fn to_pubkeyhash(&self) -> Self::Hash {
        let pk = match *self {
            LegacyPeginKey::Functionary(ref pk) => pk,
            LegacyPeginKey::NonFunctionary(ref pk) => pk,
        };
        MiniscriptKey::to_pubkeyhash(pk)
    }
}

/// Context information required for tweaking Pegin Keys
/// Needs secp_ctx to actually compute the tweak and and the
/// tweak value.
/// In general, users should never really have use this struct
/// in any shape as it used internally in tweak creation.
/// In most cases, you would [DescriptorTweakCtx] which is the context
/// used in pegin descriptors for descriptor supported operations
pub struct LegacyPeginKeyCtx<'secp, C: secp256k1::Verification> {
    /// The underlying secp context
    secp_ctx: &'secp secp256k1::Secp256k1<C>,
    // Use zero tweak for untweakable keys
    tweak: Option<[u8; 32]>,
}

impl<'secp, C: secp256k1::Verification> Clone for LegacyPeginKeyCtx<'secp, C> {
    fn clone(&self) -> Self {
        Self {
            secp_ctx: self.secp_ctx,
            tweak: self.tweak.clone(),
        }
    }
}

impl<'secp, C: secp256k1::Verification> Copy for LegacyPeginKeyCtx<'secp, C> {}

impl<'secp, C: secp256k1::Verification> LegacyPeginKeyCtx<'secp, C> {
    /// Create a new context
    pub fn new(secp_ctx: &'secp secp256k1::Secp256k1<C>, tweak: Option<[u8; 32]>) -> Self {
        Self {
            secp_ctx: secp_ctx,
            tweak: tweak,
        }
    }
}

/// Context information for computing tweaks for pegin descriptors
pub struct DescriptorTweakCtx<'secp, C: secp256k1::Verification, UserPkCtx: Copy> {
    /// The underlying secp context to compute the tweak.
    secp_ctx: &'secp secp256k1::Secp256k1<C>,
    /// Context required for derivation of user's PublicKey
    user_key_ctx: UserPkCtx,
}

impl<'secp, C: secp256k1::Verification, UserPkCtx: Copy> Clone
    for DescriptorTweakCtx<'secp, C, UserPkCtx>
{
    fn clone(&self) -> Self {
        Self {
            secp_ctx: self.secp_ctx,
            user_key_ctx: self.user_key_ctx,
        }
    }
}

impl<'secp, C: secp256k1::Verification, UserPkCtx: Copy> Copy
    for DescriptorTweakCtx<'secp, C, UserPkCtx>
{
}

impl<'secp, C: secp256k1::Verification, UserPkCtx: Copy> DescriptorTweakCtx<'secp, C, UserPkCtx> {
    /// Create a new context
    pub fn new(user_key_ctx: UserPkCtx, secp_ctx: &'secp secp256k1::Secp256k1<C>) -> Self {
        Self {
            user_key_ctx: user_key_ctx,
            secp_ctx: secp_ctx,
        }
    }
}

impl<'secp, C: secp256k1::Verification> ToPublicKey<LegacyPeginKeyCtx<'secp, C>>
    for LegacyPeginKey
{
    fn to_public_key(&self, to_pk_ctx: LegacyPeginKeyCtx<'secp, C>) -> bitcoin::PublicKey {
        match *self {
            LegacyPeginKey::Functionary(ref pk) => {
                let tweak = to_pk_ctx.tweak.unwrap_or([0u8; 32]);
                #[allow(deprecated)]
                contracthash::tweak_key(to_pk_ctx.secp_ctx, pk.clone(), &tweak)
            }
            LegacyPeginKey::NonFunctionary(ref pk) => pk.clone(),
        }
    }

    fn hash_to_hash160(
        hash: &Self::Hash,
        _to_pk_ctx: LegacyPeginKeyCtx<'secp, C>,
    ) -> hash160::Hash {
        *hash
    }
}

/// Legacy Pegin Descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct LegacyPegin<Pk: MiniscriptKey> {
    /// The federation pks
    pub fed_pks: Vec<LegacyPeginKey>,
    /// The federation threshold
    pub fed_k: usize,
    /// The emergency pks
    pub emer_pks: Vec<LegacyPeginKey>,
    /// The emergency threshold
    pub emer_k: usize,
    /// csv timelock
    pub timelock: u32,
    /// The elements descriptor required to redeem
    pub desc: Descriptor<Pk>,
    // Representation of federation policy as a miniscript
    // Allows for easier implementation
    ms: BtcMiniscript<LegacyPeginKey, BtcSegwitv0>,
}

impl<Pk: MiniscriptKey> LegacyPegin<Pk> {
    /// Create a new LegacyPegin descriptor
    pub fn new(
        fed_pks: Vec<LegacyPeginKey>,
        fed_k: usize,
        emer_pks: Vec<LegacyPeginKey>,
        emer_k: usize,
        timelock: u32,
        desc: Descriptor<Pk>,
    ) -> Self {
        let fed_ms = BtcMiniscript::from_ast(BtcTerminal::Multi(fed_k, fed_pks.clone()))
            .expect("Multi type check can't fail");
        let csv = BtcMiniscript::from_ast(BtcTerminal::Verify(Arc::new(
            BtcMiniscript::from_ast(BtcTerminal::Older(timelock)).unwrap(),
        )))
        .unwrap();
        let emer_ms = BtcMiniscript::from_ast(BtcTerminal::Multi(emer_k, emer_pks.clone()))
            .expect("Multi type check can't fail");
        let emer_ms =
            BtcMiniscript::from_ast(BtcTerminal::AndV(Arc::new(csv), Arc::new(emer_ms))).unwrap();
        let ms = BtcMiniscript::from_ast(BtcTerminal::OrD(Arc::new(fed_ms), Arc::new(emer_ms)))
            .expect("Type check");
        Self {
            fed_pks,
            fed_k,
            emer_pks,
            emer_k,
            timelock,
            desc,
            ms,
        }
    }

    // Internal function to set the fields of Self according to
    // miniscript
    fn from_ms_and_desc(
        desc: Descriptor<Pk>,
        ms: BtcMiniscript<LegacyPeginKey, BtcSegwitv0>,
    ) -> Self {
        let (fed_pks, fed_k, right) = if let BtcTerminal::OrD(a, b) = &ms.node {
            if let (BtcTerminal::Multi(fed_k, ref fed_pks), right) = (&a.node, &b.node) {
                (fed_pks, *fed_k, right)
            } else {
                unreachable!("Only valid pegin miniscripts");
            }
        } else {
            unreachable!("Only valid pegin miniscripts");
        };
        let (timelock, emer_pks, emer_k) = if let BtcTerminal::AndV(l, r) = right {
            if let (BtcTerminal::Verify(csv), BtcTerminal::Multi(emer_k, emer_pks)) =
                (&l.node, &r.node)
            {
                if let BtcTerminal::Older(timelock) = csv.node {
                    (timelock, emer_pks, *emer_k)
                } else {
                    unreachable!("Only valid pegin miniscripts");
                }
            } else {
                unreachable!("Only valid pegin miniscripts");
            }
        } else {
            unreachable!("Only valid pegin miniscripts");
        };
        Self {
            fed_pks: fed_pks.clone(),
            fed_k,
            emer_pks: emer_pks.clone(),
            emer_k,
            timelock,
            desc,
            ms,
        }
    }

    /// Create a new descriptor with hard coded values for the
    /// legacy federation and emergency keys
    pub fn new_legacy_fed(_desc: Descriptor<Pk>) -> Self {
        unimplemented!()
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for LegacyPegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "legacy_pegin({:?},{:?})", self.ms, self.desc)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for LegacyPegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = format!("legacy_pegin({},{})", self.ms, self.desc);
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl<Pk: MiniscriptKey> Liftable<LegacyPeginKey> for LegacyPegin<Pk> {
    fn lift(&self) -> Result<semantic::Policy<LegacyPeginKey>, Error> {
        let btc_pol = BtcLiftable::lift(&self.ms)?;
        Liftable::lift(&btc_pol)
    }
}

impl<Pk: MiniscriptKey> BtcLiftable<LegacyPeginKey> for LegacyPegin<Pk> {
    fn lift(&self) -> Result<BtcPolicy<LegacyPeginKey>, BtcError> {
        self.ms.lift()
    }
}

impl<Pk: MiniscriptKey> FromTree for LegacyPegin<Pk>
where
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "legacy_pegin" && top.args.len() == 2 {
            // a roundtrip hack to use FromTree from bitcoin::Miniscript from
            // expression::Tree in elements.
            let ms_str = top.args[0].to_string();
            let ms_expr = BtcTree::from_str(&ms_str)?;
            //
            let ms = BtcMiniscript::<LegacyPeginKey, BtcSegwitv0>::from_tree(&ms_expr);
            let desc = Descriptor::<Pk>::from_tree(&top.args[1]);
            Ok(LegacyPegin::from_ms_and_desc(desc?, ms?))
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing legacy_pegin descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
}

impl<Pk: MiniscriptKey> FromStr for LegacyPegin<Pk>
where
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

impl<Pk: MiniscriptKey> PeginTrait<Pk> for LegacyPegin<Pk>
where
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn sanity_check(&self) -> Result<(), Error> {
        self.ms
            .sanity_check()
            .map_err(|_| Error::Unexpected(format!("Federation script sanity check failed")))?;
        self.desc
            .sanity_check()
            .map_err(|_| Error::Unexpected(format!("Federation script sanity check failed")))?;
        Ok(())
    }

    fn bitcoin_address<ToPkCtx: Copy>(
        &self,
        to_pk_ctx: ToPkCtx,
        network: bitcoin::Network,
    ) -> Option<bitcoin::Address>
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        Some(bitcoin::Address::p2shwsh(
            &self.bitcoin_witness_script(to_pk_ctx),
            network,
        ))
    }

    fn bitcoin_script_pubkey<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        self.bitcoin_address(to_pk_ctx, bitcoin::Network::Bitcoin)
            .expect("Address cannot fail for pegin")
            .script_pubkey()
    }

    fn bitcoin_unsigned_script_sig<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        let witness_script = self.bitcoin_witness_script(to_pk_ctx);
        script::Builder::new()
            .push_slice(&witness_script.to_v0_p2wsh()[..])
            .into_script()
    }

    fn bitcoin_witness_script<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        todo!()
    }

    fn get_satisfaction<S, ToPkCtx>(
        &self,
        satisfier: S,
        to_pk_ctx: ToPkCtx,
    ) -> Result<(Vec<Vec<u8>>, BtcScript), Error>
    where
        ToPkCtx: Copy,
        Pk: ToPublicKey<ToPkCtx>,
        S: BtcSatisfier<ToPkCtx, Pk>,
    {
        todo!()
    }

    fn max_satisfaction_weight(&self) -> Option<usize> {
        todo!()
    }

    fn script_code<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> BtcScript
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        todo!()
    }

    fn into_user_descriptor(self) -> Descriptor<Pk> {
        todo!()
    }
}

// // // Implementation of Descriptor for Legacy Pegin
// // impl<'secp, C: secp256k1::Verification ,Pk: MiniscriptKey> BtcDescriptorTrait<LegacyPeginKey, LegacyPeginKeyCtx<'secp, C>>
// //     for LegacyPegin<Pk>
// // where
// //     <Pk as FromStr>::Err: ToString,
// //     <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
// // {
// //     fn sanity_check(&self) -> Result<(), Error> {
// //         self.ms
// //             .sanity_check()
// //             .map_err(|_| Error::Unexpected(format!("Federation script sanity check failed")))?;
// //         self.desc
// //             .sanity_check()
// //             .map_err(|_| Error::Unexpected(format!("Federation script sanity check failed")))?;
// //         Ok(())
// //     }

// //     fn address(&self, to_pk_ctx: ToPkCtx, network: bitcoin::Network) -> Option<BtcAddress>
// //     {
// //         Some(bitcoin::Address::p2shwsh(
// //             &self.witness_script(to_pk_ctx),
// //             network,
// //         ))
// //     }

// //     fn script_pubkey(&self, to_pk_ctx: ToPkCtx) -> BtcScript
// //     {
// //         self.address(to_pk_ctx, bitcoin::Network::Bitcoin)
// //             .expect("Address cannot fail for pegin")
// //             .script_pubkey()
// //     }

// //     fn unsigned_script_sig(&self, to_pk_ctx: ToPkCtx) -> BtcScript
// //     {
// //         let witness_script = self.witness_script(to_pk_ctx);
// //         script::Builder::new()
// //             .push_slice(&witness_script.to_v0_p2wsh()[..])
// //             .into_script()
// //     }

// //     fn witness_script(&self, to_pk_ctx: ToPkCtx) -> BtcScript
// //     {
// //         let tweak_vec = self.desc.witness_script(to_pk_ctx).into_bytes();
// //         // Hopefully, we never have to use this and dynafed is deployed
// //         let mut builder = script::Builder::new()
// //             .push_opcode(opcodes::all::OP_DEPTH)
// //             .push_int(self.fed_k as i64 + 1)
// //             .push_opcode(opcodes::all::OP_EQUAL)
// //             .push_opcode(opcodes::all::OP_IF)
// //             // manually serialize the left CMS branch, without the OP_CMS
// //             .push_int(self.fed_k as i64);
// //         // Issue 1:
// //         // Creating context is expensive, but sadly our API does not support that
// //         // As per the last discussion, ToPkCtx is something that Pk -> bitcoin::PublicKey
// //         // But we also additionally need the secp ctx to perform the tweak addition
// //         let secp_ctx = secp256k1::Secp256k1::verification_only();
// //         let tweak = hashes::sha256::Hash::hash(&tweak_vec);

// //         let key_ctx = LegacyPeginKeyCtx::new(&secp_ctx, Some(tweak.into_inner()));
// //         for key in &self.fed_pks {
// //             let tweaked_pk = key.to_public_key(key_ctx);
// //             builder = builder.push_key(&tweaked_pk);
// //         }
// //         let mut nearly_done = builder
// //             .push_int(self.fed_pks.len() as i64)
// //             .push_opcode(opcodes::all::OP_ELSE)
// //             .into_script()
// //             .to_bytes();

// //         let right = if let BtcTerminal::OrD(l, right) = &self.ms.node {
// //             right
// //         } else {
// //             unreachable!("Only valid pegin descriptors should be created inside LegacyPegin")
// //         };
// //         let mut rser = right.encode(key_ctx).into_bytes();
// //         // ...and we have an OP_VERIFY style checksequenceverify, which in
// //         // Liquid production was encoded with OP_DROP instead...
// //         assert_eq!(rser[4], opcodes::all::OP_VERIFY.into_u8());
// //         rser[4] = opcodes::all::OP_DROP.into_u8();
// //         // ...then we should serialize it by sharing the OP_CMS across
// //         // both branches, and add an OP_DEPTH check to distinguish the
// //         // branches rather than doing the normal cascade construction
// //         nearly_done.extend(rser);

// //         let insert_point = nearly_done.len() - 1;
// //         nearly_done.insert(insert_point, 0x68);
// //         bitcoin::Script::from(nearly_done)
// //     }

// //     fn get_satisfaction<S>(
// //         &self,
// //         satisfier: S,
// //         to_pk_ctx: ToPkCtx,
// //     ) -> Result<(Vec<Vec<u8>>, BtcScript), Error>
// //     where
// //         ToPkCtx: Copy,
// //         S: BtcSatisfier<ToPkCtx, Pk>,
// //         Pk: ToPublicKey<ToPkCtx>,
// //     {
// //         let s = self.ms.satisfy(satisfier, to_pk_ctx);
// //         todo!()
// //         // Issue 2:
// //         // satisfaction API is also not consistent.
// //         // The trait bound requires S: BtcSatisfier<ToPkCtx, Pk>,
// //         // But what we actually need is S: Satisfier<LegacyPeginCtx<'a, T>, LegacyPeginKey>
// //         // Which we cannot do because it will impose a stricter bound than trait definition
// //         // I am starting to think as per our current definition ToPkCtx is something that
// //         // takes Pk into bitcoin::PublicKey to the one that is finally used in script instead
// //         // just something that takes into bitcoin::PublicKey.
// //         // But we cannot declare the 'a and T in the function definition
// //         // because it won't match the trait interface.
// //         Err(Error::Unexpected(format!(
// //             "Satisfaction not supported for pegin descriptors"
// //         )))
// //     }

// //     fn max_satisfaction_weight(&self) -> Option<usize> {
// //         let script_size = 628;
// //         Some(
// //             4 * 36
// //                 + varint_len(script_size)
// //                 + script_size
// //                 + varint_len(self.ms.max_satisfaction_witness_elements()?)
// //                 + self.ms.max_satisfaction_size()?,
// //         )
// //     }

// //     fn script_code(&self, to_pk_ctx: ToPkCtx) -> BtcScript
// //     {
// //         self.witness_script(to_pk_ctx)
// //     }
// // }

// // /// New Pegin Descriptor with Miniscript support
// // /// Useful with dynamic federations
// // #[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
// // pub struct Pegin<Pk: MiniscriptKey> {
// //     /// The untweaked pegin bitcoin descriptor
// //     pub fed_desc: BtcDescriptor<Pk>,
// //     /// The redeem elements descriptor
// //     pub elem_desc: Descriptor<Pk>,
// // }

// // impl<Pk: MiniscriptKey> Pegin<Pk> {
// //     /// Create a new LegacyPegin descriptor
// //     pub fn new(fed_desc: BtcDescriptor<Pk>, elem_desc: Descriptor<Pk>) -> Self {
// //         Self {
// //             fed_desc,
// //             elem_desc,
// //         }
// //     }
// // }

// // // Implementation of PeginDescriptor for Pegin
// // // impl<Pk: MiniscriptKey> PeginDescriptor<Pk> for Pegin<Pk>{}
