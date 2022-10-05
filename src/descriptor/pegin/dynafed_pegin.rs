// Miniscript
// Written in 2020 by
//     Rust Elements developers
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

//! DynaFed Pegin Descriptor Support
//!
//! Traits and implementations for Dynafed Pegin descriptors.
//! Note that this is a bitcoin descriptor and thus cannot be
//! added to elements Descriptor.
//! Unlike Pegin descriptors these are Miniscript, so dealing
//! with these is easier.

use std::fmt;

use bitcoin::blockdata::script;
use bitcoin::hashes::Hash;
use bitcoin::{self, hashes, Script as BtcScript};
use elements::secp256k1_zkp;

use crate::descriptor::checksum::{desc_checksum, verify_checksum};
use crate::expression::{self, FromTree};
use crate::extensions::{CovExtArgs, CovenantExt};
use crate::policy::{semantic, Liftable};
use crate::{
    BtcDescriptor, BtcError, BtcFromTree, BtcLiftable, BtcPolicy, BtcSatisfier, BtcTree,
    Descriptor, Error, MiniscriptKey, ToPublicKey,
};

/// New Pegin Descriptor with Miniscript support
/// Useful with dynamic federations
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Pegin<Pk: MiniscriptKey> {
    /// The untweaked pegin bitcoin descriptor
    pub fed_desc: BtcDescriptor<Pk>,
    /// The redeem elements descriptor
    ///
    /// TODO: Allow pegin redeem descriptor with extensions
    pub elem_desc: Descriptor<Pk, CovenantExt<CovExtArgs>>,
}

impl<Pk: MiniscriptKey> Pegin<Pk> {
    /// Create a new LegacyPegin descriptor
    pub fn new(
        fed_desc: BtcDescriptor<Pk>,
        elem_desc: Descriptor<Pk, CovenantExt<CovExtArgs>>,
    ) -> Self {
        Self {
            fed_desc,
            elem_desc,
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Pegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pegin({:?},{:?})", self.fed_desc, self.elem_desc)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Pegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = format!("pegin({},{})", self.fed_desc, self.elem_desc);
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Pegin<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        let btc_pol = BtcLiftable::lift(&self.fed_desc)?;
        Liftable::lift(&btc_pol)
    }
}

impl<Pk: MiniscriptKey> BtcLiftable<Pk> for Pegin<Pk> {
    fn lift(&self) -> Result<BtcPolicy<Pk>, BtcError> {
        self.fed_desc.lift()
    }
}

impl_from_tree!(
    Pegin<Pk>,
    fn from_tree(top: &expression::Tree<'_>) -> Result<Self, Error> {
        if top.name == "pegin" && top.args.len() == 2 {
            // a roundtrip hack to use FromTree from bitcoin::Miniscript from
            // expression::Tree in elements.
            let ms_str = top.args[0].to_string();
            let ms_expr = BtcTree::from_str(&ms_str)?;
            //
            // TODO: Confirm with Andrew about the descriptor type for dynafed
            // Assuming sh(wsh) for now.
            let fed_desc = BtcDescriptor::<Pk>::from_tree(&ms_expr)?;
            let elem_desc = Descriptor::<Pk, CovenantExt<CovExtArgs>>::from_tree(&top.args[1])?;
            Ok(Pegin::new(fed_desc, elem_desc))
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing legacy_pegin descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
);

impl_from_str!(
    Pegin<Pk>,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(&top)
    }
);

impl<Pk: MiniscriptKey> Pegin<Pk> {
    /// Checks whether the descriptor is safe.
    pub fn sanity_check(&self) -> Result<(), Error> {
        self.fed_desc
            .sanity_check()
            .map_err(|_| Error::Unexpected("Federation script sanity check failed".to_string()))?;
        self.elem_desc
            .sanity_check()
            .map_err(|_| Error::Unexpected("Federation script sanity check failed".to_string()))?;
        Ok(())
    }

    /// Computes the Bitcoin address of the pegin descriptor, if one exists.
    /// Requires the secp context to compute the tweak
    pub fn bitcoin_address<C: secp256k1_zkp::Verification>(
        &self,
        network: bitcoin::Network,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> Result<bitcoin::Address, Error>
    where
        Pk: ToPublicKey,
    {
        // TODO
        Ok(bitcoin::Address::p2shwsh(
            &self
                .bitcoin_witness_script(secp)
                .expect("DO this cleanly after TR. Pay to taproot pegins unspecified till now"),
            network,
        ))
    }

    /// Computes the bitcoin scriptpubkey of the descriptor.
    /// Requires the secp context to compute the tweak
    pub fn bitcoin_script_pubkey<C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> BtcScript
    where
        Pk: ToPublicKey,
    {
        self.bitcoin_address(bitcoin::Network::Bitcoin, secp)
            .expect("Address cannot fail for pegin")
            .script_pubkey()
    }

    /// Computes the scriptSig that will be in place for an unsigned
    /// input spending an output with this descriptor. For pre-segwit
    /// descriptors, which use the scriptSig for signatures, this
    /// returns the empty script.
    ///
    /// This is used in Segwit transactions to produce an unsigned
    /// transaction whose txid will not change during signing (since
    /// only the witness data will change).
    /// Requires the secp context to compute the tweak
    pub fn bitcoin_unsigned_script_sig<C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> BtcScript
    where
        Pk: ToPublicKey,
    {
        let witness_script = self
            .bitcoin_witness_script(secp)
            .expect("TODO after taproot");
        script::Builder::new()
            .push_slice(&witness_script.to_v0_p2wsh()[..])
            .into_script()
    }

    /// Computes the bitcoin "witness script" of the descriptor, i.e. the underlying
    /// script before any hashing is done. For `Bare`, `Pkh` and `Wpkh` this
    /// is the scriptPubkey; for `ShWpkh` and `Sh` this is the redeemScript;
    /// for the others it is the witness script.
    pub fn bitcoin_witness_script<C: secp256k1_zkp::Verification>(
        &self,
        _secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> Result<BtcScript, Error>
    where
        Pk: ToPublicKey,
    {
        let tweak_vec = self
            .elem_desc
            .explicit_script()
            .expect("Tr pegins unknown yet")
            .into_bytes();
        let _tweak = hashes::sha256::Hash::hash(&tweak_vec);

        unreachable!("TODO: After upstream Refactor for Translator trait")
        // let derived = self.fed_desc.derive

        // struct TranslateTweak<'a, C: secp256k1_zkp::Verification>(
        //     hashes::sha256::Hash,
        //     &'a secp256k1_zkp::Secp256k1<C>,
        // );

        // impl<'a, Pk, C> PkTranslator<Pk, bitcoin::PublicKey, ()> for TranslateTweak<'a, C>
        // where
        //     Pk: MiniscriptKey,
        //     C: secp256k1_zkp::Verification,
        // {
        //     fn pk(&mut self, pk: &Pk) -> Result<bitcoin::PublicKey, ()> {
        //         tweak_key(pk, self.1, self.0.as_inner())
        //     }

        //     fn pkh(
        //         &mut self,
        //         pkh: &<Pk as MiniscriptKey>::Hash,
        //     ) -> Result<<bitcoin::PublicKey as MiniscriptKey>::Hash, ()> {
        //         unreachable!("No keyhashes in elements descriptors")
        //     }
        // }
        // let mut t = TranslateTweak(tweak, secp);

        // let tweaked_desc = <bitcoin_miniscript::TranslatePk>::translate_pk(&self.fed_desc, t).expect("Tweaking must succeed"),
        // Ok(tweaked_desc.explicit_script()?)
    }

    /// Returns satisfying witness and scriptSig to spend an
    /// output controlled by the given descriptor if it possible to
    /// construct one using the satisfier S.
    pub fn get_bitcoin_satisfaction<S, C: secp256k1_zkp::Verification>(
        &self,
        _secp: &secp256k1_zkp::Secp256k1<C>,
        _satisfier: S,
    ) -> Result<(Vec<Vec<u8>>, BtcScript), Error>
    where
        S: BtcSatisfier<bitcoin::PublicKey>,
        Pk: ToPublicKey,
    {
        let tweak_vec = self
            .elem_desc
            .explicit_script()
            .expect("Tr pegins unknown yet")
            .into_bytes();
        let _tweak = hashes::sha256::Hash::hash(&tweak_vec);
        unreachable!("TODO: After upstream refactor");
        // let tweaked_desc = self.fed_desc.translate_pk_infallible(
        //     |pk| tweak_key(pk, secp, tweak.as_inner()),
        //     |_| unreachable!("No keyhashes in elements descriptors"),
        // );
        // let res = tweaked_desc.get_satisfaction(satisfier)?;
        // Ok(res)
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction. Assumes all signatures are 73 bytes, including push opcode
    /// and sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    // FIXME: the ToPublicKey bound here should not needed. Fix after upstream
    pub fn max_satisfaction_weight(&self) -> Result<usize, Error>
    where
        Pk: ToPublicKey,
    {
        // tweaking does not change max satisfaction weight
        let w = self.fed_desc.max_satisfaction_weight()?;
        Ok(w)
    }

    /// Get the `scriptCode` of a transaction output.
    ///
    /// The `scriptCode` is the Script of the previous transaction output being serialized in the
    /// sighash when evaluating a `CHECKSIG` & co. OP code.
    pub fn script_code<C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> Result<BtcScript, Error>
    where
        Pk: ToPublicKey,
    {
        self.bitcoin_witness_script(secp)
    }

    /// Get the corresponding elements descriptor that would be used
    /// at redeem time by the user.
    /// Users can use the DescrpitorTrait operations on the output Descriptor
    /// to obtain the characteristics of the elements descriptor.
    pub fn into_user_descriptor(self) -> Descriptor<Pk, CovenantExt<CovExtArgs>> {
        self.elem_desc
    }
}
