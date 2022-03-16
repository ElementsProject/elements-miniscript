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

use bitcoin::hashes::Hash;
use bitcoin::{self, blockdata::script, hashes};
use bitcoin::{secp256k1, Script as BtcScript};
use expression::{self, FromTree};
use policy::{semantic, Liftable};
use std::{fmt, str::FromStr};
use Descriptor;
use Error;
use {
    BtcDescriptor, BtcDescriptorTrait, BtcError, BtcFromTree, BtcLiftable, BtcPolicy, BtcSatisfier,
    BtcTree,
};

use {DescriptorTrait, TranslatePk};

use tweak_key;

use descriptor::checksum::{desc_checksum, verify_checksum};

use super::PeginTrait;
use {MiniscriptKey, ToPublicKey};

/// New Pegin Descriptor with Miniscript support
/// Useful with dynamic federations
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
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

impl<Pk: MiniscriptKey> fmt::Debug for Pegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "pegin({:?},{:?})", self.fed_desc, self.elem_desc)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Pegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

impl<Pk: MiniscriptKey> FromTree for Pegin<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "pegin" && top.args.len() == 2 {
            // a roundtrip hack to use FromTree from bitcoin::Miniscript from
            // expression::Tree in elements.
            let ms_str = top.args[0].to_string();
            let ms_expr = BtcTree::from_str(&ms_str)?;
            //
            // TODO: Confirm with Andrew about the descriptor type for dynafed
            // Assuming sh(wsh) for now.
            let fed_desc = BtcDescriptor::<Pk>::from_tree(&ms_expr)?;
            let elem_desc = Descriptor::<Pk>::from_tree(&top.args[1])?;
            Ok(Pegin::new(fed_desc, elem_desc))
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing legacy_pegin descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
}

impl<Pk: MiniscriptKey> FromStr for Pegin<Pk>
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

impl<Pk: MiniscriptKey> PeginTrait<Pk> for Pegin<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn sanity_check(&self) -> Result<(), Error> {
        self.fed_desc
            .sanity_check()
            .map_err(|_| Error::Unexpected(format!("Federation script sanity check failed")))?;
        self.elem_desc
            .sanity_check()
            .map_err(|_| Error::Unexpected(format!("Federation script sanity check failed")))?;
        Ok(())
    }

    fn bitcoin_address<C: secp256k1::Verification>(
        &self,
        network: bitcoin::Network,
        secp: &secp256k1::Secp256k1<C>,
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

    fn bitcoin_script_pubkey<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> BtcScript
    where
        Pk: ToPublicKey,
    {
        self.bitcoin_address(bitcoin::Network::Bitcoin, secp)
            .expect("Address cannot fail for pegin")
            .script_pubkey()
    }

    fn bitcoin_unsigned_script_sig<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
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

    fn bitcoin_witness_script<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<BtcScript, Error>
    where
        Pk: ToPublicKey,
    {
        let tweak_vec = self.elem_desc.explicit_script().into_bytes();
        let tweak = hashes::sha256::Hash::hash(&tweak_vec);
        let tweaked_desc = self.fed_desc.translate_pk_infallible(
            |pk| tweak_key(pk, secp, tweak.as_inner()),
            |_| unreachable!("No keyhashes in elements descriptors"),
        );
        // Hopefully, we never have to use this and dynafed is deployed
        Ok(tweaked_desc.explicit_script()?)
    }

    fn get_bitcoin_satisfaction<S, C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        satisfier: S,
    ) -> Result<(Vec<Vec<u8>>, BtcScript), Error>
    where
        S: BtcSatisfier<bitcoin::PublicKey>,
        Pk: ToPublicKey,
    {
        let tweak_vec = self.elem_desc.explicit_script().into_bytes();
        let tweak = hashes::sha256::Hash::hash(&tweak_vec);
        let tweaked_desc = self.fed_desc.translate_pk_infallible(
            |pk| tweak_key(pk, secp, tweak.as_inner()),
            |_| unreachable!("No keyhashes in elements descriptors"),
        );
        let res = tweaked_desc.get_satisfaction(satisfier)?;
        Ok(res)
    }

    fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        // tweaking does not change max satisfaction weight
        let w = self.fed_desc.max_satisfaction_weight()?;
        Ok(w)
    }

    fn script_code<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<BtcScript, Error>
    where
        Pk: ToPublicKey,
    {
        self.bitcoin_witness_script(secp)
    }

    fn into_user_descriptor(self) -> Descriptor<Pk> {
        self.elem_desc
    }
}
