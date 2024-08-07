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

use std::convert::TryFrom;
use std::fmt;

use bitcoin::blockdata::script::{self, PushBytes};
use bitcoin::hashes::Hash;
use bitcoin::{self, hashes, ScriptBuf as BtcScript};
use elements::secp256k1_zkp;

use crate::descriptor::checksum::{desc_checksum, verify_checksum};
use crate::expression::{self, FromTree};
use crate::extensions::{CovExtArgs, CovenantExt};
use crate::policy::{semantic, Liftable};
use crate::{
    tweak_key, BtcDescriptor, BtcError, BtcFromTree, BtcLiftable, BtcPolicy, BtcSatisfier, BtcTree,
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
        let push_bytes = <&PushBytes>::try_from(witness_script.as_bytes())
            .expect("Witness script is not too larg");
        script::Builder::new().push_slice(push_bytes).into_script()
    }

    /// Computes the bitcoin "witness script" of the descriptor, i.e. the underlying
    /// script before any hashing is done. For `Bare`, `Pkh` and `Wpkh` this
    /// is the scriptPubkey; for `ShWpkh` and `Sh` this is the redeemScript;
    /// for the others it is the witness script.
    pub fn bitcoin_witness_script<C: secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
    ) -> Result<BtcScript, Error>
    where
        Pk: ToPublicKey,
    {
        let tweak_vec = self
            .elem_desc
            .explicit_script()
            .expect("Tr pegins unknown yet")
            .into_bytes();
        bitcoin_witness_script(&self.fed_desc, &tweak_vec[..], secp)
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
        let w = self.fed_desc.max_weight_to_satisfy()?;
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

fn bitcoin_witness_script<C: secp256k1_zkp::Verification, Pk: ToPublicKey>(
    fed_desc: &BtcDescriptor<Pk>,
    claim_script: &[u8],
    secp: &secp256k1_zkp::Secp256k1<C>,
) -> Result<BtcScript, Error> {
    struct TranslateTweak<'a, 'b, C: secp256k1_zkp::Verification>(
        &'a [u8],
        &'b secp256k1_zkp::Secp256k1<C>,
    );

    impl<'a, 'b, Pk, C> bitcoin_miniscript::Translator<Pk, bitcoin::PublicKey, ()>
        for TranslateTweak<'a, 'b, C>
    where
        Pk: MiniscriptKey + ToPublicKey,
        C: secp256k1_zkp::Verification,
    {
        fn pk(&mut self, pk: &Pk) -> Result<bitcoin::PublicKey, ()> {
            Ok(tweak_key(&pk.to_public_key(), self.1, &self.0[..]))
        }

        // We don't need to implement these methods as we are not using them in the policy.
        // Fail if we encounter any hash fragments. See also translate_hash_clone! macro.
        translate_hash_fail!(Pk, bitcoin::PublicKey, ());
    }
    let mut t = TranslateTweak(claim_script, secp);

    let tweaked_desc = bitcoin_miniscript::TranslatePk::translate_pk(fed_desc, &mut t)
        .expect("Tweaking must succeed");
    Ok(tweaked_desc.explicit_script()?)
}

#[cfg(test)]
mod tests {
    use elements::hex::FromHex;

    use crate::BtcDescriptor;

    // test vector created with:
    // ```
    // $ elements-cli getnetworkinfo | jq .version
    // 230201
    // $ elements-cli getblockchaininfo | jq .blocks
    // 2976078
    // elements-cli getsidechaininfo | jq '.current_fedpegscripts[0]'`
    // "5b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc401021031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb2103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5fae736402c00fb269522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae68"
    // $ elements-cli getpeginaddress
    // {
    // "mainchain_address": "bc1qyya0twwz58kgfslpdgsygeq0r4nngl9tkt89v6phk8nqrwyenwrq5h0dk8",
    // "claim_script": "0014a15906e643f2c9635527ab8658d370e8eaf149b5"
    // }
    // ```
    #[test]
    fn test_pegin() {
        let fedpegscript ="5b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc401021031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb2103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5fae736402c00fb269522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae68";
        let s = bitcoin::ScriptBuf::from_hex(fedpegscript).unwrap();

        type Segwitv0Script =
            bitcoin_miniscript::Miniscript<bitcoin::PublicKey, bitcoin_miniscript::Segwitv0>;

        let m = Segwitv0Script::parse(&s).unwrap();
        assert_eq!(m.encode(), s);

        let d = BtcDescriptor::<_>::new_wsh(m).unwrap();

        let fedpegdesc = "wsh(or_d(multi(11,020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261,02675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af99,02896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d48,029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c,02a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc4010,031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb,03079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b,03111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2,0318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa0840174,03230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de1,035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a6,03bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c,03cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d17546,03d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d424828,03ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a),and_v(v:older(4032),multi(2,03aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79,0291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807,0386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb))))#7jwwklk4";
        assert_eq!(&d.to_string(), fedpegdesc);

        let claimscript =
            Vec::<u8>::from_hex("0014de8e299d5347503f7ee33247e780b7f412727623").unwrap();
        let secp = secp256k1::Secp256k1::new();

        let mainchain_address = "bc1qssx7ha3zxpq25l6uukphlwj3jumvmcv8qr3dy6uy8l8j4vwa5fhswpcw3p";

        let s = super::bitcoin_witness_script(&d, &claimscript, &secp).unwrap();
        let b = bitcoin::Address::p2wsh(&s, bitcoin::Network::Bitcoin);
        assert_eq!(mainchain_address, b.to_string());
    }
}
