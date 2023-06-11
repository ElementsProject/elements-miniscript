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

//! SLIP77
//!
//! Implementation of the SLIP77 protocol, documented at
//! https://github.com/satoshilabs/slips/blob/master/slip-0077.md
//!

use std::{borrow, fmt};

use elements::hashes::{hex, sha256, sha512, Hash, HashEngine, Hmac, HmacEngine};
use elements::secp256k1_zkp;

/// A master blinding key, used for SLIP77-derived confidential addresses
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MasterBlindingKey([u8; 32]);

impl fmt::Display for MasterBlindingKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        elements::hex::format_hex(&self.0, f)
    }
}

impl From<[u8; 32]> for MasterBlindingKey {
    fn from(x: [u8; 32]) -> Self {
        MasterBlindingKey(x)
    }
}

impl borrow::Borrow<[u8]> for MasterBlindingKey {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl MasterBlindingKey {
    /// Compute a master blinding key from a seed
    ///
    /// The recommended in (SLIP-39) source of this seed is to obtain the
    /// 64-byte seed from a BIP39 derivation.
    pub fn from_seed(seed: &[u8]) -> Self {
        const DOMAIN: &[u8] = b"Symmetric key seed";
        let mut root_eng = HmacEngine::<sha512::Hash>::new(DOMAIN);
        root_eng.input(seed);
        let root = Hmac::from_engine(root_eng);

        const LABEL: &[u8] = b"SLIP-0077";
        let mut node_eng = HmacEngine::<sha512::Hash>::new(&root[0..32]);
        node_eng.input(&[0]);
        node_eng.input(LABEL);
        let node = Hmac::from_engine(node_eng);

        let mut ret = [0; 32];
        ret.copy_from_slice(&node[32..64]);
        MasterBlindingKey(ret)
    }

    /// Accessor for the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derives a blinding private key from a given script pubkey
    pub fn blinding_private_key(&self, spk: &elements::Script) -> secp256k1_zkp::SecretKey {
        let mut eng = HmacEngine::<sha256::Hash>::new(&self.0);
        eng.input(spk.as_bytes());
        // lol why is this conversion so hard
        secp256k1_zkp::SecretKey::from_slice(&Hmac::from_engine(eng).to_byte_array()).unwrap()
    }

    /// Derives a public private key from a given script pubkey
    pub fn blinding_key<C: secp256k1_zkp::Signing>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
        spk: &elements::Script,
    ) -> secp256k1_zkp::PublicKey {
        let sk = self.blinding_private_key(spk);
        secp256k1_zkp::PublicKey::from_secret_key(secp, &sk)
    }
}

impl hex::FromHex for MasterBlindingKey {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where
        I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        Ok(MasterBlindingKey(<[u8; 32]>::from_byte_iter(iter)?))
    }
}

impl std::str::FromStr for MasterBlindingKey {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::FromHex::from_hex(s)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use elements::hashes::hex::FromHex;

    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        elements::hex::FromHex::from_hex(s).unwrap()
    }

    #[test]
    fn mbk_from_seed() {
        // taken from libwally src/test/test_confidential_addr.py
        let mbk = MasterBlindingKey::from_seed(&unhex("c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8"));
        assert_eq!(
            mbk.as_bytes(),
            &unhex("6c2de18eabeff3f7822bc724ad482bef0557f3e1c1e1c75b7a393a5ced4de616")[..]
        );

        let secp = secp256k1_zkp::Secp256k1::new();
        let spk = elements::Script::from_str("76a914a579388225827d9f2fe9014add644487808c695d88ac")
            .unwrap();
        let mut addr = elements::Address::from_str("2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr").unwrap();
        addr.blinding_pubkey = Some(mbk.blinding_key(&secp, &spk));
        assert_eq!(
            addr.to_string(),
            "CTEkf75DFff5ReB7juTg2oehrj41aMj21kvvJaQdWsEAQohz1EDhu7Ayh6goxpz3GZRVKidTtaXaXYEJ"
        );
    }

    #[test]
    fn local_test_elements_22_0() {
        // Local test on elements 22.0
        let mbk = MasterBlindingKey::from_hex(
            "64269a8de756da06ebe35d26dccb4dd46bddcf858b54eeaae315490cfe6cacc0",
        )
        .unwrap();

        let addr = elements::Address::from_str(
            "el1qqg2pz79c0reryhr6hzxrzueju9m2asllwydrhexs6vj854cvwlen4tryh4thsdt2a26rte3fe87rf3my9t90wt78pcqrxv733",
        )
        .unwrap();

        let derived_blinding_key = mbk.blinding_private_key(&addr.script_pubkey());
        assert_eq!(
            derived_blinding_key,
            secp256k1_zkp::SecretKey::from_slice(&unhex(
                "791a1081ae2ad98a5ad603737c648247f19d3c26e2beb54617638172edb230e7"
            ))
            .unwrap()
        );
    }
}
