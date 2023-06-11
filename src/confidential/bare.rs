// Miniscript
// Written in 2023 by
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

//! "Bare Key" Confidential Descriptors

use bitcoin::hashes::{sha256t_hash_newtype, Hash};
use elements::encode::Encodable;
use elements::secp256k1_zkp;

use crate::ToPublicKey;

/// The SHA-256 initial midstate value for the [`TweakHash`].
const MIDSTATE_HASH_TO_PRIVATE_HASH: [u8; 32] = [
    0x2f, 0x85, 0x61, 0xec, 0x30, 0x88, 0xad, 0xa9, 0x5a, 0xe7, 0x43, 0xcd, 0x3c, 0x5f, 0x59, 0x7d,
    0xc0, 0x4b, 0xd0, 0x7f, 0x06, 0x5f, 0x1c, 0x06, 0x47, 0x89, 0x36, 0x63, 0xf3, 0x92, 0x6e, 0x65,
];

sha256t_hash_newtype!(
    TweakHash,
    TweakTag,
    MIDSTATE_HASH_TO_PRIVATE_HASH,
    64,
    doc = "BIP-340 Tagged hash for tweaking blinding keys",
    forward
);

/// Tweaks a bare key using the scriptPubKey of a descriptor
pub fn tweak_key<'a, Pk, V>(
    secp: &secp256k1_zkp::Secp256k1<V>,
    spk: &elements::Script,
    pk: &Pk,
) -> secp256k1_zkp::PublicKey
where
    Pk: ToPublicKey + 'a,
    V: secp256k1_zkp::Verification,
{
    let mut eng = TweakHash::engine();
    pk.to_public_key()
        .write_into(&mut eng)
        .expect("engines don't error");
    spk.consensus_encode(&mut eng).expect("engines don't error");
    let hash_bytes = TweakHash::from_engine(eng).to_byte_array();
    let hash_scalar = secp256k1_zkp::Scalar::from_be_bytes(hash_bytes).expect("bytes from hash");
    pk.to_public_key()
        .inner
        .add_exp_tweak(secp, &hash_scalar)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::sha256t::Tag;
    use bitcoin::hashes::{sha256, HashEngine};

    use super::*;

    #[test]
    fn tagged_hash() {
        // Check that cached midstate is computed correctly
        // This code taken from `tag_engine` in the rust-bitcoin tests; it is identical
        // to that used by the BIP-0340 hashes in Taproot
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(b"CT-Blinding-Key/1.0");
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(
            MIDSTATE_HASH_TO_PRIVATE_HASH,
            engine.midstate().to_byte_array()
        );

        // Test empty hash
        assert_eq!(
            TweakHash::from_engine(TweakTag::engine()).to_string(),
            "d12a140aca856fbb917b931f263c42f064608985e2ce17ae5157daa17c55e8d9",
        );
        assert_eq!(
            TweakHash::hash(&[]).to_string(),
            "d12a140aca856fbb917b931f263c42f064608985e2ce17ae5157daa17c55e8d9",
        );

        // And hash of 100 bytes
        let data: Vec<u8> = (0..80).collect();
        assert_eq!(
            TweakHash::hash(&data).to_string(),
            "e1e52419a2934d278c50e29608969d2f23c1bd1243a09bfc8026d4ed4b085e39",
        );
    }
}
