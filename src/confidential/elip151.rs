// Miniscript
// Written in 2023 by Leonardo Comandini
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

//! ELIP151
//!
//! Implementation of the ELIP151 protocol, documented at
//! https://github.com/ElementsProject/ELIPs/blob/main/elip-0151.md
//!

use bitcoin::hashes::{sha256t_hash_newtype, Hash};
use bitcoin::secp256k1;
use bitcoin::Network;
use elements::encode::Encodable;
use elements::opcodes;
use elements::script::Builder;

use crate::confidential::{Descriptor as ConfidentialDescriptor, Key};
use crate::descriptor::{DescriptorSecretKey, SinglePriv};
use crate::extensions::{Extension, ParseableExt};
use crate::{Descriptor as OrdinaryDescriptor, DescriptorPublicKey, Error};

sha256t_hash_newtype! {
    pub struct Elip151Tag = hash_str("Deterministic-View-Key/1.0");
    /// ELIP-151 Deterministic descriptor blinding keys
    #[hash_newtype(forward)]
    pub struct Elip151Hash(_);
}

impl Key {
    pub fn from_elip151<T: Extension + ParseableExt>(
        descriptor: &OrdinaryDescriptor<DescriptorPublicKey, T>,
    ) -> Result<Self, Error> {
        if !descriptor.has_wildcard() {
            return Err(Error::Unexpected(
                "Descriptors without wildcards are not supported in elip151".into(),
            ));
        }

        // Handle multi-path
        let script_pubkeys: Vec<_> = descriptor
            .clone()
            .into_single_descriptors()
            .expect("valid descriptor")
            .iter()
            .map(|descriptor| {
                // Remove wildcards
                descriptor
                    .at_derivation_index((1 << 31) - 1)
                    .expect("index not hardened, not multi-path")
                    .script_pubkey()
            })
            .collect();

        let mut eng = Elip151Hash::engine();
        for script_pubkey in script_pubkeys {
            Builder::new()
                .push_opcode(opcodes::all::OP_INVALIDOPCODE)
                .into_script()
                .consensus_encode(&mut eng)
                .expect("engines don't error");
            script_pubkey
                .consensus_encode(&mut eng)
                .expect("engines don't error");
        }
        let hash_bytes = Elip151Hash::from_engine(eng).to_byte_array();

        // This computes mod n
        let scalar = secp256k1::scalar::Scalar::from_be_bytes(hash_bytes).expect("bytes from hash");
        let secret_key =
            secp256k1::SecretKey::from_slice(&scalar.to_be_bytes()).expect("bytes from scalar");

        // Single view keys are displayed as hex (not WIF) so we can choose any netowrk here
        let network = Network::Bitcoin;
        Ok(Key::View(DescriptorSecretKey::Single(SinglePriv {
            origin: None,
            key: bitcoin::key::PrivateKey::new(secret_key, network),
        })))
    }
}

impl<T: Extension + ParseableExt> ConfidentialDescriptor<DescriptorPublicKey, T> {
    pub fn with_elip151_descriptor_blinding_key(
        descriptor: OrdinaryDescriptor<DescriptorPublicKey, T>,
    ) -> Result<Self, Error> {
        Ok(ConfidentialDescriptor {
            key: Key::from_elip151(&descriptor)?,
            descriptor,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::descriptor::checksum::desc_checksum;
    use bitcoin::hashes::{sha256, HashEngine, sha256t::Tag};
    use std::str::FromStr;

    /// The SHA-256 initial midstate value for the [`Elip151Hash`].
    const MIDSTATE_ELIP151: [u8; 32] = [
        0x49, 0x81, 0x61, 0xd8, 0x52, 0x45, 0xf7, 0xaa, 0xd8, 0x24, 0x27, 0xb5, 0x64, 0x69, 0xe7,
        0xd6, 0x98, 0x17, 0xeb, 0x0f, 0x27, 0x14, 0x6f, 0x4e, 0x7b, 0x95, 0xb3, 0x6e, 0x46, 0xc1,
        0xb5, 0x61,
    ];

    #[test]
    fn tagged_hash_elip151() {
        // Check that cached midstate is computed correctly, code from rust-bitcoin
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(b"Deterministic-View-Key/1.0");
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(MIDSTATE_ELIP151, engine.midstate().to_byte_array());

        // Test empty hash
        let expected = "dcd8403dcf5af960f69fa41d114931a840877dfb5378046018f78ea894a36ebd";
        assert_eq!(Elip151Hash::from_engine(Elip151Tag::engine()).to_string(), expected);
        assert_eq!(Elip151Hash::hash(&[]).to_string(), expected);
    }

    fn add_checksum(desc: &str) -> String {
        if desc.find('#').is_some() {
            desc.into()
        } else {
            format!("{}#{}", desc, desc_checksum(desc).unwrap())
        }
    }

    fn confidential_descriptor(
        desc: &str,
    ) -> Result<ConfidentialDescriptor<DescriptorPublicKey>, Error> {
        let desc = add_checksum(desc);
        let desc = OrdinaryDescriptor::<DescriptorPublicKey>::from_str(&desc).unwrap();
        ConfidentialDescriptor::with_elip151_descriptor_blinding_key(desc)
    }

    fn _first_address(desc: &ConfidentialDescriptor<DescriptorPublicKey>) -> String {
        let single_desc = if desc.descriptor.is_multipath() {
            let descriptor = desc
                .descriptor
                .clone()
                .into_single_descriptors()
                .unwrap()
                .first()
                .unwrap()
                .clone();
            ConfidentialDescriptor {
                key: desc.key.clone(),
                descriptor,
            }
        } else {
            desc.clone()
        };
        let definite_desc = single_desc.at_derivation_index(0).unwrap();
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let params = &elements::AddressParams::LIQUID;
        definite_desc.address(&secp, params).unwrap().to_string()
    }

    #[test]
    fn test_vectors_elip151() {
        let xpub = "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8";
        let pubkey = "03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494";

        let mut _i = 0;
        for (desc, key) in [
            (&format!("elwpkh({xpub}/<0;1>/*)"), "b3baf94d60cf8423cd257283575997a2c00664ced3e8de00f8726703142b1989"),
            (&format!("elwpkh({xpub}/0/*)"), "de9c5fb624154624146a8aea0489b30f05c720eed6b493b1f3ab63405a11bf37"),
        ] {
            let conf_desc = confidential_descriptor(desc).unwrap();
            let elip151_desc = add_checksum(&format!("ct(elip151,{})", desc));
            let conf_desc_elip151 =
                ConfidentialDescriptor::<DescriptorPublicKey>::from_str(&elip151_desc).unwrap();
            assert_eq!(conf_desc, conf_desc_elip151);
            assert_eq!(conf_desc.key.to_string(), key);

            // Uncomment this and below to regenerate test vectors; to see the output, run
            // cargo test test_vectors_elip151 -- --nocapture
            /*
            _i = _i + 1;
            println!("* Test vector {}", _i);
            println!("** Ordinary descriptor: <code>{}</code>", add_checksum(desc));
            println!("** Derived descriptor blinding key: <code>{}</code>", conf_desc.key);
            println!("** Derived confidential descriptor: <code>{}</code>", conf_desc);
            println!("** Derived confidential descriptor (equivalent version): <code>{}</code>", elip151_desc);
            println!("** First address: <code>{}</code>", _first_address(&conf_desc))
            */
        }

        _i = 0;
        for invalid_desc in [&format!("elwpkh({xpub})"), &format!("elwpkh({pubkey})")] {
            let err = confidential_descriptor(invalid_desc).unwrap_err();
            let text = "Descriptors without wildcards are not supported in elip151".to_string();
            assert_eq!(err, Error::Unexpected(text));
            /*
            _i = _i + 1;
            println!("* Invalid Test vector {}", _i);
            println!("** Ordinary descriptor: <code>{}</code>", add_checksum(invalid_desc));
            println!("** Invalid confidential descriptor: <code>{}</code>", add_checksum(&format!("ct(elip151,{})", invalid_desc)));
            */
        }
    }
}
