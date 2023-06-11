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

//! Confidential Descriptors
//!
//! Implements ELIP ????, described at `URL`
//!

pub mod bare;
pub mod slip77;

use std::fmt;

use elements::secp256k1_zkp;

use crate::descriptor::checksum::{desc_checksum, verify_checksum};
use crate::expression::FromTree;
use crate::extensions::{CovExtArgs, CovenantExt, Extension, ParseableExt};
use crate::{expression, Error, MiniscriptKey, ToPublicKey};

/// A description of a blinding key
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Key<Pk: MiniscriptKey> {
    /// Blinding key is computed using SLIP77 with the given master key
    Slip77(slip77::MasterBlindingKey),
    /// Blinding key is given directly
    Bare(Pk),
}

impl<Pk: MiniscriptKey> fmt::Display for Key<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Key::Slip77(data) => write!(f, "slip77({})", data),
            Key::Bare(pk) => fmt::Display::fmt(pk, f),
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Key<Pk> {
    fn to_public_key<C: secp256k1_zkp::Signing + secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
        spk: &elements::Script,
    ) -> secp256k1_zkp::PublicKey {
        match *self {
            Key::Slip77(ref mbk) => mbk.blinding_key(secp, spk),
            Key::Bare(ref pk) => bare::tweak_key(secp, spk, pk),
        }
    }
}

/// A confidential descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Descriptor<Pk: MiniscriptKey, T: Extension = CovenantExt<CovExtArgs>> {
    /// The blinding key
    pub key: Key<Pk>,
    /// The script descriptor
    pub descriptor: crate::Descriptor<Pk, T>,
}

impl<Pk: MiniscriptKey, T: Extension> Descriptor<Pk, T> {
    /// Sanity checks for the underlying descriptor.
    pub fn sanity_check(&self) -> Result<(), Error> {
        self.descriptor.sanity_check()?;
        Ok(())
    }
}

impl<Pk: MiniscriptKey + ToPublicKey, T: Extension + ParseableExt> Descriptor<Pk, T> {
    /// Obtains the unblinded address for this descriptor.
    pub fn unconfidential_address(
        &self,
        params: &'static elements::AddressParams,
    ) -> Result<elements::Address, Error> {
        self.descriptor.address(params)
    }

    /// Obtains the blinded address for this descriptor.
    pub fn address<C: secp256k1_zkp::Signing + secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
        params: &'static elements::AddressParams,
    ) -> Result<elements::Address, Error> {
        let spk = self.descriptor.script_pubkey();
        self.descriptor
            .blinded_address(self.key.to_public_key(secp, &spk), params)
    }
}

impl<Pk: MiniscriptKey, T: Extension> fmt::Display for Descriptor<Pk, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc_str = format!("ct({},{:#})", self.key, self.descriptor);
        let checksum = desc_checksum(&desc_str).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", desc_str, checksum)
    }
}

impl_from_str!(
    ;T; Extension,
    Descriptor<Pk, T>,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Descriptor<Pk, T>, Error> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;

        if top.name != "ct" {
            return Err(Error::BadDescriptor(String::from(
                "Not a CT Descriptor",
            )));
        }
        if top.args.len() != 2 {
            return Err(Error::BadDescriptor(
                format!("CT descriptor had {} arguments rather than 2", top.args.len())
            ));
        }

        let keyexpr = &top.args[0];
        Ok(Descriptor {
            key: match (keyexpr.name, keyexpr.args.len()) {
                ("slip77", 1) => Key::Slip77(expression::terminal(&keyexpr.args[0], slip77::MasterBlindingKey::from_str)?),
                ("slip77", _) => return Err(Error::BadDescriptor(
                    "slip77() must have exactly one argument".to_owned()
                )),
                _ => Key::Bare(expression::terminal(keyexpr, Pk::from_str)?),
            },
            descriptor: crate::Descriptor::from_tree(&top.args[1])?,
        })
    }
);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use elements::Address;

    use super::*;
    use crate::NoExt;

    #[test]
    fn bare_addr_to_confidential() {
        let secp = secp256k1_zkp::Secp256k1::new();

        // taken from libwally src/test/test_confidential_addr.py
        let mut addr = Address::from_str("Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6").unwrap();
        let key = Key::Bare(
            bitcoin::PublicKey::from_str(
                "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623",
            )
            .unwrap(),
        );
        addr.blinding_pubkey = Some(key.to_public_key(&secp, &addr.script_pubkey()));
        assert_eq!(
            addr.to_string(),
            "VTpt7krqRQPJwqe3XQXPg2cVdEKYVFbuprTr7es7pNRMe8mndnq2iYWddxJWYowhLAwoDF8QrZ1v2EXv"
        );
    }

    struct ConfidentialTest {
        key: Key<secp256k1_zkp::PublicKey>,
        descriptor: crate::Descriptor<secp256k1_zkp::PublicKey, NoExt>,
        descriptor_str: String,
        conf_addr: &'static str,
        unconf_addr: &'static str,
    }

    impl ConfidentialTest {
        fn check<C: secp256k1_zkp::Signing + secp256k1_zkp::Verification>(
            &self,
            secp: &secp256k1_zkp::Secp256k1<C>,
        ) {
            let desc: Descriptor<secp256k1_zkp::PublicKey, NoExt> = Descriptor {
                key: self.key,
                descriptor: self.descriptor.clone(),
            };
            assert_eq!(self.descriptor_str, desc.to_string());
            assert_eq!(desc, Descriptor::from_str(&desc.to_string()).unwrap());
            assert_eq!(
                self.conf_addr,
                desc.address(secp, &elements::AddressParams::ELEMENTS)
                    .unwrap()
                    .to_string(),
            );
            assert_eq!(
                self.unconf_addr,
                desc.unconfidential_address(&elements::AddressParams::ELEMENTS)
                    .unwrap()
                    .to_string(),
            );
        }
    }

    #[test]
    fn confidential_descriptor() {
        let secp = secp256k1_zkp::Secp256k1::new();

        // CT key used for bare keys
        let ct_key = secp256k1_zkp::PublicKey::from_str(
            "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623",
        )
        .unwrap();
        // Auxiliary key to create scriptpubkeys from
        let spk_key = secp256k1_zkp::PublicKey::from_str(
            "03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4",
        )
        .unwrap();

        let tests = vec![
            // Bare key, P2PKH
            ConfidentialTest {
                key: Key::Bare(ct_key),
                descriptor: crate::Descriptor::new_pkh(spk_key),
                descriptor_str: format!("ct({},elpkh({}))#y6sgetu5", ct_key, spk_key),
                conf_addr: "CTEp9vcs3eU7zQoyrAqeu9LwdcB8QtC2igYSWt7dhaEQvDwVCceLHdLrREAeYrhC5Jz9Wedn3JyxMzpo",
                unconf_addr: "2daq3zWYvigZd3i8VmBnFrZd4DPT9iV94EP",
            },
            // Bare key, P2WPKH
            ConfidentialTest {
                key: Key::Bare(ct_key),
                descriptor: crate::Descriptor::new_wpkh(spk_key).unwrap(),
                descriptor_str: format!("ct({},elwpkh({}))#h5e0p6m9", ct_key, spk_key),
                conf_addr: "el1qq0r6pegudzm0tzpszelc34qjln4fdxawgwmgnza63wwpzdy6jrm0grmqvvk2ce5ksnxcs9ecgtnryt7xg34060uctupg60d02",
                unconf_addr: "ert1qpasxxt9vv6tgfnvgzuuy9e3j9lryg6ha53x9q0",
            },
            // Bare key, P2SH-WPKH
            ConfidentialTest {
                key: Key::Bare(ct_key),
                descriptor: crate::Descriptor::new_sh_wpkh(spk_key).unwrap(),
                descriptor_str: format!("ct({},elsh(wpkh({})))#3kvhe0a8", ct_key, spk_key),
                conf_addr: "AzpsK7uqP1KVEMfDQvBXYUkpHmFagD3W4vaLe1X7uy8MS6nj41kNYnaexuXgx14PcbNnYAqBdCSWcbga",
                unconf_addr: "XQ7ffnJkhMwj1H8Ma6N1vcU9mqAa96wB9w",
            },
            // Bare key, P2TR
            ConfidentialTest {
                key: Key::Bare(ct_key),
                descriptor: crate::Descriptor::new_tr(spk_key, None).unwrap(),
                descriptor_str: format!("ct({},eltr({}))#ytq9w7f3", ct_key, spk_key),
                conf_addr: "el1pqw5c43qvxyvj52ua7crx7tv62zca5356rsx439dqkyyqyavpmq2hz6r5jd0rkpzukq6hd965kepcmwtxvg0fh4ak4f636gv25yky23ce6z5pdt3ksqn2",
                unconf_addr: "ert1pdp6fxh3mq3wtqdtkja2tvsudh9nxy85m67m25agayx92ztz9guvs9wr5lg",
            },
            // SLIP77, P2PKH
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_pkh(spk_key),
                descriptor_str: "ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))#8cdjnvav".into(),
                conf_addr: "CTEkBfH2b6fyhfpn2iW1aoLFrC9DHooTsa7ouxXDuKVjLNF3GwJdgqQn63GriXDvTs7ntSU8NwXGrLKg",
                unconf_addr: "2daq3zWYvigZd3i8VmBnFrZd4DPT9iV94EP",
            },
            // SLIP77, P2WPKH
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_wpkh(spk_key).unwrap(),
                descriptor_str: "ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))#z5dnzfhk".into(),
                conf_addr: "el1qqva2r6mg26rr86u9t3qz2amya9v3ckks9ztcxgur6y6pktfa26d2qrmqvvk2ce5ksnxcs9ecgtnryt7xg3406z5cvgcqsgt35",
                unconf_addr: "ert1qpasxxt9vv6tgfnvgzuuy9e3j9lryg6ha53x9q0",
            },
            // SLIP77, P2SH
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_sh_wpkh(spk_key).unwrap(),
                descriptor_str: "ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elsh(wpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4)))#qgjmm4as".into(),
                conf_addr: "AzprjJt3poXAJWLmanTHYB2zrkUMXiiVyCRhDS7VRRaXUsRqeCMi3vKe4YufizpYDyzvQFLsvjfMeLMD",
                unconf_addr: "XQ7ffnJkhMwj1H8Ma6N1vcU9mqAa96wB9w",
            },
            // SLIP77, P2TR
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_tr(spk_key, None).unwrap(),
                descriptor_str: "ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),eltr(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))#65xky8c4".into(),
                conf_addr: "el1pqgkj53t6cpqytk65s7dygws4a6hny3rrev7rw3r5gl7ymnjdqtt9k6r5jd0rkpzukq6hd965kepcmwtxvg0fh4ak4f636gv25yky23cehlfsszhd84mc",
                unconf_addr: "ert1pdp6fxh3mq3wtqdtkja2tvsudh9nxy85m67m25agayx92ztz9guvs9wr5lg",
            },
        ];

        for test in tests {
            test.check(&secp);
        }
    }
}
