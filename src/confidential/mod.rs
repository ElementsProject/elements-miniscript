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
pub mod elip151;
pub mod slip77;

use std::fmt;

use bitcoin::bip32;
use elements::secp256k1_zkp;

use crate::descriptor::checksum::{desc_checksum, verify_checksum};
use crate::descriptor::{
    ConversionError, DefiniteDescriptorKey, DescriptorSecretKey, DescriptorPublicKey,
    DescriptorXKey, Wildcard
};
use crate::expression::FromTree;
use crate::extensions::{CovExtArgs, CovenantExt, Extension, ParseableExt};
use crate::{expression, Error, MiniscriptKey, ToPublicKey};

/// A description of a blinding key
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Key {
    /// Blinding key is computed using SLIP77 with the given master key
    Slip77(slip77::MasterBlindingKey),
    /// Blinding key is given directly
    Bare(DescriptorPublicKey),
    /// Blinding key is given directly, as a secret key
    View(DescriptorSecretKey),
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Key::Slip77(data) => write!(f, "slip77({})", data),
            Key::Bare(pk) => fmt::Display::fmt(pk, f),
            Key::View(sk) => {
                if let DescriptorSecretKey::Single(sk) = sk {
                    crate::descriptor::maybe_fmt_master_id(f, &sk.origin)?;
                    for byte in &sk.key.inner.secret_bytes() {
                        write!(f, "{:02x}", byte)?;
                    }
                    Ok(())
                } else {
                    fmt::Display::fmt(sk, f)
                }
            }
        }
    }
}

impl Key {
    fn to_public_key<C: secp256k1_zkp::Signing + secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
        spk: &elements::Script,
    ) -> Result<secp256k1_zkp::PublicKey, Error> {
        match *self {
            Key::Slip77(ref mbk) => Ok(mbk.blinding_key(secp, spk)),
            Key::Bare(ref pk) => {
                if pk.is_multipath() {
                    Err(Error::Unexpected("multipath blinding key".into()))
                } else if pk.has_wildcard() {
                    Err(Error::Unexpected("wildcard blinding key".into()))
                } else {
                    // Convert into a DefiniteDescriptorKey, note that we are deriving the xpub
                    // since there is not wildcard.
                    // Consider adding DescriptorPublicKey::to_definite_descriptor
                    let pk = pk.clone().at_derivation_index(0).expect("single or xpub without wildcards");
                    Ok(bare::tweak_key(secp, spk, &pk))
                }
            },
            Key::View(ref sk) => {
                if sk.is_multipath() {
                    Err(Error::Unexpected("multipath blinding key".into()))
                } else {
                    let pk = sk.to_public(secp).expect("single or xprv");
                    if pk.has_wildcard() {
                        Err(Error::Unexpected("wildcard blinding key".into()))
                    } else {
                        let pk = pk.at_derivation_index(0).expect("single or xprv without wildcards");
                        Ok(bare::tweak_key(secp, spk, &pk))
                    }
                }
            },
        }
    }
}

/// A confidential descriptor
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Descriptor<Pk: MiniscriptKey, T: Extension = CovenantExt<CovExtArgs>> {
    /// The blinding key
    pub key: Key,
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

impl<T: Extension + ParseableExt> Descriptor<DescriptorPublicKey, T> {
    /// Replaces all wildcards (i.e. `/*`) in the descriptor and the descriptor blinding key
    /// with a particular derivation index, turning it into a *definite* descriptor.
    ///
    /// # Errors
    /// - If index ≥ 2^31
    pub fn at_derivation_index(&self, index: u32) -> Result<Descriptor<DefiniteDescriptorKey, T>, ConversionError> {
        let definite_key = match self.key.clone() {
            Key::Slip77(k) => Key::Slip77(k),
            Key::Bare(k) => Key::Bare(k.at_derivation_index(index)?.into_descriptor_public_key()),
            Key::View(k) => Key::View(match k {
                // Consider implementing DescriptorSecretKey::at_derivation_index
                DescriptorSecretKey::Single(_) => k,
                DescriptorSecretKey::XPrv(xprv) => {
                    let derivation_path = match xprv.wildcard {
                        Wildcard::None => xprv.derivation_path,
                        Wildcard::Unhardened => xprv.derivation_path.into_child(
                            bip32::ChildNumber::from_normal_idx(index)
                                .ok()
                                .ok_or(ConversionError::HardenedChild)?,
                        ),
                        Wildcard::Hardened => xprv.derivation_path.into_child(
                            bip32::ChildNumber::from_hardened_idx(index)
                                .ok()
                                .ok_or(ConversionError::HardenedChild)?,
                        ),
                    };
                    DescriptorSecretKey::XPrv(DescriptorXKey {
                        origin: xprv.origin,
                        xkey: xprv.xkey,
                        derivation_path,
                        wildcard: Wildcard::None,
                    })
                },
                DescriptorSecretKey::MultiXPrv(_) => return Err(ConversionError::MultiKey),
            }),
        };
        let definite_descriptor = self.descriptor.at_derivation_index(index)?;
        Ok(Descriptor{
            key: definite_key,
            descriptor: definite_descriptor,
        })
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
            .blinded_address(self.key.to_public_key(secp, &spk)?, params)
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
                ("elip151", 0) => {
                    let d = crate::Descriptor::<DescriptorPublicKey>::from_tree(&top.args[1])?;
                    Key::from_elip151(&d)?
                }
                ("slip77", 1) => Key::Slip77(expression::terminal(&keyexpr.args[0], slip77::MasterBlindingKey::from_str)?),
                ("slip77", _) => return Err(Error::BadDescriptor(
                    "slip77() must have exactly one argument".to_owned()
                )),
                _ => expression::terminal(keyexpr, |s: &str| DescriptorSecretKey::from_str_inner(s, true)).map(Key::View)
                .or_else(|_| expression::terminal(keyexpr, DescriptorPublicKey::from_str).map(Key::Bare))?,
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
    use crate::{DefiniteDescriptorKey, NoExt};

    #[test]
    fn bare_addr_to_confidential() {
        let secp = secp256k1_zkp::Secp256k1::new();

        // taken from libwally src/test/test_confidential_addr.py
        let mut addr = Address::from_str("Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6").unwrap();
        let key = Key::Bare(
            DescriptorPublicKey::from_str(
                "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623",
            )
            .unwrap(),
        );
        addr.blinding_pubkey = Some(key.to_public_key(&secp, &addr.script_pubkey()).unwrap());
        assert_eq!(
            addr.to_string(),
            "VTpt7krqRQPJwqe3XQXPg2cVdEKYVFbuprTr7es7pNRMe8mndnq2iYWddxJWYowhLAwoDF8QrZ1v2EXv"
        );
    }

    struct ConfidentialTest {
        key: Key,
        descriptor: crate::Descriptor<DefiniteDescriptorKey, NoExt>,
        descriptor_str: String,
        conf_addr: &'static str,
        unconf_addr: &'static str,
    }

    impl ConfidentialTest {
        fn check<C: secp256k1_zkp::Signing + secp256k1_zkp::Verification>(
            &self,
            secp: &secp256k1_zkp::Secp256k1<C>,
        ) {
            let desc: Descriptor<DefiniteDescriptorKey, NoExt> = Descriptor {
                key: self.key.clone(),
                descriptor: self.descriptor.clone(),
            };
            assert_eq!(self.descriptor_str, desc.to_string());
            assert_eq!(desc, Descriptor::from_str(&desc.to_string()).unwrap());
            assert_eq!(
                self.conf_addr,
                desc.address(secp, &elements::AddressParams::LIQUID)
                    .unwrap()
                    .to_string(),
            );
            assert_eq!(
                self.unconf_addr,
                desc.unconfidential_address(&elements::AddressParams::LIQUID)
                    .unwrap()
                    .to_string(),
            );
        }

        #[allow(dead_code)]
        fn output_elip_test_vector(&self, index: usize) {
            println!(
                "* Valid Descriptor {}: <code>{}</code>",
                index, self.descriptor_str
            );
            match self.key {
                Key::Bare(ref pk) => println!("** Blinding public key: <code>{}</code>", pk),
                Key::View(ref sk) => println!("** Blinding private key: <code>{}</code>", sk),
                Key::Slip77(mbk) => println!("** SLIP77 master blinding key: <code>{}</code>", mbk),
            }
            println!("** Confidential address: <code>{}</code>", self.conf_addr);
            println!(
                "** Unconfidential address: <code>{}</code>",
                self.unconf_addr
            );
            println!();
        }
    }

    #[test]
    fn confidential_descriptor() {
        let secp = secp256k1_zkp::Secp256k1::new();

        // CT key used for bare keys
        let ct_key = DescriptorPublicKey::from_str(
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        )
        .unwrap();
        // Auxiliary key to create scriptpubkeys from
        let spk_key = DefiniteDescriptorKey::from_str(
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        )
        .unwrap();

        let tests = vec![
            // Bare key, P2PKH
            ConfidentialTest {
                key: Key::Bare(ct_key.clone()),
                descriptor: crate::Descriptor::new_pkh(spk_key.clone()),
                descriptor_str: format!("ct({},elpkh({}))#y0lg3d5y", ct_key, spk_key),
                conf_addr: "VTpvZZYdbhbyVF3Wa99eMjgXhfvu4LS26dR2FwMfNXq7FDX73HZEsZr3VvgH9EDgQnYK7sP6ACKSuMGw",
                unconf_addr: "Q5WHLVd78iAspUNvzuULvi2F8u693pzAqe",
            },
            // Bare key, P2WPKH
            ConfidentialTest {
                key: Key::Bare(ct_key.clone()),
                descriptor: crate::Descriptor::new_wpkh(spk_key.clone()).unwrap(),
                descriptor_str: format!("ct({},elwpkh({}))#kt4e25qt", ct_key, spk_key),
                conf_addr: "lq1qqg5s7xj7upzl7h4q2k2wj4vq63nvaktn0egqu09nqcr6d44p4evaqknpl78t02k2xqgdh9ltmfmpy9ssk7qfvghdsfr4mvr9c",
                unconf_addr: "ex1qtfsllr4h4t9rqyxmjl4a5asjzcgt0qyktcafre",
            },
            // Bare key, P2SH-WPKH
            ConfidentialTest {
                key: Key::Bare(ct_key.clone()),
                descriptor: crate::Descriptor::new_sh_wpkh(spk_key.clone()).unwrap(),
                descriptor_str: format!("ct({},elsh(wpkh({})))#xg9r4jej", ct_key, spk_key),
                conf_addr: "VJL8znN4XjXEUKzDaYsqdzRASGLY2KHxC4N6g5b5QvrNjXfeKp83Ci9AW2a8QzbZjpEffoy4PEywpLAZ",
                unconf_addr: "Gq6kpy2HiNgsyQVpBsuBKAPRFiir23qKro",
            },
            // Bare key, P2TR
            ConfidentialTest {
                key: Key::Bare(ct_key.clone()),
                descriptor: crate::Descriptor::new_tr(spk_key.clone(), None).unwrap(),
                descriptor_str: format!("ct({},eltr({}))#c0pjjxyw", ct_key, spk_key),
                conf_addr: "lq1pq0nsl8du3gsuk7r90sgm78259mmv6mt9d4yvj30zr3u052ufs5meuc2tuvwx7k7g9kvhhpux07vqpm3qjj8uwdj94650265ustv0xy8zrdxdfgp8g9pl",
                unconf_addr: "ex1pv997x8r0t0yzmxtms7r8lxqqacsffr78xez6a284d2wg9k8nzr3qxa9kvf",
            },
            // SLIP77, P2PKH
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_pkh(spk_key.clone()),
                descriptor_str: format!("ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elpkh({}))#hw2glz99", spk_key),
                conf_addr: "VTq585ahVjWarEwg2nKQ9yYirmYs5F5j74CeYYA9cq1EZD9obm7hwpx6xqq3J1AY9YRaSavEMzYfr6t7",
                unconf_addr: "Q5WHLVd78iAspUNvzuULvi2F8u693pzAqe",
            },
            // SLIP77, P2WPKH
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_wpkh(spk_key.clone()).unwrap(),
                descriptor_str: format!("ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elwpkh({}))#545pl285", spk_key),
                conf_addr: "lq1qqdx5wnttttzulcs6ujlg9pfts6mp3r4sdwg5ekdej566n5wxzk88vknpl78t02k2xqgdh9ltmfmpy9ssk7qfvr33xa22hpw23",
                unconf_addr: "ex1qtfsllr4h4t9rqyxmjl4a5asjzcgt0qyktcafre",
            },
            // SLIP77, P2SH
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_sh_wpkh(spk_key.clone()).unwrap(),
                descriptor_str: format!("ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elsh(wpkh({})))#m30vswxr", spk_key),
                conf_addr: "VJLFGQ17aGa3WSVEVyxzDktD9SFixJjfSmqVq8xaWmR9X6gFbiF95KFwKA41PBhu3jNTxJFKTUphHL8J",
                unconf_addr: "Gq6kpy2HiNgsyQVpBsuBKAPRFiir23qKro",
            },
            // SLIP77, P2TR
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_tr(spk_key.clone(), None).unwrap(),
                descriptor_str: format!("ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),eltr({}))#n3v4t5cs", spk_key),
                conf_addr: "lq1pq26fndnz8ef6umlz6e2755sm6j5jwxv3tdt2295mr4mx6ux0uf8vcc2tuvwx7k7g9kvhhpux07vqpm3qjj8uwdj94650265ustv0xy8z8wfacw9e5a5t",
                unconf_addr: "ex1pv997x8r0t0yzmxtms7r8lxqqacsffr78xez6a284d2wg9k8nzr3qxa9kvf",
            },
        ];

        for test in &tests {
            test.check(&secp);
        }
        // Uncomment to regenerate test vectors; to see the output, run
        // cargo test confidential::tests:;confidential_descriptor -- --nocapture
        /*
        for (n, test) in tests.iter().enumerate() {
            test.output_elip_test_vector(n + 1);
        }
        */
    }

    #[test]
    fn confidential_descriptor_invalid() {
        let bad_strs = vec![
            (
                "ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elsh(wpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4)))#xxxxxxxx",
                "Invalid descriptor: Invalid checksum 'xxxxxxxx', expected 'qgjmm4as'",
            ),
            (
                "ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04,b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elsh(wpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4)))#qs64ccxw",
                "Invalid descriptor: slip77() must have exactly one argument",
            ),
            (
                "ct(slip77,elsh(wpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4)))#8p3zmumf",
                "Invalid descriptor: slip77() must have exactly one argument",
            ),
            (
                "ct(elsh(wpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4)))#u9cwz9f3",
                "Invalid descriptor: CT descriptor had 1 arguments rather than 2",
            ),
            (
                "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))#cnsp2qsc",
                "Invalid descriptor: CT descriptor had 3 arguments rather than 2",
            ),
            (
                "ct(pk(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623),elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))#nvax6rau",
                "unexpected «pk»",
            ),
            (
                "ct(L3jXxwef3fpB7hcrFozcWgHeJCPSAFiZ1Ji2YJMPxceaGvy3PC1q,elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))#gcy6hcfz",
                "unexpected «Key too short (<66 char), doesn't match any format»",
            ),
        ];

        /*
        for (n, bad_str) in bad_strs.iter().enumerate() {
            println!("* Invalid Descriptor {}", n + 1);
            println!("** <code>{}</code>", bad_str.0);
            println!("** Reason:");
        }
        */

        for bad_str in bad_strs {
            let err = Descriptor::<DefiniteDescriptorKey>::from_str(bad_str.0).unwrap_err();
            assert_eq!(bad_str.1, err.to_string());
        }
    }

    #[test]
    fn view_descriptor() {
        let secp = secp256k1_zkp::Secp256k1::new();

        let view_key = DescriptorSecretKey::from_str(
            "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5qzmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb",
        ).unwrap();
        let ct_key = view_key.to_public(&secp).unwrap();
        let spk_key = DefiniteDescriptorKey::from_str(
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        )
        .unwrap();

        // View key, P2PKH
        let test = ConfidentialTest {
            key: Key::View(view_key.clone()),
            descriptor: crate::Descriptor::new_wpkh(spk_key.clone()).unwrap(),
            descriptor_str: format!("ct({},elwpkh({}))#j95xktq7", view_key, spk_key),
            conf_addr: "lq1qq2r0pdvcknjpwev96qu9975alzqs78cvsut5ju82t7tv8d645dgmwknpl78t02k2xqgdh9ltmfmpy9ssk7qfvtk83xqzx62q4",
            unconf_addr: "ex1qtfsllr4h4t9rqyxmjl4a5asjzcgt0qyktcafre",
        };
        test.check(&secp);

        // View key converted to Bare (note that addresses are the same)
        let test = ConfidentialTest {
            key: Key::Bare(ct_key.clone()),
            descriptor: crate::Descriptor::new_wpkh(spk_key.clone()).unwrap(),
            descriptor_str: format!("ct({},elwpkh({}))#elmfpmp9", ct_key, spk_key),
            conf_addr: "lq1qq2r0pdvcknjpwev96qu9975alzqs78cvsut5ju82t7tv8d645dgmwknpl78t02k2xqgdh9ltmfmpy9ssk7qfvtk83xqzx62q4",
            unconf_addr: "ex1qtfsllr4h4t9rqyxmjl4a5asjzcgt0qyktcafre",
        };
        test.check(&secp);
    }

    #[test]
    fn view_single_key_descriptor() {
        let secp = secp256k1_zkp::Secp256k1::new();
        let view_key = "c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963";
        let ct_key = "0286fc9a38e765d955e9b0bcc18fa9ae81b0c893e2dd1ef5542a9c73780a086b90";
        let pk = "021a8fb6bd5a653b021b98a2a785725b8ddacfe3687bc043aa7f4d25d3a48d40b5";
        let addr_conf = "lq1qq265u4g3k3m3qpyxjwpdrtnm293wuxgvs9xzmzcs2ck0mv5rx23w4d7xfsednsmmxrszfe7s9rs0c6cvf3dfytxax3utlmm46";
        let addr_unconf = "ex1qklrycvkecdanpcpyulgz3c8udvxyck5jvsv4j5";

        for desc_str in [
            format!("ct({view_key},elwpkh({pk}))#c2kx9zll"),
            format!("ct({ct_key},elwpkh({pk}))#m5mvyh29"),
        ] {
            let desc = Descriptor::<DefiniteDescriptorKey>::from_str(&desc_str).unwrap();
            assert_eq!(desc.to_string(), desc_str);
            assert_eq!(addr_conf, &desc.address(&secp, &elements::AddressParams::LIQUID).unwrap().to_string());
            assert_eq!(addr_unconf, &desc.unconfidential_address(&elements::AddressParams::LIQUID).unwrap().to_string());
        }
    }

    #[test]
    fn view_xonly_pubkey_descriptor() {
        // View keys are 64 hex chars, but also x-only public keys are 64 hex chars
        let view_key = "ab16855a17319477d4283fe5c29cc7d047f81e8ffb199e20d9be1bc31a751c4c";
        // This view key can also be interpreted as a public key
        let _public_key = DescriptorPublicKey::from_str(view_key).unwrap();
        // But since compressed public keys are disallowed, it must be interpreted as a view key
        let pk = "021a8fb6bd5a653b021b98a2a785725b8ddacfe3687bc043aa7f4d25d3a48d40b5";
        let desc_str = format!("ct({view_key},elwpkh({pk}))#n9uc7tzt");
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(&desc_str).unwrap();
        assert!(matches!(desc.key, Key::View(_)));
    }

    #[test]
    fn descriptor_wildcard() {
        let secp = secp256k1_zkp::Secp256k1::new();
        let params = &elements::AddressParams::LIQUID;

        let xprv = "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5qzmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb";
        let xpub = "xpub661MyMwAqRbcEcT9W98HZP2kFzyzQQZkYnrRnrM8uD8kH8kSeFoQHq1x2iihLgC6PXGy5LrjCL66uSNhJ8pwjfx2rMUTLWuRMns2EG9xnjs";
        let desc_view_str = format!("ct({}/*,elwpkh({}/*))#wk8ltq6h", xprv, xpub);
        let desc_bare_str = format!("ct({}/*,elwpkh({}/*))#zzac2dpf", xpub, xpub);
        let index = 1;
        let conf_addr = "lq1qqf6690fpw2y00hv5a84zsydjgztg2089d5xnll4k4cstzn63uvgudd907qpvlvvwd5ym9gx7j0v46elf23kfxhmutc58z4k24";
        let unconf_addr = "ex1qkjhlqqk0kx8x6zdj5r0f8k2avl54gmynyjcw4v";

        let desc_view = Descriptor::<DescriptorPublicKey>::from_str(&desc_view_str).unwrap();
        let desc_bare = Descriptor::<DescriptorPublicKey>::from_str(&desc_bare_str).unwrap();
        let definite_desc_view = desc_view.at_derivation_index(index).unwrap();
        let definite_desc_bare = desc_bare.at_derivation_index(index).unwrap();
        assert_eq!(definite_desc_view.address(&secp, params).unwrap().to_string(), conf_addr.to_string());
        assert_eq!(definite_desc_bare.address(&secp, params).unwrap().to_string(), conf_addr.to_string());
        assert_eq!(definite_desc_view.unconfidential_address(params).unwrap().to_string(), unconf_addr.to_string());
        assert_eq!(definite_desc_bare.unconfidential_address(params).unwrap().to_string(), unconf_addr.to_string());

        // It's not possible to get an address if the blinding key has a wildcard,
        // because the descriptor blinding key is not *definite*,
        // but we can't enforce this with the Descriptor generic.
        let desc_view_str = format!("ct({}/*,elwpkh({}))#ls6mx2ac", xprv, xpub);
        let desc_view = Descriptor::<DefiniteDescriptorKey>::from_str(&desc_view_str).unwrap();
        assert_eq!(desc_view.address(&secp, params).unwrap_err(), Error::Unexpected("wildcard blinding key".into()));

        let desc_bare_str = format!("ct({}/*,elwpkh({}))#czkz0hwn", xpub, xpub);
        let desc_bare = Descriptor::<DefiniteDescriptorKey>::from_str(&desc_bare_str).unwrap();
        assert_eq!(desc_bare.address(&secp, params).unwrap_err(), Error::Unexpected("wildcard blinding key".into()));
    }
}
