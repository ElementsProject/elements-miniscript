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
            Key::View(sk) => fmt::Display::fmt(sk, f),
        }
    }
}

impl Key {
    fn to_public_key<C: secp256k1_zkp::Signing + secp256k1_zkp::Verification>(
        &self,
        secp: &secp256k1_zkp::Secp256k1<C>,
        spk: &elements::Script,
    ) -> secp256k1_zkp::PublicKey {
        match *self {
            Key::Slip77(ref mbk) => mbk.blinding_key(secp, spk),
            Key::Bare(ref pk) => bare::tweak_key(secp, spk, &pk.clone().at_derivation_index(0).expect("FIXME deal with derivation paths properly")),
            Key::View(ref sk) => bare::tweak_key(secp, spk, &sk.to_public(secp).expect("view keys cannot be multipath keys").at_derivation_index(0).expect("FIXME deal with derivation paths properly")),
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
                _ => expression::terminal(keyexpr, DescriptorPublicKey::from_str).map(Key::Bare)
                .or_else(|_| expression::terminal(keyexpr, DescriptorSecretKey::from_str).map(Key::View))?,
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
        addr.blinding_pubkey = Some(key.to_public_key(&secp, &addr.script_pubkey()));
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
                conf_addr: "CTEnDa5fqGccV3g3jvp4exSQwRfb6FpGchNBF4ZrAaq8ip8gvLqHCtzw1F7d7U5gYJYXBwymgEMmJjca",
                unconf_addr: "2dhfebpgPWpeqPdCMMam5F2UHAgx3bbLzAg",
            },
            // Bare key, P2WPKH
            ConfidentialTest {
                key: Key::Bare(ct_key.clone()),
                descriptor: crate::Descriptor::new_wpkh(spk_key.clone()).unwrap(),
                descriptor_str: format!("ct({},elwpkh({}))#kt4e25qt", ct_key, spk_key),
                conf_addr: "el1qqg5s7xj7upzl7h4q2k2wj4vq63nvaktn0egqu09nqcr6d44p4evaqknpl78t02k2xqgdh9ltmfmpy9ssk7qfvrldr2dttt3ez",
                unconf_addr: "ert1qtfsllr4h4t9rqyxmjl4a5asjzcgt0qyk32h3ur",
            },
            // Bare key, P2SH-WPKH
            ConfidentialTest {
                key: Key::Bare(ct_key.clone()),
                descriptor: crate::Descriptor::new_sh_wpkh(spk_key.clone()).unwrap(),
                descriptor_str: format!("ct({},elsh(wpkh({})))#xg9r4jej", ct_key, spk_key),
                conf_addr: "AzpnREsN1RSi4JB7rAfpywmPsvGxyygmwm9o3iZcP43svg4frVW5DXvGj5yEx6mKcPtAyHgQWVikFRCM",
                unconf_addr: "XKGUGskfGsNRR1Ww4ytemgBjuszohUaNgv",
            },
            // Bare key, P2TR
            ConfidentialTest {
                key: Key::Bare(ct_key.clone()),
                descriptor: crate::Descriptor::new_tr(spk_key.clone(), None).unwrap(),
                descriptor_str: format!("ct({},eltr({}))#c0pjjxyw", ct_key, spk_key),
                conf_addr: "el1pq0nsl8du3gsuk7r90sgm78259mmv6mt9d4yvj30zr3u052ufs5meuc2tuvwx7k7g9kvhhpux07vqpm3qjj8uwdj94650265ustv0xy8z2pc847zht4k0",
                unconf_addr: "ert1pv997x8r0t0yzmxtms7r8lxqqacsffr78xez6a284d2wg9k8nzr3q3s6527",
            },
            // SLIP77, P2PKH
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_pkh(spk_key.clone()),
                descriptor_str: format!("ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elpkh({}))#hw2glz99", spk_key),
                conf_addr: "CTEvn67jjJXDr3aDCZypTCJc6XHZ7ATyd89oXfNLQt1G2omPUpPkHA6zUAGPGF2YH4RnWfWut2f4dRSd",
                unconf_addr: "2dhfebpgPWpeqPdCMMam5F2UHAgx3bbLzAg",
            },
            // SLIP77, P2WPKH
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_wpkh(spk_key.clone()).unwrap(),
                descriptor_str: format!("ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elwpkh({}))#545pl285", spk_key),
                conf_addr: "el1qqdx5wnttttzulcs6ujlg9pfts6mp3r4sdwg5ekdej566n5wxzk88vknpl78t02k2xqgdh9ltmfmpy9ssk7qfvge347y58xukt",
                unconf_addr: "ert1qtfsllr4h4t9rqyxmjl4a5asjzcgt0qyk32h3ur",
            },
            // SLIP77, P2SH
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_sh_wpkh(spk_key.clone()).unwrap(),
                descriptor_str: format!("ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elsh(wpkh({})))#m30vswxr", spk_key),
                conf_addr: "AzptgrWR3xVX6Qg8mbkyZiESb6C9uy8VCUdCCmw7UtceiF5H8PdB6933YDT7vHsevK1yFmxfajdaedCH",
                unconf_addr: "XKGUGskfGsNRR1Ww4ytemgBjuszohUaNgv",
            },
            // SLIP77, P2TR
            ConfidentialTest {
                key: Key::Slip77(slip77::MasterBlindingKey::from_seed(b"abcd")),
                descriptor: crate::Descriptor::new_tr(spk_key.clone(), None).unwrap(),
                descriptor_str: format!("ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),eltr({}))#n3v4t5cs", spk_key),
                conf_addr: "el1pq26fndnz8ef6umlz6e2755sm6j5jwxv3tdt2295mr4mx6ux0uf8vcc2tuvwx7k7g9kvhhpux07vqpm3qjj8uwdj94650265ustv0xy8zwzhhycxfhdrm",
                unconf_addr: "ert1pv997x8r0t0yzmxtms7r8lxqqacsffr78xez6a284d2wg9k8nzr3q3s6527",
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
            conf_addr: "el1qq2r0pdvcknjpwev96qu9975alzqs78cvsut5ju82t7tv8d645dgmwknpl78t02k2xqgdh9ltmfmpy9ssk7qfvq78z9wukacu0",
            unconf_addr: "ert1qtfsllr4h4t9rqyxmjl4a5asjzcgt0qyk32h3ur",
        };
        test.check(&secp);

        // View key converted to Bare (note that addresses are the same)
        let test = ConfidentialTest {
            key: Key::Bare(ct_key.clone()),
            descriptor: crate::Descriptor::new_wpkh(spk_key.clone()).unwrap(),
            descriptor_str: format!("ct({},elwpkh({}))#elmfpmp9", ct_key, spk_key),
            conf_addr: "el1qq2r0pdvcknjpwev96qu9975alzqs78cvsut5ju82t7tv8d645dgmwknpl78t02k2xqgdh9ltmfmpy9ssk7qfvq78z9wukacu0",
            unconf_addr: "ert1qtfsllr4h4t9rqyxmjl4a5asjzcgt0qyk32h3ur",
        };
        test.check(&secp);
    }
}
