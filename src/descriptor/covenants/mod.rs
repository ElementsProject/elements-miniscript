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

//! Covenant Descriptor Support
//! Covenant Descriptor support
//!
//! Traits and implementations for Covenant descriptors
//! A cov() descriptor puts a context items required for
//! sighash onto the top of the stack in the required order
//!
//! ** WORKS only for Segwit sighash
//! A new transaction digest algorithm is defined, but only applicable to sigops in version 0 witness program:
//! Text from BIP 143:
//!  Double SHA256 of the serialization of:
//! 1. nVersion of the transaction (4-byte little endian)
//! 2. hashPrevouts (32-byte hash)
//! 3. hashSequence (32-byte hash)
//! 3b. ELEMENTS EXTRA hashIssuances (32-byte hash)
//! 4. outpoint (32-byte hash + 4-byte little endian)
//! 5. scriptCode of the input (serialized as scripts inside CTxOuts)
//! 6. value of the output spent by this input (8-byte little endian)
//! 7. nSequence of the input (4-byte little endian)
//! 8. hashOutputs (32-byte hash)
//! 9. nLocktime of the transaction (4-byte little endian)
//! 10. sighash type of the signature (4-byte little endian)
//!
//! The miniscript fragments lookups all the relevant fragment
//! from the stack using using OP_PICK(specifying the relative)
//! position using OP_DEPTH.
//! After all the miniscript fragments are evaluated, we concat
//! all the items using OP_CAT to obtain a Sighash on which we
//! which we verify using CHECKSIGFROMSTACK

mod cov;
mod error;
mod satisfy;
mod script_internals;
pub use self::cov::CovenantDescriptor;
pub use self::error::CovError;
pub use self::satisfy::CovSatisfier;
pub use self::script_internals::CovOperations;

#[cfg(test)]
#[allow(unused_imports)]
mod tests {

    use interpreter;
    use CovenantExt;

    use super::cov::*;
    use super::*;
    use bitcoin;
    use descriptor::DescriptorTrait;
    use elements::hashes::hex::ToHex;
    use elements::secp256k1_zkp;
    use elements::{self, secp256k1_zkp::ZERO_TWEAK};
    use elements::{confidential, opcodes::all::OP_PUSHNUM_1};
    use elements::{encode::serialize, opcodes, script};
    use elements::{
        AssetId, AssetIssuance, OutPoint, Script, SigHashType, Transaction, TxIn, TxInWitness,
        TxOut, Txid,
    };
    use interpreter::SatisfiedConstraint;
    use std::str::FromStr;
    use util::{count_non_push_opcodes, witness_size};
    use Interpreter;
    use {descriptor::DescriptorType, Descriptor, ElementsSig, Error, Satisfier};

    const BTC_ASSET: [u8; 32] = [
        0x23, 0x0f, 0x4f, 0x5d, 0x4b, 0x7c, 0x6f, 0xa8, 0x45, 0x80, 0x6e, 0xe4, 0xf6, 0x77, 0x13,
        0x45, 0x9e, 0x1b, 0x69, 0xe8, 0xe6, 0x0f, 0xce, 0xe2, 0xe4, 0x94, 0x0c, 0x7a, 0x0d, 0x5d,
        0xe1, 0xb2,
    ];

    fn string_rtt(desc_str: &str) {
        let desc = Descriptor::<String>::from_str(desc_str).unwrap();
        assert_eq!(desc.to_string_no_chksum(), desc_str);
        let cov_desc = desc.as_cov().unwrap();
        assert_eq!(cov_desc.to_string(), desc.to_string());
    }
    #[test]
    fn parse_cov() {
        string_rtt("elcovwsh(A,pk(B))");
        string_rtt("elcovwsh(A,or_i(pk(B),pk(C)))");
        string_rtt("elcovwsh(A,multi(2,B,C,D))");
        string_rtt("elcovwsh(A,and_v(v:pk(B),pk(C)))");
        string_rtt("elcovwsh(A,thresh(2,ver_eq(1),s:pk(C),s:pk(B)))");
        string_rtt("elcovwsh(A,outputs_pref(01020304))");
    }

    fn script_rtt(desc_str: &str) {
        let desc = Descriptor::<bitcoin::PublicKey>::from_str(desc_str).unwrap();
        assert_eq!(desc.desc_type(), DescriptorType::Cov);
        let script = desc.as_cov().expect("Parsed as cov").encode();

        let cov_desc =
            CovenantDescriptor::<bitcoin::PublicKey, CovenantExt>::parse_insane(&script).unwrap();

        assert_eq!(cov_desc.to_string(), desc.to_string());
    }
    #[test]
    fn script_encode_test() {
        let (pks, _sks) = setup_keys(5);

        script_rtt(&format!("elcovwsh({},pk({}))", pks[0], pks[1]));
        script_rtt(&format!(
            "elcovwsh({},or_i(pk({}),pk({})))",
            pks[0], pks[1], pks[2]
        ));
        script_rtt(&format!(
            "elcovwsh({},multi(2,{},{},{}))",
            pks[0], pks[1], pks[2], pks[3]
        ));
        script_rtt(&format!(
            "elcovwsh({},and_v(v:pk({}),pk({})))",
            pks[0], pks[1], pks[2]
        ));
        script_rtt(&format!(
            "elcovwsh({},and_v(v:ver_eq(2),pk({})))",
            pks[0], pks[1]
        ));
        script_rtt(&format!(
            "elcovwsh({},and_v(v:outputs_pref(f2f233),pk({})))",
            pks[0], pks[1]
        ));
    }

    // Some deterministic keys for ease of testing
    fn setup_keys(n: usize) -> (Vec<bitcoin::PublicKey>, Vec<secp256k1_zkp::SecretKey>) {
        let secp_sign = secp256k1_zkp::Secp256k1::signing_only();

        let mut sks = vec![];
        let mut pks = vec![];
        let mut sk = [0; 32];
        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;
            let sk = secp256k1_zkp::SecretKey::from_slice(&sk[..]).expect("secret key");
            let pk = bitcoin::PublicKey {
                inner: secp256k1_zkp::PublicKey::from_secret_key(&secp_sign, &sk),
                compressed: true,
            };
            sks.push(sk);
            pks.push(pk);
        }
        (pks, sks)
    }

    #[test]
    fn test_sanity_check_limits() {
        let (pks, _sks) = setup_keys(1);
        // Count of the opcodes without the
        let cov_script = script::Builder::new().verify_cov(&pks[0]).into_script();
        assert_eq!(
            count_non_push_opcodes(&cov_script),
            Ok(cov::COV_SCRIPT_OPCODE_COST)
        );
        assert_eq!(cov_script.len(), cov::COV_SCRIPT_SIZE);

        let sighash_size = 4
        + 32
        + 32
        + 32
        + (32 + 4)
        + (5) // script code size
        + 4
        + 32
        + 4
        + 4;
        assert_eq!(sighash_size, 185);
    }

    fn _satisfy_and_interpret(
        desc: Descriptor<bitcoin::PublicKey>,
        cov_sk: secp256k1_zkp::SecretKey,
    ) -> Result<(), Error> {
        assert_eq!(desc.desc_type(), DescriptorType::Cov);
        let desc = desc.as_cov().unwrap();
        // Now create a transaction spending this.
        let mut spend_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![txin_from_txid_vout(
                "141f79c7c254ee3a9a9bc76b4f60564385b784bdfc1882b25154617801fe2237",
                1,
            )],
            output: vec![],
        };

        spend_tx.output.push(TxOut::default());
        spend_tx.output[0].script_pubkey = script::Builder::new()
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .into_script()
            .to_v0_p2wsh();
        spend_tx.output[0].value = confidential::Value::Explicit(99_000);
        spend_tx.output[0].asset =
            confidential::Asset::Explicit(AssetId::from_slice(&BTC_ASSET).unwrap());

        // same second output
        let second_out = spend_tx.output[0].clone();
        spend_tx.output.push(second_out);

        // Add a fee output
        spend_tx.output.push(TxOut::default());
        spend_tx.output[2].asset =
            confidential::Asset::Explicit(AssetId::from_slice(&BTC_ASSET).unwrap());
        spend_tx.output[2].value = confidential::Value::Explicit(2_000);

        // Try to satisfy the covenant part
        let script_code = desc.cov_script_code();
        let cov_sat = CovSatisfier::new_segwitv0(
            &spend_tx,
            0,
            confidential::Value::Explicit(200_000),
            &script_code,
            SigHashType::All,
        );

        // Create a signature to sign the input

        let sighash_u256 = cov_sat.segwit_sighash().unwrap();
        let secp = secp256k1_zkp::Secp256k1::signing_only();
        let sig = secp.sign_ecdsa(
            &secp256k1_zkp::Message::from_slice(&sighash_u256[..]).unwrap(),
            &cov_sk,
        );
        let el_sig = (sig, SigHashType::All);

        // For satisfying the Pk part of the covenant
        struct SimpleSat {
            sig: ElementsSig,
            pk: bitcoin::PublicKey,
        }

        impl Satisfier<bitcoin::PublicKey> for SimpleSat {
            fn lookup_ecdsa_sig(&self, pk: &bitcoin::PublicKey) -> Option<ElementsSig> {
                if *pk == self.pk {
                    Some(self.sig)
                } else {
                    None
                }
            }
        }

        let pk_sat = SimpleSat {
            sig: el_sig,
            pk: desc.pk,
        };

        // A pair of satisfiers is also a satisfier
        let (wit, ss) = desc.get_satisfaction((cov_sat, pk_sat))?;
        let interpreter = Interpreter::from_txdata(&desc.script_pubkey(), &ss, &wit, 0, 0).unwrap();

        assert!(wit[0].len() <= 73);
        assert!(wit[1].len() == 4); // version

        // Check that everything is executed correctly with correct sigs inside
        // miniscript
        let constraints = interpreter
            .iter_assume_sigs()
            .collect::<Result<Vec<_>, _>>()
            .expect("If satisfy succeeds, interpret must succeed");

        // The last constraint satisfied must be the covenant pk
        assert_eq!(
            constraints.last().unwrap(),
            &SatisfiedConstraint::PublicKey {
                key_sig: interpreter::KeySigPair::Ecdsa(desc.pk, (sig, SigHashType::All))
            }
        );
        Ok(())
    }

    #[test]
    fn satisfy_and_interpret() {
        let (pks, sks) = setup_keys(5);
        _satisfy_and_interpret(
            Descriptor::from_str(&format!("elcovwsh({},1)", pks[0])).unwrap(),
            sks[0],
        )
        .unwrap();

        // Version tests
        // Satisfy with 2, err with 3
        _satisfy_and_interpret(
            Descriptor::from_str(&format!("elcovwsh({},ver_eq(2))", pks[0])).unwrap(),
            sks[0],
        )
        .unwrap();
        _satisfy_and_interpret(
            Descriptor::from_str(&format!("elcovwsh({},ver_eq(3))", pks[0])).unwrap(),
            sks[0],
        )
        .unwrap_err();

        // Outputs Pref test
        // 1. Correct case
        let mut out = TxOut::default();
        out.script_pubkey = script::Builder::new()
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .into_script()
            .to_v0_p2wsh();
        out.value = confidential::Value::Explicit(99_000);
        out.asset = confidential::Asset::Explicit(AssetId::from_slice(&BTC_ASSET).unwrap());
        let desc = Descriptor::<bitcoin::PublicKey>::from_str(&format!(
            "elcovwsh({},outputs_pref({}))",
            pks[0],
            serialize(&out).to_hex(),
        ))
        .unwrap();
        _satisfy_and_interpret(desc, sks[0]).unwrap();

        // 2. Chaning the amount should fail the test
        let mut out = TxOut::default();
        out.script_pubkey = script::Builder::new()
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .into_script()
            .to_v0_p2wsh();
        out.value = confidential::Value::Explicit(99_001); // Changed to +1
        out.asset = confidential::Asset::Explicit(AssetId::from_slice(&BTC_ASSET).unwrap());
        let desc = Descriptor::<bitcoin::PublicKey>::from_str(&format!(
            "elcovwsh({},outputs_pref({}))",
            pks[0],
            serialize(&out).to_hex(),
        ))
        .unwrap();
        _satisfy_and_interpret(desc, sks[0]).unwrap_err();
    }

    // Fund output and spend tx are tests handy with code for
    // running with regtest mode and testing that the scripts
    // are accepted by elementsd
    // Instructions for running:
    // 1. Modify the descriptor script in fund_output and
    //    get the address to which we should spend the funds
    // 2. Look up the spending transaction and update the
    //    spend tx test with outpoint for spending.
    // 3. Uncomment the printlns at the end of spend_tx to get
    //    a raw tx that we can then check if it is accepted.
    #[test]
    fn fund_output() {
        let (pks, _sks) = setup_keys(5);
        let desc =
            Descriptor::<bitcoin::PublicKey>::from_str(&format!("elcovwsh({},1)", pks[0])).unwrap();

        assert_eq!(desc.desc_type(), DescriptorType::Cov);
        assert_eq!(
            desc.address(&elements::AddressParams::ELEMENTS)
                .unwrap()
                .to_string(),
            "ert1qamjdykcfzkcsvc9z32a6qcz3mwr85a3k7z7qf2uaufem2q3lsjxqj4y4fy"
        );

        println!(
            "{}",
            desc.address(&elements::AddressParams::ELEMENTS)
                .unwrap()
                .to_string()
        );
    }
    #[test]
    fn spend_tx() {
        let (pks, sks) = setup_keys(5);
        let desc =
            Descriptor::<bitcoin::PublicKey>::from_str(&format!("elcovwsh({},1)", pks[0])).unwrap();

        assert_eq!(desc.desc_type(), DescriptorType::Cov);
        assert_eq!(
            desc.address(&elements::AddressParams::ELEMENTS)
                .unwrap()
                .to_string(),
            "ert1qamjdykcfzkcsvc9z32a6qcz3mwr85a3k7z7qf2uaufem2q3lsjxqj4y4fy"
        );
        // Now create a transaction spending this.
        let mut spend_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![txin_from_txid_vout(
                "7c8e615c8da947fefd2d9b6f83f313a9b59d249c93a5f232287633195b461cb7",
                0,
            )],
            output: vec![],
        };

        spend_tx.output.push(TxOut::default());
        spend_tx.output[0].script_pubkey = desc.script_pubkey(); // send back to self
        spend_tx.output[0].value = confidential::Value::Explicit(99_000);
        spend_tx.output[0].asset =
            confidential::Asset::Explicit(AssetId::from_slice(&BTC_ASSET).unwrap());

        // same second output
        let second_out = spend_tx.output[0].clone();
        spend_tx.output.push(second_out);

        // Add a fee output
        spend_tx.output.push(TxOut::default());
        spend_tx.output[2].asset =
            confidential::Asset::Explicit(AssetId::from_slice(&BTC_ASSET).unwrap());
        spend_tx.output[2].value = confidential::Value::Explicit(2_000);

        // Try to satisfy the covenant part
        let desc = desc.as_cov().unwrap();
        let script_code = desc.cov_script_code();
        let cov_sat = CovSatisfier::new_segwitv0(
            &spend_tx,
            0,
            confidential::Value::Explicit(200_000),
            &script_code,
            SigHashType::All,
        );

        // Create a signature to sign the input

        let sighash_u256 = cov_sat.segwit_sighash().unwrap();
        let secp = secp256k1_zkp::Secp256k1::signing_only();
        let sig = secp.sign(
            &secp256k1_zkp::Message::from_slice(&sighash_u256[..]).unwrap(),
            &sks[0],
        );
        let sig = (sig, SigHashType::All);

        // For satisfying the Pk part of the covenant
        struct SimpleSat {
            sig: ElementsSig,
            pk: bitcoin::PublicKey,
        }

        impl Satisfier<bitcoin::PublicKey> for SimpleSat {
            fn lookup_ecdsa_sig(&self, pk: &bitcoin::PublicKey) -> Option<ElementsSig> {
                if *pk == self.pk {
                    Some(self.sig)
                } else {
                    None
                }
            }
        }

        let pk_sat = SimpleSat { sig, pk: pks[0] };

        // A pair of satisfiers is also a satisfier
        let (wit, ss) = desc.get_satisfaction((cov_sat, pk_sat)).unwrap();
        let interpreter = Interpreter::from_txdata(&desc.script_pubkey(), &ss, &wit, 0, 0).unwrap();
        // Check that everything is executed correctly with dummysigs
        let constraints: Result<Vec<_>, _> = interpreter.iter_assume_sigs().collect();
        constraints.expect("Covenant incorrect satisfaction");
        // Commented Demo test code:
        // 1) Send 0.002 btc to above address
        // 2) Create a tx by filling up txid
        // 3) Send the tx
        assert_eq!(witness_size(&wit), 384);
        assert_eq!(wit.len(), 13);
        // spend_tx.input[0].witness.script_witness = wit;
        // use elements::encode::serialize_hex;
        // println!("{}", serialize_hex(&spend_tx));
        // println!("{}", serialize_hex(&desc.explicit_script()));
    }

    fn txin_from_txid_vout(txid: &str, vout: u32) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(txid).unwrap(),
                vout: vout,
            },
            sequence: 0xfffffffe,
            is_pegin: false,
            has_issuance: false,
            // perhaps make this an option in elements upstream?
            asset_issuance: AssetIssuance {
                asset_blinding_nonce: secp256k1_zkp::ZERO_TWEAK,
                asset_entropy: [0; 32],
                amount: confidential::Value::Null,
                inflation_keys: confidential::Value::Null,
            },
            script_sig: Script::new(),
            witness: TxInWitness::default(),
        }
    }
}
