//! # rust-miniscript integration test
//!
//! Read Miniscripts from file and translate into miniscripts
//! which we know how to satisfy
//!

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::{self, Secp256k1};
use elements::pset::PartiallySignedTransaction as Psbt;
use elements::{
    confidential, pset as psbt, secp256k1_zkp, AssetIssuance, LockTime, OutPoint, Script, Sequence,
    TxIn, TxInWitness, TxOut, TxOutWitness, Txid,
};
use elements_miniscript as miniscript;
use elementsd::ElementsD;
use miniscript::psbt::PsbtExt;
use miniscript::{bitcoin, elements, elementssig_to_rawsig, Descriptor};

mod setup;
use setup::test_util::{self, PubData, TestData, PARAMS};
use setup::Call;

// parse ~30 miniscripts from file
pub(crate) fn parse_miniscripts(
    secp: &Secp256k1<secp256k1::All>,
    pubdata: &PubData,
) -> Vec<Descriptor<bitcoin::PublicKey>> {
    // File must exist in current path before this produces output
    let mut desc_vec = vec![];
    // Consumes the iterator, returns an (Optional) String
    for line in read_lines("tests/data/random_ms.txt") {
        let ms = test_util::parse_insane_ms(&line.unwrap(), pubdata);
        let wsh = Descriptor::new_wsh(ms).unwrap();
        desc_vec.push(wsh.derived_descriptor(secp, 0).unwrap());
    }
    desc_vec
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Lines<io::BufReader<File>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename).expect("File not found");
    io::BufReader::new(file).lines()
}

// Find the Outpoint by value.
// Ideally, we should find by scriptPubkey, but this
// works for temp test case
fn get_vout(cl: &ElementsD, txid: Txid, value: u64) -> (OutPoint, TxOut) {
    let tx = cl.get_transaction(&txid);
    for (i, txout) in tx.output.into_iter().enumerate() {
        if txout.value == confidential::Value::Explicit(value) {
            return (OutPoint::new(txid, i as u32), txout);
        }
    }
    unreachable!("Only call get vout on functions which have the expected outpoint");
}

pub fn test_from_cpp_ms(cl: &ElementsD, testdata: &TestData) {
    let secp = secp256k1::Secp256k1::new();
    let desc_vec = parse_miniscripts(&secp, &testdata.pubdata);
    let sks = &testdata.secretdata.sks;
    let pks = &testdata.pubdata.pks;
    // Generate some blocks
    cl.generate(500);

    // Next send some btc to each address corresponding to the miniscript
    // Create a hard-
    let mut txids = vec![];
    for wsh in desc_vec.iter() {
        let txid = cl.send_to_address(
            &wsh.address(&PARAMS).unwrap(), // This is unblinded address
            "1",
        );
        cl.generate(1);
        txids.push(txid);
    }
    // Wait for the funds to mature.
    cl.generate(50);
    // Create a PSBT for each transaction.
    // Spend one input and spend one output for simplicity.
    let mut psbts = vec![];
    for (desc, txid) in desc_vec.iter().zip(txids) {
        let mut psbt = Psbt::new_v2();
        psbt.global.tx_data.fallback_locktime =
            Some(LockTime::from_time(1_603_866_330).expect("valid timestamp")); // 10/28/2020 @ 6:25am (UTC)
        let (outpoint, witness_utxo) = get_vout(cl, txid, 100_000_000);
        let txin = TxIn {
            previous_output: outpoint,
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::from_height(49), // We waited 50 blocks, keep 49 for safety
            asset_issuance: AssetIssuance::default(),
            witness: TxInWitness::default(),
        };
        psbt.add_input(psbt::Input::from_txin(txin));
        // Get a new script pubkey from the node so that
        // the node wallet tracks the receiving transaction
        // and we can check it by gettransaction RPC.
        let addr = cl.get_new_address();
        let out = TxOut {
            value: confidential::Value::Explicit(99_999_000),
            script_pubkey: addr.script_pubkey(),
            asset: witness_utxo.asset,
            nonce: confidential::Nonce::Null,
            witness: TxOutWitness::default(),
        };
        psbt.add_output(psbt::Output::from_txout(out));
        // ELEMENTS: Add fee output
        let fee_out = TxOut::new_fee(1_000, witness_utxo.asset.explicit().unwrap());
        psbt.add_output(psbt::Output::from_txout(fee_out));

        psbt.inputs_mut()[0].witness_utxo = Some(witness_utxo);
        psbt.inputs_mut()[0].witness_script = Some(desc.explicit_script().unwrap());
        psbts.push(psbt);
    }

    let mut spend_txids = vec![];
    // Sign the transactions with all keys
    // AKA the signer role of psbt
    for i in 0..psbts.len() {
        let ms = if let Descriptor::Wsh(wsh) = &desc_vec[i] {
            match wsh.as_inner() {
                miniscript::descriptor::WshInner::Ms(ms) => ms,
                _ => unreachable!(),
            }
        } else {
            unreachable!("Only Wsh descriptors are supported");
        };

        let sks_reqd: Vec<_> = ms
            .iter_pk()
            .map(|pk| sks[pks.iter().position(|&x| x == pk).unwrap()])
            .collect();
        // Get the required sighash message
        let amt = confidential::Value::Explicit(100_000_000);
        let unsigned_tx = psbts[i].extract_tx().unwrap();
        let mut sighash_cache = elements::sighash::SighashCache::new(&unsigned_tx);
        let sighash_ty = elements::EcdsaSighashType::All;
        let sighash = sighash_cache.segwitv0_sighash(0, &ms.encode(), amt, sighash_ty);

        // requires both signing and verification because we check the tx
        // after we psbt extract it
        let msg = secp256k1_zkp::Message::from_slice(&sighash[..]).unwrap();

        // Finally construct the signature and add to psbt
        for sk in sks_reqd {
            let sig = secp.sign_ecdsa(&msg, &sk);
            let ser_sig = elementssig_to_rawsig(&(sig, sighash_ty));
            let pk = pks[sks.iter().position(|&x| x == sk).unwrap()];
            psbts[i].inputs_mut()[0].partial_sigs.insert(pk, ser_sig);
        }
        // Add the hash preimages to the psbt
        psbts[i].inputs_mut()[0].sha256_preimages.insert(
            testdata.pubdata.sha256,
            testdata.secretdata.sha256_pre.to_vec(),
        );
        psbts[i].inputs_mut()[0].hash256_preimages.insert(
            sha256d::Hash::from_byte_array(testdata.pubdata.hash256.to_byte_array()),
            testdata.secretdata.hash256_pre.to_vec(),
        );
        println!("{}", ms);
        psbts[i].inputs_mut()[0].hash160_preimages.insert(
            testdata.pubdata.hash160,
            testdata.secretdata.hash160_pre.to_vec(),
        );
        psbts[i].inputs_mut()[0].ripemd160_preimages.insert(
            testdata.pubdata.ripemd160,
            testdata.secretdata.ripemd160_pre.to_vec(),
        );
        // Finalize the transaction using psbt
        // Let miniscript do it's magic!
        if let Err(e) = psbts[i].finalize_mall_mut(&secp, elements::BlockHash::all_zeros()) {
            // All miniscripts should satisfy
            panic!("Could not satisfy: error{} ms:{} at ind:{}", e[0], ms, i);
        } else {
            // default genesis hash
            let tx = psbts[i]
                .extract(&secp, elements::BlockHash::all_zeros())
                .unwrap();

            // Send the transactions to bitcoin node for mining.
            // Regtest mode has standardness checks
            // Check whether the node accepts the transactions
            let txid = cl.send_raw_transaction(&tx);
            spend_txids.push(txid);
        }
    }
    // Finally mine the blocks and await confirmations
    cl.generate(10);
    // Get the required transactions from the node mined in the blocks.
    for txid in spend_txids {
        // Check whether the transaction is mined in blocks
        // Assert that the confirmations are > 0.
        let num_conf = cl.call("gettransaction", &[txid.to_string().into()])["confirmations"]
            .as_u64()
            .unwrap();
        assert!(num_conf > 0);
    }
}

#[test]
fn test_setup() {
    setup::setup(false);
    setup::setup(true);
}

#[test]
fn tests_from_cpp() {
    let (cl, _, genesis_hash) = &setup::setup(false);
    let testdata = TestData::new_fixed_data(50, *genesis_hash);
    test_from_cpp_ms(cl, &testdata);
}
