//! # rust-miniscript integration test
//!
//! CheckSigFromStack integration tests
//!

use elements::pset::PartiallySignedTransaction as Psbt;
use elements::sighash::SighashCache;
use elements::taproot::TapLeafHash;
use elements::{
    confidential, pset as psbt, secp256k1_zkp as secp256k1, sighash, OutPoint, Script, Sequence,
    TxIn, TxOut, Txid,
};
use elementsd::ElementsD;
use miniscript::extensions::{check_sig_price_oracle_1, sighash_msg_price_oracle_1};
use miniscript::psbt::{PsbtInputExt, PsbtInputSatisfier};
use miniscript::{bitcoin, elements, Descriptor, Satisfier, ToPublicKey, TxEnv};
use rand::RngCore;
mod setup;
use setup::test_util::{self, TestData, PARAMS};
use setup::Call;
use {actual_rand as rand, elements_miniscript as miniscript};

// Find the Outpoint by value.
// Ideally, we should find by scriptPubkey, but this
// works for temp test case
fn get_vout(cl: &ElementsD, txid: Txid, value: u64, spk: Script) -> (OutPoint, TxOut) {
    let tx = cl.get_transaction(&txid);
    for (i, txout) in tx.output.into_iter().enumerate() {
        if txout.value == confidential::Value::Explicit(value) && txout.script_pubkey == spk {
            return (OutPoint::new(txid, i as u32), txout);
        }
    }
    unreachable!("Only call get vout on functions which have the expected outpoint");
}

pub fn test_desc_satisfy(cl: &ElementsD, testdata: &TestData, desc: &str) -> Vec<Vec<u8>> {
    /* Convert desc into elements one by adding a prefix*/
    let desc = format!("el{}", desc);
    //
    let secp = secp256k1::Secp256k1::new();
    let xonly_keypairs = &testdata.secretdata.x_only_keypairs;
    let x_only_pks = &testdata.pubdata.x_only_pks;
    // Generate some blocks
    cl.generate(1);

    let definite_desc = test_util::parse_test_desc(&desc, &testdata.pubdata)
        .unwrap()
        .at_derivation_index(0)
        .unwrap();

    let derived_desc = definite_desc.derived_descriptor(&secp).unwrap();
    let desc_address = derived_desc.address(&PARAMS).unwrap(); // No blinding

    // Next send some btc to each address corresponding to the miniscript
    let txid = cl.send_to_address(&desc_address, "1"); // 1 BTC
                                                       // Wait for the funds to mature.
    cl.generate(2);
    // Create a PSBT for each transaction.
    // Spend one input and spend one output for simplicity.
    let mut psbt = Psbt::new_v2();
    // figure out the outpoint from the txid
    let (outpoint, witness_utxo) = get_vout(cl, txid, 100_000_000, derived_desc.script_pubkey());
    let txin = TxIn {
        previous_output: outpoint,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::from_height(1),
        asset_issuance: Default::default(),
        witness: Default::default(),
    };
    psbt.add_input(psbt::Input::from_txin(txin));
    // Get a new script pubkey from the node so that
    // the node wallet tracks the receiving transaction
    // and we can check it by gettransaction RPC.
    let addr = cl.get_new_address();
    let out = TxOut {
        // Had to decrease 'value', so that fees can be increased
        // (Was getting insufficient fees error, for deep script trees)
        value: confidential::Value::Explicit(99_997_000),
        script_pubkey: addr.script_pubkey(),
        asset: witness_utxo.asset,
        nonce: confidential::Nonce::Null,
        witness: Default::default(),
    };
    psbt.add_output(psbt::Output::from_txout(out));
    // ELEMENTS: Add fee output
    let fee_out = TxOut::new_fee(3_000, witness_utxo.asset.explicit().unwrap());
    psbt.add_output(psbt::Output::from_txout(fee_out));

    psbt.inputs_mut()[0]
        .update_with_descriptor_unchecked(&definite_desc)
        .unwrap();
    psbt.inputs_mut()[0].witness_utxo = Some(witness_utxo.clone());

    // --------------------------------------------
    // Sign the transactions with all keys
    // AKA the signer role of psbt
    // Get all the pubkeys and the corresponding secret keys

    let unsigned_tx = &psbt.extract_tx().unwrap();
    let mut sighash_cache = SighashCache::new(unsigned_tx);
    match derived_desc {
        Descriptor::TrExt(ref tr) => {
            let hash_ty = sighash::SchnorrSighashType::Default;

            let prevouts = [witness_utxo];
            let prevouts = sighash::Prevouts::All(&prevouts);
            // ------------------ script spend -------------
            let x_only_keypairs_reqd: Vec<(secp256k1::KeyPair, TapLeafHash)> = tr
                .iter_scripts()
                .flat_map(|(_depth, script)| {
                    let leaf_hash = TapLeafHash::from_script(&script.encode(), script.version());
                    script.iter_pk().filter_map(move |pk| {
                        let i = x_only_pks.iter().position(|&x| x.to_public_key() == pk);
                        i.map(|idx| (xonly_keypairs[idx], leaf_hash))
                    })
                })
                .collect();
            for (keypair, leaf_hash) in x_only_keypairs_reqd {
                let sighash_msg = sighash_cache
                    .taproot_script_spend_signature_hash(
                        0,
                        &prevouts,
                        leaf_hash,
                        hash_ty,
                        testdata.pubdata.genesis_hash,
                    )
                    .unwrap();
                let msg = secp256k1::Message::from_slice(&sighash_msg[..]).unwrap();
                let mut aux_rand = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut aux_rand);
                let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);
                // FIXME: uncomment when == is supported for secp256k1::KeyPair. (next major release)
                // let x_only_pk = pks[xonly_keypairs.iter().position(|&x| x == keypair).unwrap()];
                // Just recalc public key
                let x_only_pk = secp256k1::XOnlyPublicKey::from_keypair(&keypair).0;
                psbt.inputs_mut()[0].tap_script_sigs.insert(
                    (x_only_pk, leaf_hash),
                    elements::SchnorrSig { sig, hash_ty },
                );
            }
        }
        _ => {
            // Non-tr descriptors
            panic!("Only testing Tr covenant descriptor")
        }
    }
    // Add the hash preimages to the psbt
    psbt.inputs_mut()[0].sha256_preimages.insert(
        testdata.pubdata.sha256,
        testdata.secretdata.sha256_pre.to_vec(),
    );
    println!("Testing descriptor: {}", desc);
    // Finalize the transaction using psbt
    // Let miniscript do it's magic!
    struct CsfsSatisfier<'a>(&'a TestData);

    impl<'a> Satisfier<bitcoin::PublicKey> for CsfsSatisfier<'a> {
        fn lookup_csfs_sig(
            &self,
            pk: &bitcoin::key::XOnlyPublicKey,
            msg: &miniscript::extensions::CsfsMsg,
        ) -> Option<secp256k1::schnorr::Signature> {
            let xpk = pk.to_x_only_pubkey();
            let known_xpks = &self.0.pubdata.x_only_pks;
            let i = known_xpks.iter().position(|&x| x == xpk).unwrap();

            // Create a signature
            let keypair = &self.0.secretdata.x_only_keypairs[i];
            let msg = secp256k1::Message::from_slice(msg.as_inner()).unwrap();
            let mut aux_rand = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut aux_rand);

            let secp = secp256k1::Secp256k1::new();
            let sig = secp.sign_schnorr_with_aux_rand(&msg, keypair, &aux_rand);
            Some(sig)
        }

        fn lookup_price_oracle_sig(
            &self,
            pk: &bitcoin::key::XOnlyPublicKey,
            time: u64,
        ) -> Option<(secp256k1::schnorr::Signature, i64, u64)> {
            let xpk = pk.to_x_only_pubkey();
            let known_xpks = &self.0.pubdata.x_only_pks;
            let i = known_xpks.iter().position(|&x| x == xpk).unwrap();

            // select a time ahead of the current test time
            let time_signed = time + 1;
            let price = self.0.pubdata.price as u64;
            let sighash_msg = sighash_msg_price_oracle_1(time_signed, price);
            let keypair = &self.0.secretdata.x_only_keypairs[i];
            let mut aux_rand = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut aux_rand);

            let secp = secp256k1::Secp256k1::new();
            let sig = secp.sign_schnorr_with_aux_rand(&sighash_msg, keypair, &aux_rand);
            assert!(check_sig_price_oracle_1(
                &secp,
                &sig,
                &xpk,
                time_signed,
                price
            ));
            Some((sig, self.0.pubdata.price, time_signed))
        }
    }

    let psbt_sat = PsbtInputSatisfier::new(&psbt, 0);
    let csfs_sat = CsfsSatisfier(testdata);

    let mut tx = psbt.extract_tx().unwrap();
    let txouts = vec![psbt.inputs()[0].witness_utxo.clone().unwrap()];
    let extracted_tx = tx.clone(); // Possible to optimize this, but we don't care for this
                                   // Env requires reference of tx, while satisfaction requires mutable access to inputs.
    let cov_sat = TxEnv::new(&extracted_tx, &txouts, 0).unwrap();
    derived_desc
        .satisfy(&mut tx.input[0], (psbt_sat, csfs_sat, cov_sat))
        .expect("Satisfaction error");

    for wit in tx.input[0].witness.script_witness.iter() {
        println!("Witness: {} {:x?}", wit.len(), wit);
    }

    // Send the transactions to bitcoin node for mining.
    // Regtest mode has standardness checks
    // Check whether the node accepts the transactions
    let txid = cl.send_raw_transaction(&tx);

    // Finally mine the blocks and await confirmations
    cl.generate(1);
    // Get the required transactions from the node mined in the blocks.
    // Check whether the transaction is mined in blocks
    // Assert that the confirmations are > 0.
    let num_conf = cl.call("gettransaction", &[txid.to_string().into()])["confirmations"]
        .as_u64()
        .unwrap();
    assert!(num_conf > 0);
    tx.input[0].witness.script_witness.clone()
}

fn test_descs(cl: &ElementsD, testdata: &TestData) {
    // K : Compressed key available
    // K!: Compressed key with corresponding secret key unknown
    // X: X-only key available
    // X!: X-only key with corresponding secret key unknown

    // Test 1: Simple spend with internal key
    let wit = test_desc_satisfy(cl, testdata, "tr(X!,csfs(X1,msg1))");
    assert!(wit.len() == 3);

    // test in a complicated miniscript
    let wit = test_desc_satisfy(cl, testdata, "tr(X!,and_b(csfs(X2,msg2),a:csfs(X1,msg3)))");
    assert!(wit.len() == 4);

    // test combining with other miniscript fragments
    let wit = test_desc_satisfy(cl, testdata, "tr(X!,and_b(pk(X2),a:csfs(X1,msg4)))");
    assert!(wit.len() == 4);

    // test price oracle 1
    let price = testdata.pubdata.price;
    let wit = test_desc_satisfy(
        cl,
        testdata,
        &format!(
            "tr(X!,and_v(v:pk(X2),num64_eq(price_oracle1(X1,123213),{})))",
            price
        ),
    );
    assert_eq!(wit.len(), 4 + 2); // 4 witness elements + 1 for price oracle + 1 for time

    // More complex tests
    test_desc_satisfy(
        cl,
        testdata,
        "tr(X!,and_v(v:pk(X1),num64_eq(price_oracle1(X2,1),price_oracle1_w(X3,2))))",
    );
    test_desc_satisfy(
        cl,
        testdata,
        &format!(
            "tr(X!,and_v(v:pk(X1),num64_eq({},price_oracle1_w(X3,2))))",
            price
        ),
    );
    // Different keys and different times
    test_desc_satisfy(
        cl,
        testdata,
        "tr(X!,and_v(v:pk(X2),num64_eq(price_oracle1(X3,1),price_oracle1_w(X4,23))))",
    );
    // Combination with other arith fragments
    test_desc_satisfy(cl, testdata, "tr(X!,and_v(v:pk(X2),num64_eq(div(add(price_oracle1(X3,1),price_oracle1_w(X4,2)),2),price_oracle1_w(X5,2))))");
}

#[test]
fn test_csfs() {
    let (cl, _, genesis_hash) = &setup::setup(false);
    let testdata = TestData::new_fixed_data(50, *genesis_hash);
    test_descs(cl, &testdata);
}
