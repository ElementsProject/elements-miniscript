//! # rust-miniscript integration test
//!
//! Read Miniscripts from file and translate into miniscripts
//! which we know how to satisfy
//!

use std::{error, fmt};

use elements::hashes::{sha256d, Hash};
use elements::pset::PartiallySignedTransaction as Psbt;
use elements::sighash::SighashCache;
use elements::taproot::TapLeafHash;
use elements::{
    confidential, pset as psbt, secp256k1_zkp as secp256k1, sighash, OutPoint, SchnorrSig, Script,
    Sequence, TxIn, TxOut, Txid,
};
use elementsd::ElementsD;
use miniscript::psbt::{PsbtExt, PsbtInputExt};
use miniscript::{
    bitcoin, elements, elementssig_to_rawsig, Descriptor, Miniscript, ScriptContext, ToPublicKey,
};
use rand::RngCore;
mod setup;
use ::secp256k1::Scalar;
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

#[derive(Debug, PartialEq)]
pub enum DescError {
    /// PSBT was not able to finalize
    PsbtFinalizeError,
    /// Problem with address computation
    AddressComputationError,
    /// Error while parsing the descriptor
    DescParseError,
}

impl fmt::Display for DescError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DescError::PsbtFinalizeError => f.write_str("PSBT was not able to finalize"),
            DescError::AddressComputationError => f.write_str("Problem with address computation"),
            DescError::DescParseError => f.write_str("Not able to parse the descriptor"),
        }
    }
}

impl error::Error for DescError {}

pub fn test_desc_satisfy(
    cl: &ElementsD,
    testdata: &TestData,
    descriptor: &str,
) -> Result<Vec<Vec<u8>>, DescError> {
    /* Convert desc into elements one by adding a prefix*/
    let descriptor = format!("el{}", descriptor);
    //
    let secp = secp256k1::Secp256k1::new();
    let sks = &testdata.secretdata.sks;
    let xonly_keypairs = &testdata.secretdata.x_only_keypairs;
    let pks = &testdata.pubdata.pks;
    let x_only_pks = &testdata.pubdata.x_only_pks;
    // Generate some blocks
    cl.generate(1);

    let definite_desc = test_util::parse_test_desc(&descriptor, &testdata.pubdata)
        .map_err(|_| DescError::DescParseError)?
        .at_derivation_index(0)
        .unwrap();

    let derived_desc = definite_desc.derived_descriptor(&secp).unwrap();
    let desc_address = derived_desc.address(&PARAMS); // No blinding
    let desc_address = desc_address.map_err(|_x| DescError::AddressComputationError)?;

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
        Descriptor::Tr(ref tr) => {
            // Fixme: take a parameter
            let hash_ty = sighash::SchnorrSighashType::Default;

            let internal_key_present = x_only_pks
                .iter()
                .position(|&x| x.to_public_key() == *tr.internal_key());
            let internal_keypair = internal_key_present.map(|idx| xonly_keypairs[idx]);
            let prevouts = [witness_utxo];
            let prevouts = sighash::Prevouts::All(&prevouts);

            if let Some(internal_keypair) = internal_keypair {
                // ---------------------- Tr key spend --------------------
                let internal_keypair = internal_keypair
                    .add_xonly_tweak(
                        &secp,
                        &Scalar::from_be_bytes(tr.spend_info().tap_tweak().to_byte_array())
                            .expect("valid scalar"),
                    )
                    .expect("Tweaking failed");
                let sighash_msg = sighash_cache
                    .taproot_key_spend_signature_hash(
                        0,
                        &prevouts,
                        hash_ty,
                        testdata.pubdata.genesis_hash,
                    )
                    .unwrap();
                let msg = secp256k1::Message::from_slice(&sighash_msg[..]).unwrap();
                let mut aux_rand = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut aux_rand);
                let schnorr_sig =
                    secp.sign_schnorr_with_aux_rand(&msg, &internal_keypair, &aux_rand);
                psbt.inputs_mut()[0].tap_key_sig = Some(SchnorrSig {
                    sig: schnorr_sig,
                    hash_ty,
                });
            } else {
                // No internal key
            }
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
                let (x_only_pk, _parity) = secp256k1::XOnlyPublicKey::from_keypair(&keypair);
                psbt.inputs_mut()[0].tap_script_sigs.insert(
                    (x_only_pk, leaf_hash),
                    elements::SchnorrSig { sig, hash_ty },
                );
            }
        }
        _ => {
            // Non-tr descriptors
            // Ecdsa sigs
            let sks_reqd = match derived_desc {
                Descriptor::Bare(bare) => find_sks_ms(bare.as_inner(), testdata),
                Descriptor::Pkh(pk) => find_sk_single_key(*pk.as_inner(), testdata),
                Descriptor::Wpkh(pk) => find_sk_single_key(*pk.as_inner(), testdata),
                Descriptor::Sh(sh) => match sh.as_inner() {
                    miniscript::descriptor::ShInner::Wsh(wsh) => match wsh.as_inner() {
                        miniscript::descriptor::WshInner::SortedMulti(ref smv) => {
                            let ms = Miniscript::from_ast(smv.sorted_node()).unwrap();
                            find_sks_ms(&ms, testdata)
                        }
                        miniscript::descriptor::WshInner::Ms(ref ms) => find_sks_ms(ms, testdata),
                    },
                    miniscript::descriptor::ShInner::Wpkh(pk) => {
                        find_sk_single_key(*pk.as_inner(), testdata)
                    }
                    miniscript::descriptor::ShInner::SortedMulti(smv) => {
                        let ms = Miniscript::from_ast(smv.sorted_node()).unwrap();
                        find_sks_ms(&ms, testdata)
                    }
                    miniscript::descriptor::ShInner::Ms(ms) => find_sks_ms(ms, testdata),
                },
                Descriptor::Wsh(wsh) => match wsh.as_inner() {
                    miniscript::descriptor::WshInner::SortedMulti(ref smv) => {
                        let ms = Miniscript::from_ast(smv.sorted_node()).unwrap();
                        find_sks_ms(&ms, testdata)
                    }
                    miniscript::descriptor::WshInner::Ms(ref ms) => find_sks_ms(ms, testdata),
                },
                Descriptor::Tr(_tr) => unreachable!("Tr checked earlier"),
                Descriptor::TrExt(_tr) => unreachable!("Extensions not tested here"),
                Descriptor::LegacyCSFSCov(_cov) => unimplemented!("Covenant tests not supported"),
            };
            let msg = psbt
                .sighash_msg(0, &mut sighash_cache, None, testdata.pubdata.genesis_hash)
                .unwrap()
                .to_secp_msg();

            // Fixme: Take a parameter
            let hash_ty = elements::EcdsaSighashType::All;

            // Finally construct the signature and add to psbt
            for sk in sks_reqd {
                let sig = secp.sign_ecdsa(&msg, &sk);
                let pk = pks[sks.iter().position(|&x| x == sk).unwrap()];
                assert!(secp.verify_ecdsa(&msg, &sig, &pk.inner).is_ok());
                psbt.inputs_mut()[0]
                    .partial_sigs
                    .insert(pk, elementssig_to_rawsig(&(sig, hash_ty)));
            }
        }
    }
    // Add the hash preimages to the psbt
    psbt.inputs_mut()[0].sha256_preimages.insert(
        testdata.pubdata.sha256,
        testdata.secretdata.sha256_pre.to_vec(),
    );
    psbt.inputs_mut()[0].hash256_preimages.insert(
        sha256d::Hash::from_byte_array(testdata.pubdata.hash256.to_byte_array()),
        testdata.secretdata.hash256_pre.to_vec(),
    );
    psbt.inputs_mut()[0].hash160_preimages.insert(
        testdata.pubdata.hash160,
        testdata.secretdata.hash160_pre.to_vec(),
    );
    psbt.inputs_mut()[0].ripemd160_preimages.insert(
        testdata.pubdata.ripemd160,
        testdata.secretdata.ripemd160_pre.to_vec(),
    );
    println!("Testing descriptor: {}", definite_desc);
    // Finalize the transaction using psbt
    // Let miniscript do it's magic!
    if psbt
        .finalize_mut(&secp, testdata.pubdata.genesis_hash)
        .is_err()
    {
        return Err(DescError::PsbtFinalizeError);
    }
    let tx = psbt
        .extract(&secp, testdata.pubdata.genesis_hash)
        .expect("Extraction error");

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
    Ok(tx.input[0].witness.script_witness.clone())
}

// Find all secret corresponding to the known public keys in ms
fn find_sks_ms<Ctx: ScriptContext>(
    ms: &Miniscript<bitcoin::PublicKey, Ctx>,
    testdata: &TestData,
) -> Vec<secp256k1::SecretKey> {
    let sks = &testdata.secretdata.sks;
    let pks = &testdata.pubdata.pks;
    let sks = ms
        .iter_pk()
        .filter_map(|pk| {
            let i = pks.iter().position(|&x| x.to_public_key() == pk);
            i.map(|idx| (sks[idx]))
        })
        .collect();
    sks
}

fn find_sk_single_key(pk: bitcoin::PublicKey, testdata: &TestData) -> Vec<secp256k1::SecretKey> {
    let sks = &testdata.secretdata.sks;
    let pks = &testdata.pubdata.pks;
    let i = pks.iter().position(|&x| x.to_public_key() == pk);
    i.map(|idx| vec![sks[idx]]).unwrap_or(Vec::new())
}

fn test_descs(cl: &ElementsD, testdata: &TestData) {
    // K : Compressed key available
    // K!: Compressed key with corresponding secret key unknown
    // X: X-only key available
    // X!: X-only key with corresponding secret key unknown

    // Test 1: Simple spend with internal key
    let wit = test_desc_satisfy(cl, testdata, "tr(X)").unwrap();
    assert!(wit.len() == 1);

    // Test 2: Same as above, but with leaves
    let wit = test_desc_satisfy(cl, testdata, "tr(X,{pk(X1!),pk(X2!)})").unwrap();
    assert!(wit.len() == 1);

    // Test 3: Force to spend with script spend. Unknown internal key and only one known script path
    // X! -> Internal key unknown
    // Leaf 1 -> pk(X1) with X1 known
    // Leaf 2-> and_v(v:pk(X2),pk(X3!)) with partial witness only to X2 known
    let wit = test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1),and_v(v:pk(X2),pk(X3!))})").unwrap();
    assert!(wit.len() == 3); // control block, script and signature

    // Test 4: Force to spend with script spend. Unknown internal key and multiple script paths
    // Should select the one with minimum weight
    // X! -> Internal key unknown
    // Leaf 1 -> pk(X1!) with X1 unknown
    // Leaf 2-> and_v(v:pk(X2),pk(X3)) X2 and X3 known
    let wit = test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1),and_v(v:pk(X2),pk(X3))})").unwrap();
    assert!(wit.len() == 3); // control block, script and one signatures

    // Test 5: When everything is available, we should select the key spend path
    let wit = test_desc_satisfy(cl, testdata, "tr(X,{pk(X1),and_v(v:pk(X2),pk(X3!))})").unwrap();
    assert!(wit.len() == 1); // control block, script and signature

    // Test 6: Test the new multi_a opcodes
    test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),multi_a(1,X2,X3!,X4!,X5!)})").unwrap();
    test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),multi_a(2,X2,X3,X4!,X5!)})").unwrap();
    test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),multi_a(3,X2,X3,X4,X5!)})").unwrap();
    test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),multi_a(4,X2,X3,X4,X5)})").unwrap();

    // Test 7: Test script tree of depth 127 is valid, only X128 is known
    test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),{pk(X2!),{pk(X3!),{pk(X4!),{pk(X5!),{pk(X6!),{pk(X7!),{pk(X8!),{pk(X9!),{pk(X10!),{pk(X11!),{pk(X12!),{pk(X13!),{pk(X14!),{pk(X15!),{pk(X16!),{pk(X17!),{pk(X18!),{pk(X19!),{pk(X20!),{pk(X21!),{pk(X22!),{pk(X23!),{pk(X24!),{pk(X25!),{pk(X26!),{pk(X27!),{pk(X28!),{pk(X29!),{pk(X30!),{pk(X31!),{pk(X32!),{pk(X33!),{pk(X34!),{pk(X35!),{pk(X36!),{pk(X37!),{pk(X38!),{pk(X39!),{pk(X40!),{pk(X41!),{pk(X42!),{pk(X43!),{pk(X44!),{pk(X45!),{pk(X46!),{pk(X47!),{pk(X48!),{pk(X49!),{pk(X50!),{pk(X51!),{pk(X52!),{pk(X53!),{pk(X54!),{pk(X55!),{pk(X56!),{pk(X57!),{pk(X58!),{pk(X59!),{pk(X60!),{pk(X61!),{pk(X62!),{pk(X63!),{pk(X64!),{pk(X65!),{pk(X66!),{pk(X67!),{pk(X68!),{pk(X69!),{pk(X70!),{pk(X71!),{pk(X72!),{pk(X73!),{pk(X74!),{pk(X75!),{pk(X76!),{pk(X77!),{pk(X78!),{pk(X79!),{pk(X80!),{pk(X81!),{pk(X82!),{pk(X83!),{pk(X84!),{pk(X85!),{pk(X86!),{pk(X87!),{pk(X88!),{pk(X89!),{pk(X90!),{pk(X91!),{pk(X92!),{pk(X93!),{pk(X94!),{pk(X95!),{pk(X96!),{pk(X97!),{pk(X98!),{pk(X99!),{pk(X100!),{pk(X101!),{pk(X102!),{pk(X103!),{pk(X104!),{pk(X105!),{pk(X106!),{pk(X107!),{pk(X108!),{pk(X109!),{pk(X110!),{pk(X111!),{pk(X112!),{pk(X113!),{pk(X114!),{pk(X115!),{pk(X116!),{pk(X117!),{pk(X118!),{pk(X119!),{pk(X120!),{pk(X121!),{pk(X122!),{pk(X123!),{pk(X124!),{pk(X125!),{pk(X126!),{pk(X127!),pk(X128)}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}})").unwrap();

    // Test 8: Test script tree of depth 128 is valid, only X129 is known
    test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),{pk(X2!),{pk(X3!),{pk(X4!),{pk(X5!),{pk(X6!),{pk(X7!),{pk(X8!),{pk(X9!),{pk(X10!),{pk(X11!),{pk(X12!),{pk(X13!),{pk(X14!),{pk(X15!),{pk(X16!),{pk(X17!),{pk(X18!),{pk(X19!),{pk(X20!),{pk(X21!),{pk(X22!),{pk(X23!),{pk(X24!),{pk(X25!),{pk(X26!),{pk(X27!),{pk(X28!),{pk(X29!),{pk(X30!),{pk(X31!),{pk(X32!),{pk(X33!),{pk(X34!),{pk(X35!),{pk(X36!),{pk(X37!),{pk(X38!),{pk(X39!),{pk(X40!),{pk(X41!),{pk(X42!),{pk(X43!),{pk(X44!),{pk(X45!),{pk(X46!),{pk(X47!),{pk(X48!),{pk(X49!),{pk(X50!),{pk(X51!),{pk(X52!),{pk(X53!),{pk(X54!),{pk(X55!),{pk(X56!),{pk(X57!),{pk(X58!),{pk(X59!),{pk(X60!),{pk(X61!),{pk(X62!),{pk(X63!),{pk(X64!),{pk(X65!),{pk(X66!),{pk(X67!),{pk(X68!),{pk(X69!),{pk(X70!),{pk(X71!),{pk(X72!),{pk(X73!),{pk(X74!),{pk(X75!),{pk(X76!),{pk(X77!),{pk(X78!),{pk(X79!),{pk(X80!),{pk(X81!),{pk(X82!),{pk(X83!),{pk(X84!),{pk(X85!),{pk(X86!),{pk(X87!),{pk(X88!),{pk(X89!),{pk(X90!),{pk(X91!),{pk(X92!),{pk(X93!),{pk(X94!),{pk(X95!),{pk(X96!),{pk(X97!),{pk(X98!),{pk(X99!),{pk(X100!),{pk(X101!),{pk(X102!),{pk(X103!),{pk(X104!),{pk(X105!),{pk(X106!),{pk(X107!),{pk(X108!),{pk(X109!),{pk(X110!),{pk(X111!),{pk(X112!),{pk(X113!),{pk(X114!),{pk(X115!),{pk(X116!),{pk(X117!),{pk(X118!),{pk(X119!),{pk(X120!),{pk(X121!),{pk(X122!),{pk(X123!),{pk(X124!),{pk(X125!),{pk(X126!),{pk(X127!),{pk(X128!),pk(X129)}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}})").unwrap();

    // Test 9: Test script complete tree having 128 leaves with depth log(128), only X1 is known
    test_desc_satisfy(cl, testdata, "tr(X!,{{{{{{{pk(X1),pk(X2!)},{pk(X3!),pk(X4!)}},{{pk(X5!),pk(X6!)},{pk(X7!),pk(X8!)}}},{{{pk(X9!),pk(X10!)},{pk(X11!),pk(X12!)}},{{pk(X13!),pk(X14!)},{pk(X15!),pk(X16!)}}}},{{{{pk(X17!),pk(X18!)},{pk(X19!),pk(X20!)}},{{pk(X21!),pk(X22!)},{pk(X23!),pk(X24!)}}},{{{pk(X25!),pk(X26!)},{pk(X27!),pk(X28!)}},{{pk(X29!),pk(X30!)},{pk(X31!),pk(X32!)}}}}},{{{{{pk(X33!),pk(X34!)},{pk(X35!),pk(X36!)}},{{pk(X37!),pk(X38!)},{pk(X39!),pk(X40!)}}},{{{pk(X41!),pk(X42!)},{pk(X43!),pk(X44!)}},{{pk(X45!),pk(X46!)},{pk(X47!),pk(X48!)}}}},{{{{pk(X49!),pk(X50!)},{pk(X51!),pk(X52!)}},{{pk(X53!),pk(X54!)},{pk(X55!),pk(X56!)}}},{{{pk(X57!),pk(X58!)},{pk(X59!),pk(X60!)}},{{pk(X61!),pk(X62!)},{pk(X63!),pk(X64!)}}}}}},{{{{{{pk(X65!),pk(X66!)},{pk(X67!),pk(X68!)}},{{pk(X69!),pk(X70!)},{pk(X71!),pk(X72!)}}},{{{pk(X73!),pk(X74!)},{pk(X75!),pk(X76!)}},{{pk(X77!),pk(X78!)},{pk(X79!),pk(X80!)}}}},{{{{pk(X81!),pk(X82!)},{pk(X83!),pk(X84!)}},{{pk(X85!),pk(X86!)},{pk(X87!),pk(X88!)}}},{{{pk(X89!),pk(X90!)},{pk(X91!),pk(X92!)}},{{pk(X93!),pk(X94!)},{pk(X95!),pk(X96!)}}}}},{{{{{pk(X97!),pk(X98!)},{pk(X99!),pk(X100!)}},{{pk(X101!),pk(X102!)},{pk(X103!),pk(X104!)}}},{{{pk(X105!),pk(X106!)},{pk(X107!),pk(X108!)}},{{pk(X109!),pk(X110!)},{pk(X111!),pk(X112!)}}}},{{{{pk(X113!),pk(X114!)},{pk(X115!),pk(X116!)}},{{pk(X117!),pk(X118!)},{pk(X119!),pk(X120!)}}},{{{pk(X121!),pk(X122!)},{pk(X123!),pk(X124!)}},{{pk(X125!),pk(X126!)},{pk(X127!),pk(X128!)}}}}}}})").unwrap();

    // Test 10: Test taproot desc with ZERO known keys
    let result = test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),pk(X2!)})");
    assert_eq!(result, Err(DescError::PsbtFinalizeError));

    // Test 10: Test taproot desc with ZERO known keys
    let result = test_desc_satisfy(cl, testdata, "tr(X!,j:multi_a(3,X1!,X2,X3,X4))");
    assert_eq!(result, Err(DescError::DescParseError));

    // Test 11: Test taproot with insufficient known keys
    let result = test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),multi_a(3,X2!,X3,X4)})");
    assert_eq!(result, Err(DescError::PsbtFinalizeError));

    // Test 12: size exceeds the limit
    let result = test_desc_satisfy(cl, testdata, "wsh(thresh(1,pk(K1),a:pk(K2),a:pk(K3),a:pk(K4),a:pk(K5),a:pk(K6),a:pk(K7),a:pk(K8),a:pk(K9),a:pk(K10),a:pk(K11),a:pk(K12),a:pk(K13),a:pk(K14),a:pk(K15),a:pk(K16),a:pk(K17),a:pk(K18),a:pk(K19),a:pk(K20),a:pk(K21),a:pk(K22),a:pk(K23),a:pk(K24),a:pk(K25),a:pk(K26),a:pk(K27),a:pk(K28),a:pk(K29),a:pk(K30),a:pk(K31),a:pk(K32),a:pk(K33),a:pk(K34),a:pk(K35),a:pk(K36),a:pk(K37),a:pk(K38),a:pk(K39),a:pk(K40),a:pk(K41),a:pk(K42),a:pk(K43),a:pk(K44),a:pk(K45),a:pk(K46),a:pk(K47),a:pk(K48),a:pk(K49),a:pk(K50),a:pk(K51),a:pk(K52),a:pk(K53),a:pk(K54),a:pk(K55),a:pk(K56),a:pk(K57),a:pk(K58),a:pk(K59),a:pk(K60),a:pk(K61),a:pk(K62),a:pk(K63),a:pk(K64),a:pk(K65),a:pk(K66),a:pk(K67),a:pk(K68),a:pk(K69),a:pk(K70),a:pk(K71),a:pk(K72),a:pk(K73),a:pk(K74),a:pk(K75),a:pk(K76),a:pk(K77),a:pk(K78),a:pk(K79),a:pk(K80),a:pk(K81),a:pk(K82),a:pk(K83),a:pk(K84),a:pk(K85),a:pk(K86),a:pk(K87),a:pk(K88),a:pk(K89),a:pk(K90),a:pk(K91),a:pk(K92),a:pk(K93),a:pk(K94),a:pk(K95),a:pk(K96),a:pk(K97),a:pk(K98),a:pk(K99),a:pk(K100)))");
    assert_eq!(result, Err(DescError::DescParseError));

    // Test 13: Test script tree of depth > 128 is invalid
    let result = test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),{pk(X2!),{pk(X3!),{pk(X4!),{pk(X5!),{pk(X6!),{pk(X7!),{pk(X8!),{pk(X9!),{pk(X10!),{pk(X11!),{pk(X12!),{pk(X13!),{pk(X14!),{pk(X15!),{pk(X16!),{pk(X17!),{pk(X18!),{pk(X19!),{pk(X20!),{pk(X21!),{pk(X22!),{pk(X23!),{pk(X24!),{pk(X25!),{pk(X26!),{pk(X27!),{pk(X28!),{pk(X29!),{pk(X30!),{pk(X31!),{pk(X32!),{pk(X33!),{pk(X34!),{pk(X35!),{pk(X36!),{pk(X37!),{pk(X38!),{pk(X39!),{pk(X40!),{pk(X41!),{pk(X42!),{pk(X43!),{pk(X44!),{pk(X45!),{pk(X46!),{pk(X47!),{pk(X48!),{pk(X49!),{pk(X50!),{pk(X51!),{pk(X52!),{pk(X53!),{pk(X54!),{pk(X55!),{pk(X56!),{pk(X57!),{pk(X58!),{pk(X59!),{pk(X60!),{pk(X61!),{pk(X62!),{pk(X63!),{pk(X64!),{pk(X65!),{pk(X66!),{pk(X67!),{pk(X68!),{pk(X69!),{pk(X70!),{pk(X71!),{pk(X72!),{pk(X73!),{pk(X74!),{pk(X75!),{pk(X76!),{pk(X77!),{pk(X78!),{pk(X79!),{pk(X80!),{pk(X81!),{pk(X82!),{pk(X83!),{pk(X84!),{pk(X85!),{pk(X86!),{pk(X87!),{pk(X88!),{pk(X89!),{pk(X90!),{pk(X91!),{pk(X92!),{pk(X93!),{pk(X94!),{pk(X95!),{pk(X96!),{pk(X97!),{pk(X98!),{pk(X99!),{pk(X100!),{pk(X101!),{pk(X102!),{pk(X103!),{pk(X104!),{pk(X105!),{pk(X106!),{pk(X107!),{pk(X108!),{pk(X109!),{pk(X110!),{pk(X111!),{pk(X112!),{pk(X113!),{pk(X114!),{pk(X115!),{pk(X116!),{pk(X117!),{pk(X118!),{pk(X119!),{pk(X120!),{pk(X121!),{pk(X122!),{pk(X123!),{pk(X124!),{pk(X125!),{pk(X126!),{pk(X127!),{pk(X128!),{pk(X129!),pk(X130)}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}})");
    assert_eq!(result, Err(DescError::DescParseError));

    // Misc tests for other descriptors that we support
    // Keys
    test_desc_satisfy(cl, testdata, "wpkh(K)").unwrap();
    test_desc_satisfy(cl, testdata, "pkh(K)").unwrap();
    test_desc_satisfy(cl, testdata, "sh(wpkh(K))").unwrap();

    // sorted multi
    test_desc_satisfy(cl, testdata, "sh(sortedmulti(2,K1,K2,K3))").unwrap();
    test_desc_satisfy(cl, testdata, "wsh(sortedmulti(2,K1,K2,K3))").unwrap();
    test_desc_satisfy(cl, testdata, "sh(wsh(sortedmulti(2,K1,K2,K3)))").unwrap();

    // Miniscripts
    test_desc_satisfy(cl, testdata, "sh(and_v(v:pk(K1),pk(K2)))").unwrap();
    test_desc_satisfy(cl, testdata, "wsh(and_v(v:pk(K1),pk(K2)))").unwrap();
    test_desc_satisfy(cl, testdata, "sh(wsh(and_v(v:pk(K1),pk(K2))))").unwrap();
}

#[test]
fn test_satisfy() {
    let (cl, _, genesis_hash) = &setup::setup(false);
    let testdata = TestData::new_fixed_data(50, *genesis_hash);
    test_descs(cl, &testdata);
}
