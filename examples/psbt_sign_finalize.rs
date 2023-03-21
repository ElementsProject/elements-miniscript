use std::str::FromStr;

use elements::bitcoin::PrivateKey;
use elements::encode::{serialize, serialize_hex};
use elements::hashes::Hash;
use elements::sighash::SigHashCache;
use elements::{confidential, AssetId, PackedLockTime, TxOutWitness};
use elements_miniscript as miniscript;
use elementsd::bitcoincore_rpc::jsonrpc::base64;
use miniscript::elements::hashes::hex::FromHex;
use miniscript::elements::pset::PartiallySignedTransaction as Psbt;
use miniscript::elements::{
    self, pset, secp256k1_zkp as secp256k1, Address, AddressParams, OutPoint, Script, Sequence,
    Transaction, TxIn, TxOut,
};
use miniscript::psbt::{PsbtExt, PsbtInputExt};
use miniscript::{elementssig_to_rawsig, Descriptor};

const ELEMENTS_PARAMS: AddressParams = AddressParams::ELEMENTS;

fn main() {
    let secp256k1 = secp256k1::Secp256k1::new();

    let s = "elwsh(t:or_c(pk(027a3565454fe1b749bccaef22aff72843a9c3efefd7b16ac54537a0c23f0ec0de),v:thresh(1,pkh(032d672a1a91cc39d154d366cd231983661b0785c7f27bc338447565844f4a6813),a:pkh(03417129311ed34c242c012cd0a3e0b9bca0065f742d0dfb63c78083ea6a02d4d9),a:pkh(025a687659658baeabdfc415164528065be7bcaade19342241941e556557f01e28))))#tdp6ld3e";
    let bridge_descriptor = Descriptor::from_str(&s).unwrap();
    //let bridge_descriptor = Descriptor::<bitcoin::PublicKey>::from_str(&s).expect("parse descriptor string");
    assert!(bridge_descriptor.sanity_check().is_ok());
    println!(
        "Bridge pubkey script: {}",
        bridge_descriptor.script_pubkey()
    );
    println!(
        "Bridge address: {}",
        bridge_descriptor.address(&ELEMENTS_PARAMS).unwrap()
    );
    println!(
        "Weight for witness satisfaction cost {}",
        bridge_descriptor.max_weight_to_satisfy().unwrap()
    );

    let master_private_key_str = "cQhdvB3McbBJdx78VSSumqoHQiSXs75qwLptqwxSQBNBMDxafvaw";
    let _master_private_key =
        PrivateKey::from_str(master_private_key_str).expect("Can't create private key");
    println!(
        "Master public key: {}",
        _master_private_key.public_key(&secp256k1)
    );

    let backup1_private_key_str = "cWA34TkfWyHa3d4Vb2jNQvsWJGAHdCTNH73Rht7kAz6vQJcassky";
    let backup1_private =
        PrivateKey::from_str(backup1_private_key_str).expect("Can't create private key");

    println!(
        "Backup1 public key: {}",
        backup1_private.public_key(&secp256k1)
    );

    let backup2_private_key_str = "cPJFWUKk8sdL7pcDKrmNiWUyqgovimmhaaZ8WwsByDaJ45qLREkh";
    let backup2_private =
        PrivateKey::from_str(backup2_private_key_str).expect("Can't create private key");

    println!(
        "Backup2 public key: {}",
        backup2_private.public_key(&secp256k1)
    );

    let backup3_private_key_str = "cT5cH9UVm81W5QAf5KABXb23RKNSMbMzMx85y6R2mF42L94YwKX6";
    let _backup3_private =
        PrivateKey::from_str(backup3_private_key_str).expect("Can't create private key");

    println!(
        "Backup3 public key: {}",
        _backup3_private.public_key(&secp256k1)
    );

    let spend_tx = Transaction {
        version: 2,
        lock_time: PackedLockTime(5000),
        input: vec![],
        output: vec![],
    };

    // Spend one input and spend one output for simplicity.
    let mut psbt = Psbt::from_tx(spend_tx);

    let receiver =
        Address::from_str("ert1qpq2cfgz5lktxzr5zqv7nrzz46hsvq3492ump9pz8rzcl8wqtwqcs2yqnuv")
            .unwrap();

    let amount = 100000000;

    let outpoint = elements::OutPoint {
        txid: elements::Txid::from_hex(
            "7a3565454fe1b749bccaef22aff72843a9c3efefd7b16ac54537a0c23f0ec0de",
        )
        .unwrap(),
        vout: 0,
    };

    let witness_utxo = bitcoin_asset_txout(bridge_descriptor.script_pubkey(), amount);

    // In practice, you would have to get the outpoint and witness utxo from the blockchain.
    // something like this:
    // let depo_tx = elements::Transction::from_hex("...").unwrap();
    // let (outpoint, witness_utxo) = get_vout(&depo_tx, bridge_descriptor.script_pubkey());

    let mut txin = TxIn::default();
    txin.previous_output = outpoint;

    txin.sequence = Sequence::from_height(26); //Sequence::MAX; //
    psbt.add_input(pset::Input::from_txin(txin));

    psbt.add_output(pset::Output::from_txout(bitcoin_asset_txout(
        receiver.script_pubkey(),
        amount / 5 - 500,
    )));

    psbt.add_output(pset::Output::from_txout(bitcoin_asset_txout(
        bridge_descriptor.script_pubkey(),
        amount * 4 / 5,
    )));

    // Elements: Add output for fee
    psbt.add_output(pset::Output::from_txout(bitcoin_asset_txout(
        Script::new(),
        500,
    )));

    // Generating signatures & witness data

    psbt.inputs_mut()[0]
        .update_with_descriptor_unchecked(&bridge_descriptor)
        .unwrap();

    psbt.inputs_mut()[0].witness_utxo = Some(witness_utxo.clone());

    let tx = &psbt.extract_tx().unwrap();
    let mut sighash_cache = SigHashCache::new(tx);

    // genesis hash is not used at all for sighash calculation
    let genesis_hash = elements::BlockHash::all_zeros();
    let msg = psbt
        .sighash_msg(0, &mut sighash_cache, None, genesis_hash)
        .unwrap()
        .to_secp_msg();

    // Fixme: Take a parameter
    let hash_ty = elements::EcdsaSigHashType::All;

    let sk1 = backup1_private.inner;
    let sk2 = backup2_private.inner;

    // Finally construct the signature and add to psbt
    let sig1 = secp256k1.sign_ecdsa(&msg, &sk1);
    let pk1 = backup1_private.public_key(&secp256k1);
    assert!(secp256k1.verify_ecdsa(&msg, &sig1, &pk1.inner).is_ok());

    // Second key just in case
    let sig2 = secp256k1.sign_ecdsa(&msg, &sk2);
    let pk2 = backup2_private.public_key(&secp256k1);
    assert!(secp256k1.verify_ecdsa(&msg, &sig2, &pk2.inner).is_ok());

    psbt.inputs_mut()[0]
        .partial_sigs
        .insert(pk1, elementssig_to_rawsig(&(sig1, hash_ty)));

    println!("{:#?}", psbt);

    let serialized = serialize(&psbt);
    println!("{}", base64::encode(&serialized));

    psbt.finalize_mut(&secp256k1, genesis_hash).unwrap();
    println!("{:#?}", psbt);

    let tx = psbt.extract_tx().unwrap();
    println!("{}", serialize_hex(&tx));
}

// Find the Outpoint by spk
#[allow(dead_code)]
fn get_vout(tx: &Transaction, spk: Script) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("Only call get vout on functions which have the expected outpoint");
}

// Creates a bitcoin asset txout with the given explicit amount
// The bitcoin asset id is hardcoded for tests and is not the actual bitcoin asset id of elements network
fn bitcoin_asset_txout(spk: Script, amt: u64) -> TxOut {
    TxOut {
        script_pubkey: spk,
        value: confidential::Value::Explicit(amt),
        asset: confidential::Asset::Explicit(
            AssetId::from_hex("088f6b381694259fd20599e71f7eb46e392f36b43cc20d131d95c8a4b8cc1aa8")
                .unwrap(),
        ),
        nonce: confidential::Nonce::Null,
        witness: TxOutWitness::default(),
    }
}
