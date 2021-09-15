// Miniscript
// Written in 2020 by
//     Sanket Kanjalkar <sanket1729@gmail.com>
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

//! # Partially-Signed Bitcoin Transactions
//!
//! This module implements the Finalizer and Extractor roles defined in
//! BIP 174, PSBT, described at
//! `https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki`
//!

use crate::miniscript::ext::NoExt;

use super::{sanity_check, Pset};
use super::{Error, InputError, PsetInputSatisfier};
use bitcoin::{self, PublicKey};
use descriptor::DescriptorTrait;
use descriptor::{CovSatisfier, CovenantDescriptor};
use elements::{self, confidential, Script};
use elements::{
    secp256k1_zkp::{self, Secp256k1},
    SigHashType, Transaction,
};
use interpreter;
use Descriptor;
use Miniscript;
use {BareCtx, Legacy, MiniscriptKey, Segwitv0};
// Get the scriptpubkey for the pset input
fn get_scriptpubkey(pset: &Pset, index: usize) -> Result<&Script, InputError> {
    let script_pubkey;
    let inp = &pset.inputs[index];
    if let Some(ref witness_utxo) = inp.witness_utxo {
        script_pubkey = &witness_utxo.script_pubkey;
    } else if let Some(ref non_witness_utxo) = inp.non_witness_utxo {
        let vout = inp.previous_output_index;
        script_pubkey = &non_witness_utxo.output[vout as usize].script_pubkey;
    } else {
        return Err(InputError::MissingUtxo);
    }
    Ok(script_pubkey)
}

// Get the amount being spent for the pset input
fn get_amt(pset: &Pset, index: usize) -> Result<confidential::Value, InputError> {
    let amt;
    let inp = &pset.inputs[index];
    if let Some(ref witness_utxo) = inp.witness_utxo {
        amt = witness_utxo.value;
    } else if let Some(ref non_witness_utxo) = inp.non_witness_utxo {
        let vout = inp.previous_output_index;
        amt = non_witness_utxo.output[vout as usize].value;
    } else {
        return Err(InputError::MissingUtxo);
    }
    Ok(amt)
}

// Create a descriptor from unfinalized PSET input.
// Panics on out of bound input index for pset
// Also sanity checks that the witness script and
// redeem script are consistent with the script pubkey.
// Does *not* check signatures
// We parse the insane version while satisfying because
// we want to move the script is probably already created
// and we want to satisfy it in any way possible.
pub(super) fn get_descriptor(
    pset: &Pset,
    index: usize,
) -> Result<Descriptor<PublicKey>, InputError> {
    // Figure out Scriptpubkey
    let script_pubkey = get_scriptpubkey(pset, index)?;
    let inp = &pset.inputs[index];
    // 1. `PK`: creates a `Pk` descriptor(does not check if partial sig is given)
    if script_pubkey.is_p2pk() {
        let script_pubkey_len = script_pubkey.len();
        let pk_bytes = &script_pubkey.to_bytes();
        match bitcoin::PublicKey::from_slice(&pk_bytes[1..script_pubkey_len - 1]) {
            Ok(pk) => Ok(Descriptor::new_pk(pk)),
            Err(e) => Err(InputError::from(e)),
        }
    } else if script_pubkey.is_p2pkh() {
        // 2. `Pkh`: creates a `PkH` descriptor if partial_sigs has the corresponding pk
        let partial_sig_contains_pk = inp
            .partial_sigs
            .iter()
            .filter(|&(&pk, _sig)| {
                *script_pubkey == elements::Script::new_p2pkh(&pk.to_pubkeyhash().into())
            })
            .next();
        match partial_sig_contains_pk {
            Some((pk, _sig)) => Ok(Descriptor::new_pkh(pk.to_owned())),
            None => Err(InputError::MissingPubkey),
        }
    } else if script_pubkey.is_v0_p2wpkh() {
        // 3. `Wpkh`: creates a `wpkh` descriptor if the partial sig has corresponding pk.
        let partial_sig_contains_pk = inp
            .partial_sigs
            .iter()
            .filter(|&(&pk, _sig)| {
                *script_pubkey == elements::Script::new_v0_wpkh(&pk.to_pubkeyhash().into())
            })
            .next();
        match partial_sig_contains_pk {
            Some((pk, _sig)) => Ok(Descriptor::new_wpkh(pk.to_owned())?),
            None => Err(InputError::MissingPubkey),
        }
    } else if script_pubkey.is_v0_p2wsh() {
        // 4. `Wsh`: creates a `Wsh` descriptor
        if inp.redeem_script.is_some() {
            return Err(InputError::NonEmptyRedeemScript);
        }
        if let Some(ref witness_script) = inp.witness_script {
            if witness_script.to_v0_p2wsh() != *script_pubkey {
                return Err(InputError::InvalidWitnessScript {
                    witness_script: witness_script.clone(),
                    p2wsh_expected: script_pubkey.clone(),
                });
            }
            // First try parsing as covenant descriptor. Then try normal wsh descriptor
            match CovenantDescriptor::parse_insane(witness_script) {
                Ok(cov) => Ok(Descriptor::Cov(cov)),
                Err(_) => {
                    let ms = Miniscript::<bitcoin::PublicKey, Segwitv0, NoExt>::parse_insane(
                        witness_script,
                    )?;
                    Ok(Descriptor::new_wsh(ms)?)
                }
            }
        } else {
            Err(InputError::MissingWitnessScript)
        }
    } else if script_pubkey.is_p2sh() {
        match &inp.redeem_script {
            &None => return Err(InputError::MissingRedeemScript),
            &Some(ref redeem_script) => {
                if redeem_script.to_p2sh() != *script_pubkey {
                    return Err(InputError::InvalidRedeemScript {
                        redeem: redeem_script.clone(),
                        p2sh_expected: script_pubkey.clone(),
                    });
                }
                if redeem_script.is_v0_p2wsh() {
                    // 5. `ShWsh` case
                    if let Some(ref witness_script) = inp.witness_script {
                        if witness_script.to_v0_p2wsh() != *redeem_script {
                            return Err(InputError::InvalidWitnessScript {
                                witness_script: witness_script.clone(),
                                p2wsh_expected: redeem_script.clone(),
                            });
                        }
                        let ms = Miniscript::<bitcoin::PublicKey, Segwitv0, NoExt>::parse_insane(
                            witness_script,
                        )?;
                        Ok(Descriptor::new_sh_wsh(ms)?)
                    } else {
                        Err(InputError::MissingWitnessScript)
                    }
                } else if redeem_script.is_v0_p2wpkh() {
                    // 6. `ShWpkh` case
                    let partial_sig_contains_pk = inp
                        .partial_sigs
                        .iter()
                        .filter(|&(&pk, _sig)| {
                            *script_pubkey
                                == elements::Script::new_v0_wpkh(&pk.to_pubkeyhash().into())
                        })
                        .next();
                    match partial_sig_contains_pk {
                        Some((pk, _sig)) => Ok(Descriptor::new_sh_wpkh(pk.to_owned())?),
                        None => Err(InputError::MissingPubkey),
                    }
                } else {
                    //7. regular p2sh
                    if inp.witness_script.is_some() {
                        return Err(InputError::NonEmptyWitnessScript);
                    }
                    if let Some(ref redeem_script) = inp.redeem_script {
                        let ms = Miniscript::<bitcoin::PublicKey, Legacy, NoExt>::parse_insane(
                            redeem_script,
                        )?;
                        Ok(Descriptor::new_sh(ms)?)
                    } else {
                        Err(InputError::MissingWitnessScript)
                    }
                }
            }
        }
    } else {
        // 8. Bare case
        if inp.witness_script.is_some() {
            return Err(InputError::NonEmptyWitnessScript);
        }
        if inp.redeem_script.is_some() {
            return Err(InputError::NonEmptyRedeemScript);
        }
        let ms = Miniscript::<bitcoin::PublicKey, BareCtx, NoExt>::parse_insane(script_pubkey)?;
        Ok(Descriptor::new_bare(ms)?)
    }
}

// Helper function to de-duplicate code
pub fn _interpreter_inp_check<C: secp256k1_zkp::Verification>(
    pset: &Pset,
    tx: &Transaction,
    secp: &Secp256k1<C>,
    index: usize,
) -> Result<(), Error> {
    let cltv = pset
        .locktime()
        .map_err(|_e| Error::LockTimeCombinationError)?;
    let input = &pset.inputs[index];

    let spk = get_scriptpubkey(pset, index).map_err(|e| Error::InputError(e, index))?;
    let empty_script_sig = Script::new();
    let empty_witness = Vec::new();
    let script_sig = input.final_script_sig.as_ref().unwrap_or(&empty_script_sig);
    let witness = input
        .final_script_witness
        .as_ref()
        .unwrap_or(&empty_witness);

    // Now look at all the satisfied constraints. If everything is filled in
    // corrected, there should be no errors

    let csv = pset.inputs[index].sequence.unwrap_or(0xffffffff);
    let amt = get_amt(pset, index).map_err(|e| Error::InputError(e, index))?;

    let mut interpreter =
        interpreter::Interpreter::from_txdata(spk, &script_sig, &witness, cltv, csv)
            .map_err(|e| Error::InputError(InputError::Interpreter(e), index))?;

    let vfyfn = interpreter.sighash_verify(&secp, &tx, index, amt);
    if let Some(error) = interpreter.iter(vfyfn).filter_map(Result::err).next() {
        return Err(Error::InputError(InputError::Interpreter(error), index));
    }
    Ok(())
}
/// Interpreter check per pset input
pub fn interpreter_inp_check<C: secp256k1_zkp::Verification>(
    pset: &Pset,
    secp: &Secp256k1<C>,
    index: usize,
) -> Result<(), Error> {
    let tx = pset.extract_tx()?;

    _interpreter_inp_check(pset, &tx, secp, index)
}
/// Interprets all pset inputs and checks whether the
/// script is correctly interpreted according to the context
/// The pset must have included final script sig and final witness.
/// In other words, this checks whether the finalized pset interprets
/// correctly
pub fn interpreter_check<C: secp256k1_zkp::Verification>(
    pset: &Pset,
    secp: &Secp256k1<C>,
) -> Result<(), Error> {
    let tx = pset.extract_tx()?;
    for index in 0..pset.inputs.len() {
        _interpreter_inp_check(pset, &tx, secp, index)?;
    }
    Ok(())
}

// Helper function for input sanity checks and code-dedup
fn input_sanity_checks(pset: &Pset, index: usize) -> Result<(), super::Error> {
    let input = &pset.inputs[index];
    let target = input.sighash_type.unwrap_or(elements::SigHashType::All);
    for (key, rawsig) in &input.partial_sigs {
        if rawsig.is_empty() {
            return Err(Error::InputError(
                InputError::InvalidSignature {
                    pubkey: *key,
                    sig: rawsig.clone(),
                },
                index,
            ));
        }
        let (flag, sig) = rawsig.split_last().unwrap();
        let flag = elements::SigHashType::from_u32(*flag as u32);
        if target != flag {
            return Err(Error::InputError(
                InputError::WrongSigHashFlag {
                    required: target,
                    got: flag,
                    pubkey: *key,
                },
                index,
            ));
        }
        match secp256k1_zkp::Signature::from_der(sig) {
            Err(..) => {
                return Err(Error::InputError(
                    InputError::InvalidSignature {
                        pubkey: *key,
                        sig: Vec::from(sig),
                    },
                    index,
                ));
            }
            Ok(_sig) => {
                // Interpreter will check all the sigs later.
            }
        }
    }
    Ok(())
}

// Helper function to finalize a input
fn _finalize_inp(
    pset: &mut Pset,
    extracted_tx: &Transaction,
    index: usize,
) -> Result<(), super::Error> {
    // rust 1.29 burrowchecker
    let (witness, script_sig) = {
        // Get a descriptor for this input
        let desc = get_descriptor(&pset, index).map_err(|e| Error::InputError(e, index))?;
        let pset_sat = PsetInputSatisfier::new(&pset, index);

        // If the descriptor is covenant one, create a covenant satisfier. Otherwise
        // use the regular satisfier
        if let Descriptor::Cov(cov) = &desc {
            // For covenant descriptors create satisfier
            let utxo = pset.inputs[index]
                .witness_utxo
                .as_ref()
                .ok_or(super::Error::InputError(InputError::MissingUtxo, index))?;
            // Codesepartor calculation
            let script_code = cov.cov_script_code();
            let cov_sat = CovSatisfier::new_segwitv0(
                &extracted_tx,
                index as u32,
                utxo.value,
                &script_code,
                pset.inputs[index].sighash_type.unwrap_or(SigHashType::All),
            );
            desc.get_satisfaction((pset_sat, cov_sat))
                .map_err(|e| Error::InputError(InputError::MiniscriptError(e), index))?
        } else {
            //generate the satisfaction witness and scriptsig
            desc.get_satisfaction(pset_sat)
                .map_err(|e| Error::InputError(InputError::MiniscriptError(e), index))?
        }
    };
    let input = &mut pset.inputs[index];
    //Fill in the satisfactions
    input.final_script_sig = if script_sig.is_empty() {
        None
    } else {
        Some(script_sig)
    };
    input.final_script_witness = if witness.is_empty() {
        None
    } else {
        Some(witness)
    };
    //reset everything
    input.redeem_script = None;
    input.partial_sigs.clear();
    input.sighash_type = None;
    input.redeem_script = None;
    input.bip32_derivation.clear();
    input.witness_script = None;
    Ok(())
}

/// Finalize a single input. Look at the
/// [finalize] API for finalizing all inputs
pub fn finalize_input<C: secp256k1_zkp::Verification>(
    pset: &mut Pset,
    secp: &Secp256k1<C>,
    index: usize,
) -> Result<(), super::Error> {
    input_sanity_checks(pset, index)?;

    let extracted_tx = pset.extract_tx()?;
    _finalize_inp(pset, &extracted_tx, index)?;

    interpreter_inp_check(pset, secp, index)?;
    Ok(())
}

/// Finalize the pset. This function takes in a mutable reference to pset
/// and populates the final_witness and final_scriptsig
/// of the pset assuming all of the inputs are miniscript as per BIP174.
/// If any of the inputs is not miniscript, this returns a parsing error
/// For satisfaction of individual inputs, use the satisfy API.
/// This function also performs a sanity interpreter check on the
/// finalized pset which involves checking the signatures/ preimages/timelocks.
pub fn finalize<C: secp256k1_zkp::Verification>(
    pset: &mut Pset,
    secp: &Secp256k1<C>,
) -> Result<(), super::Error> {
    sanity_check(pset)?;

    // Check well-formedness of input data
    for n in 0..pset.inputs.len() {
        input_sanity_checks(pset, n)?;
    }

    // Actually construct the witnesses
    let extracted_tx = pset.extract_tx()?;
    for index in 0..pset.inputs.len() {
        _finalize_inp(pset, &extracted_tx, index)?;
    }
    // Double check everything with the interpreter
    // This only checks whether the script will be executed
    // correctly by the bitcoin interpreter under the current
    // pset context.
    interpreter_check(&pset, secp)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::encode::{deserialize, serialize};
    use elements::hashes::hex::FromHex;

    #[test]
    fn test_inp_finalize_520bytes() {
        let mut pset : Pset = deserialize(&Vec::<u8>::from_hex("70736574ff0102040200000001030400000000010401040105010601fb04020000000001070001086b024730440220637d6cd87ac9b670c3460c4f637c9a005d517b95c85a4150757439ef697809da02204ea6a6f7844a42501c76ead15ff319bb97541ffe563432bf30a14831e2a9ae5a012102c43c9979a7eadb32f0233075a02d0855fa2ed8e786597fff3815b9a811d48208010e20ca2a8839832e19c512c80919cf9271af5367c63e09396c59116b45e25aa79d94010f0401000000011004fdffffff0001070001086b0247304402204dceea0ef5ec594ee40f986ec5c43772066513c040b2c5b32704bfb644eb6414022053df3f81760d36bb9bbb7a7badf43fde752149f0bf5c66b89e5bd70b2e2fa297012103c072ed2b07d9aba5dfa8e3042a6c1a6883d8702aa2e0c26f2af7584493912c61010e2055818d72de9fe9346589ca5b8421dbec5ab50cc817e1b1359c813110ca7469e6010f0400000000011004fdffffff0001070001086b0247304402206d729014dafbfb587bfeb003f3729dc165f0a4ebf59a47ac4c899163af6ca289022030155246fa192391e609bbcea70555aaa9a34f6c3b5992b11be5f4ac127ce422012103947d873008a2c091ccdd64c032c30656f49fd306d5321ae9a4e07bcbb0659080010e20fd7c44ed57395f818480deb96f65c97f2d715cc79ae753de5642a7a0c815519d010f0401000000011004fdffffff0001014e01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e10000220020ec2c713f5e02b75b8d31e2d978be25e109173a4b2a16f24584bddd458f8b5eb02202039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef47304402204a86173f8ff0867447f7b2f44d4fc4820b5ef4d06b603f6bf014191fed24f567022003f31ccccee0ff344528acaffe6e84872cc9525edae923366f850ca329b43d4d010105fd0e026300670480d5b260b1926b7e7e7e7e7e7e4c4e01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e10000220020503346ed7df96fb443864c62a3c89c72b51516c8afa4e2fe54ce87b5eec19e297c7eaa7454947988516c9a686b6300677e7e7e7e7e7e4c7c01aba6e3e7735aea2e22842566556ca159d995133fc414ac7ee2ee06c92ff1af0101000000000000000100026a0001230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e10000220020503346ed7df96fb443864c62a3c89c72b51516c8afa4e2fe54ce87b5eec19e297c7eaa745494798851686c936b6300677e7e7e7e7e7e4c7c01aba6e3e7735aea2e22842566556ca159d995133fc414ac7ee2ee06c92ff1af0101000000000000000100026a00017f8f32be9443b0547b4daedefd9b6b0b655bdad96759a57569bfd429291fa44f01000000003b9aca0000220020503346ed7df96fb443864c62a3c89c72b51516c8afa4e2fe54ce87b5eec19e297c7eaa745494798851686c9351885b795b7951807e6b8254887c820120887e7c820120887e7c820120887e7c820124887e7c8253887e7c7651805187638259886782012188687e7c8254887e7c820120887e7c8254887e7c8254887ea821039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef766c7cabadc101070001080100010e20fd7c44ed57395f818480deb96f65c97f2d715cc79ae753de5642a7a0c815519d010f04000000000110040000000000010308010000000000000007fc04707365740220aba6e3e7735aea2e22842566556ca159d995133fc414ac7ee2ee06c92ff1af010104026a000001030800ca9a3b0000000007fc047073657402207f8f32be9443b0547b4daedefd9b6b0b655bdad96759a57569bfd429291fa44f0104220020503346ed7df96fb443864c62a3c89c72b51516c8afa4e2fe54ce87b5eec19e290007fc0470736574012108b5acd57b633a4ab96ac07cc0127128cfdf0bd1f313d12df4bdabb8c595f3fe5f07fc047073657403210ace02b507bfca5d04b1b4b46783aea97999b9f085eed482cb2a381ca741bb02e00104160014008781f6b94a9b44e85a791d5124db1c4d93775407fc047073657404fd5110fd4e10603300000000000000017880b00107b0f85e8593ba4ba741d3b502be3a8858681ac18382884f054992ee46845b43e2e0ef0c021ae865ae190c79150d3a48e6e4ba19ff674c386d2a81524e7a324ffc555b84aab7911da7d69f459014be54e2abc3e99274662f5cd7702aae07b64b33e4d2b325b01bc5acbb43251b151afcbdc7c68cb6ce4be84682aa6d7be731104776343fcc18b176b6ac0e80d77e59c8d9cc7f1a47e2a3bb1e213004818b25e3b1d8871434982a9595cc3a278343ebe134643a9c59ca9becccb03380605ae53dfdd2938d29fda779f300cda1d6a5d7d80278766ece72c13880fc5a0aed0c82cfecc80fab6563a3d9c9d2db0ca78dbcb66f9b9fe5e35af7755016854e4874d167b4eb937132ec2f5f631bdfb82537e00e2ad4e5d868d603799345e1fa1689f1e801a4b8950304fc11ce16a0e5bb24ffe0af7f3a9d7781f00f6dc5f114f4674c9236a63a2bef2404bdb173daeb89e1854bf229043d3b2ec03fee415450ae0fde6df0677bb41baf9f0df7308d42de4c6f4eb89a314e1620b6eac3a2835463a174d17cf91e17049e0de793a37b5643fc5788a0d9945531da88eb79d3b038ec00e737f16ce2051eb888cbe8b2eae4f04caf435e7ac950b700e28b2dfc79eedf6a555c025abe80d4ce09c537a242ca0c19362151218e3cc7e5182de31187613573fb365803cc42cd31467ab56312c587fa56f8bc3ed8322c566676c5b48753a37aaafc70d53c5973c99a82c16c811d2e398c64e4e7ff7215c90031cef59e74a1da4298f422f8543daf9d8e6f9d52642df8759129fe23c42ae69780ee723e80ebf98757ff38b10fb552ff97908ef915f75aa1cbe157dd6da2238377671f9f030fb7286b69b8681c0043bb6e8b4dd72e3d19d529887dad4213226c20d780a95ea2470f44fedfbfe45bcbc540c1f1ef394f304d386969af9853242a29e159d6daa8c17ebae5f4cda1ae8bfb82a98c8ea37af780501285435f52cdbfadc474de04299fc5a0de737b9c43ac8d89d9d858074c9ff482abcf868a7b3260dfa2bc99b9c62ad4b8e339fdfd9e2309b76b2e597846c0810eaa834bd94de91a01aa67ecff6c40138a6ee7fa3903bbc17eac375b40febc889a0cd29018a24aedda1f18f15422ff02f6a4d420347fb9b0a25814ddb251cf51bba570856890fff59e825f2a195be6f41f6c5d9c3bc85f8e6fe8707bb7aa1f7da4117cfbcaaaea7a82f3052573a707cff46a2a6bb281ed0773428d6f9439266c824592035a146f6c9d1d0cbea29dcf11c271da32fcdae8834e23b54360e19b29861f3a5a8418a0b89cdd6f0f24af40db59ce7444d77e3efee9729b9827f2d0369fda915e34f50a72a0f2b80b7d56a5fba8249c958a80e87e6416834a203581cf098d14f4f451475e59af9e3737bd328ccfe5e68e8de750c2f1c9c714b20dab4cdad3402c2ebaeeb6ed9ccb58ba8be5f14944ddcc6183b438b466f710b518ba4685ec5a2e84994491c6678d7e4435e7c11ec20a468e3f11fa64c310d2deffd7d5ecfdc2d868c179041a98157b551de67b21dd39134bedee2c19bbf7d50085e3f4a2815ecb3e14cc4dd3509a36360b7fbe937d08c0c0cd90344803f2eb5ff5c998331a5c0e3d5481857d0febe8339ed4f94c97cf144f55066054428aaff92a57d6354c2781ad91b148e92bb5df896a460513beda80e5c1970b33d446a1efb62f7be002af959914eba54ec3bfcae839183c1fff2fb1eef6cf00f60ce51cba4858cba38d4e7e1492a247f75e461cfee6784a97c90e8f72eba5048a8ccb82c75e9f8a62da1081d9af9693e3eac896407213cc8256089d150d31d96fd17097355ffef2cf9a748e2549612cf9b97be832b4a2fd570c11d7ad4e3785b75a8aed042cc8f5f29565cee51ad4a2aac23c282479fa76431bba569ba7be2cfe3e5ba90f26f6ee51149e86d682061b0c5cb7b6ce42a622242450c93786bda710cde93ee27cb0a4dd3dc50f9e340fe09380a72a242baff30e31e29b09d796b76b8640f72e0c9b34dc2b011a2bcbbe1df2dcb5101392d28f898a56ff758212ff1559153d6826a4969578e9f6ad525fdc00558026348cdecd0dc0c42f7944c3393e6379be0062b6ed1f8d3d98c2879364b130b1c9a8f706c45e017dc1f9ce6843d7b48449e4399143376e0408dba6dda84910a3d750197a0884ee5c83f243784f3c5fc8be37f9fb3ab89e8e0545e17446c2310e9b35bdd6948541acd643080bf9efac1c173f702dbdf888dee8c4f86cb2b83ad1159cfcaeda29cfa329e101a44a9024a0f7ebf2cec7b88ff5b757427622eb28d4a7672a43a0d4f2ed424c162f0e939eae38f154759f8181d90bec5399c11a32b8e5506e94aedc3827f0ef6ac5d61a636df9c1f341c51215b54a33a15a21e578968c974a00d939c46858727b098e06497c5e77013292e45cd086467bc069f3c64a84f7f17f5e6ffeac04a5a24df91a9cb5d4e5a67b8b8a8ee696ea75f6b5b57dd8486e39279c2e5188e0a736ac449c296fbab0deebe54cb9d8d57fc89b928cf003d149f8cccb99580123429c259ed402e1a19d04af6d428a3044d7f191717bb6ad2b30d287595f6b24ddc24b3c285af9d65151b11084728600351c51cedc57a5ffa23ffb2931e35566ce9ca4554927e6dce33cc0b39bb410bf54639a318f33789295c94a23f543a44fbb5c3ba0c974370d65f4b69efbd8476e009e5e2bf7cbb67a994086f0426a3e55e9ea7d302120c4b8ddb473f4e10898939b5f9d215705b70766ea6b9653cb873bfea6d4f3aee97feaf8dcc10a14d1ec232962d0a929a7c53a41da2eb07dd8b537595c830a7e55513be2e1e3758a1fa8c301bbce063e010bd23b34bb669a8e21bdfddd076a0e711056c9bfb22c50f74f8d37cf3d45572cc08738e0cfce1b47782995d3113f27f9afcff3e00c3dac20fcf90ef66c3f6747cc2b6d2c5a0f23a9d8121e60c9565f01682ad4cb94b3d07b23355023395dfe5fff2e4247e69f8a4a72a1f0f4ec37f6f9a364373623cdc6a877e90d18693421e3198068e6e0353a58eaccf9efc0463147f5ba2462e03f52055017632d998f5972009cde623d0979a287279bbf564bdfe0bc97f22b54d6550dabfe09b5307beec84c9b22a4dfa712286c0b0af4a244a66f4c68866881ff6c0c4ef7a65677c5280e2d628fd1221508be46be48e0009603a1c6ff87024c692e5be3e76a401fab760f48e983371fc75bb9a021eb4e39d72714aa5b01b4d571ba97b397c9052b4bfde9c35015a70f6901a6824b43ec0edadb0529fa6fff015280b7cb120d96e97b99c0d5a83ed1c511397f8c528251524284d40445e0337ed6ee16a803a32f7faa8d66b571dc618511b5484d2569e7f2c5db8f14d8887e2c0d560a2576d855bf301b1dd329f74d8c5408531ba2d49437d92a90fbeeaf873d8430d3691ebd6b9e594d5b87085c83ce8fba39b0cad37794266f08c0d591968bfba54314afba7ef88daedd2d63c85aa7f26a696d3d1101ad630e38ac250261d5a0021fe1e833fba63684ad89a0d13706935f727c10b2cead1eaa20a5a521eb3e0e8aa1819b5563d499193af01bdfcd04bf0e838312885d923f5394e537c28265cb84ffa9abdbef6ad59c7948f43b2b87054cf3d6fdd58dc16affc75a1e3b7b3dca86cd42dd271062283c7eee92d7e417927b837199737e4f3a894d15a7933c95e692daf68b13ef0cf4892503631ecdc72d3fbfd433a83dc078b420f0a46780749b7bc65233cfa633d0e73976d5bd15570c58ea363bde143d55caabd004b23d617ca55072a840b2a50f34de0dae528d52d604fdf7c46cbb97929661490820687c295433bca5648f82e2398dc37a23c5920bc1e64f9ff90e4bca1ff0af72a4d8b0f275e0fd7f403aacd1f23d48ae228191c46bd3af5bd792349f64a719eefadeb5ff347f2a38a67b4d751edb62a34d776295ce636c0fd4fcb4be5af4cd286b151255f13e5b8186920c42d3ef44b15747f00d94ef15f327d427ae37017ed5dc35711d108028c7de9f0f17175fab6261b50294c502d959067b25c9948013f67fad9967798f57deb536ee23418801aca24210bc941a583a01abe8d0839fd6b522a693b7231e19eadc3842030f5ee37d96176f3326ab4823f8a9a9a197028d06e3aef6b97886add7202140891fd26172c8590a09f8a336fec867149222db1da21d2fe4ccfd3424de6c474644a14ca7b94708e4773666936f75336918458b0be7f2c3c9cd5ce2bb0b0f1c8542c3fccd6539b1768f4922880a5e1672fd246abf1f3a75278493e45782a3fabffa66d2b89cf5e11af762e884b04918ea325d9ca7680bee7eff5be40444acb4dd09640b54e77c5605268661c24fef401c04d73ce64a4651ac7c3df57ab5d5a9e0d8979a11c5d1d98ef1388bc8b25b4478aee1645f4c8255034719d075901fe6c23cf1a5fff0351d09690cfb88b81636df11e31397713f756b72cdbbaf08d64a815a0277a93400a027ca04fd3b4243c86b71b5c99d61311ec6c25d4739bf28b34f9b9d284a8ca6e7bbdec4f2f50c92944410d48e5db76c1baa1fb1eb68d90a96038f95b157b5c10973cde2a21ba73b345f7e9d0d9fa2a1a0210e9a5764c61bcfe0f8dd88407feb2ab868332541806a7c0cc01de8242f99b8eed23fef778af3ad5ff24f739b50ad0fb2ac0366455bf38707571ef6b6766d0ed87960068d0cc67caff9fc5a128d83df6dc58d434ccb189ad20e112dc5db76e19d421046af5b0e0b5083ec999ed61e581bd21eda4f573f7d1d67456eddba4eec0c51b54ba7fedf2c3d0af38138d6d25f9f0e1e2e55dee6a56dfab7e341d525cc3326b6c96b66c143dced139ba09a3ff01ec4d434d8224c363da0df6e024ee0b2098364b68a85ced5323496dc8f0fc0d673dfdb3b98dccb9048eadb1e3f5fdcf4108826b56d53485c491ea0155630bd1458dcd5c22898fd3d5ffb06bffb647f6375ff9260d56c5cb6d35c89c3d05a420e884fb9def082a3cad803ae24d184b12d7f9e1d8b76c751b8ed5830d64806843871f4177ff0e9fd9710413771516912d23d36c41245ac68fdc18ab6fa83f47b27946ba00ce710c05b064d1450938726b07d72bbd9dd1351cecbbcb3a8e5202b170b7d710a349881c13c9b5285617c9b1b017325fcafb67331d96271d1e22c701356019a6bf49931d7fa99f9d138b19d4dece2b9ffd4afbebe248dd93e5877fc9cb0951621cb9bfa33bf8bac479fa6d77298ce43e869bab8c78a8d95451441f152d24580f8cf9dfeac0e77725df59bf3ee4b559e987f863b22719da4e9fb87baeac7b63afa8e43d62de41dc748c9903e84d85f78b92a994a72794d781b8bfcd9ff3ec98d2ec40f8c826d0c040a778a1f423a04b59998dd9fddb3e1cd46111a1d456618eb9716eb8a710f57a4447d9b7fca0856ac6fa2afad35d8acafb5e09964af2c16eae6cdfae015bc0b9b9e9cdf0777d85bcd9b0e71a077b32f9c619849087c6e90b8ef28fa603be42e84f535aad50adc16abb150cdc1dc4f48f2e2c690098d3f06d7bc6f8f9c8371368ae34b7cb0f3313d548bbd33f0933e23c8f4c40415dff1d37f24075748fb7c7ac5e63906283fca90d5c98573edb9c22dc02f9a9d1d269a7124b4ab55c90e62d0697ee145ec814444f23873fa023d51caf19904413a46fcad1c8dba8fbe42fe68caa34820bd1c73ab587342ab5646ecf802c8da4ff89e990fdf3d10f8e949be7ea110b3cc1ac0d49d1f35b23851dea43e27b75d12ea25d5ad88868a40fc53d30cbf52dae8e38c7d8fcf8e8784921e110ef94863cb971adaa67b6160e22c956570d9d6fa9f644db34b3f87391c53f670c5867c147165aef06a93cd4bd02dd38b4a2f0cc491f99231bca01a1b4341ca37f0695940a7d77c57587f8a07fc04707365740584830400071324f912be9be8db6528de0e02c5c92ee1211546645b108d0fa4d9fb0c2c6cdc84e40bfaf2d7b95fef16f3202713dfd5003de7b637efc4b21e4600e1f198c18ec40d44f036b19519c61aa785e18cdac369659dfa7c781d16b33b52ad5d391fafafc434546e9f25751063316d22536b6f3675011d15deb839731a6918143f2a9807fc0470736574072103ab32a659b0eb6156190f61a24a5853eaa726a2e6da68d17907290b22fcd0d5080007fc04707365740121088bc57d62245ea0d3d7be09d4effa42aa5198946f8ba1470de983b443db42638c07fc047073657403210a2a760fdb262f805739e03f780fa5d571caf630938b12bba82c87b84737a1e118010416001458506becd4157f32abd26757fa718500ad41f20007fc047073657404fd5110fd4e10603300000000000000011fa8cf0033eea2fc180097a6baf1ac0ab2174a9ddc66153b056b5bf02b3ad301b6ace94fda06a8f17c213ab69762b7c600888e0bb33efd1ab99c8d4d008a5eb828af007cc559edc1ca50c1d16ac74383ab53ed991a3e5df4fd2e4bccef79e179d4493f526c3baf89fef4990e32ef3475794d2f78f5339bebb07939aad890a5cfb229d22aaf9602fa0ce537f23c90e81f00d0abf48394d92ae12111a40085207da0cb6ac3ff0aaab32a4ae61c6999c2a68a09a64c8e5398acfa94b1a3e59baa3216e76b62d0a7089d136c4074c50659db5024499c1c5b12365910406409091dc8e804bd5eeead4872940dd9c77d113ec60349eb518e9355960f7c002b15506871bad2171b71aca88a81a31fd9c97cccbe77570298f59ab5801e2dd389230a1bf075dc4646cab7dbf0e93ab75c5dbb83524141a791556ce35f9d0f358183f664264f655cee737f28349604ab78f43e8be138d849d23d894b8c6f74e4cbe9e2d63c90cc4c041dc1cb7a2699e1c879f5a4afcd5bc8c4652df25e6f4c3bedfe9abf82f8ed522c51234e0c91f5a6d7d406acb157ee53816ae690d66337436d6c694b6f3fe876cd21df28c18771bf583e1601eee89ba6db29a070260b9c1f685026288074a1b29995c5add3eba0b6a284bb664bbef1210caf0360e9895a645d68c58ccd898428670999221f1c78362df8a729ee24ec772c37b68b8675da4b75a1a3a473ce14fa5236e40b1cb001a3de261628460a18903b407398214852867d57abed3676e8d6e6a0897d97d4527f425f8d522746f05fbfac2a10dd101faaac8a2e8013369f82474eea1c6f533c60fe990394bb70c76e9434794373c05df1a89328c7a33f384ceb056c6d8fea73755d0cbd0411f1493e6a1f80ce10e1685f36c432b90d973b06af46e1cd9c5091cc3c62ce9b3e0e3c1003d63ba904e9109a0dd0dc2f07d80ffd07fc14cac4950005281abb39dc69dbe409156ddd62db8148c17c1f35ed462ebc89f4686f24e528837497c81d43b433675977afd03e0f077046019d943587a48420295272d1d4a13a5304be5b499bd5f4cd78c520fd5b5edf301f201611447eaee14d1de13bbb1a04c0e4eb84fc5d4a5793189a3be33295ed48d595c5ce2f6a90647c7f0d58d8ed10d7dd0df48b80d6d0bff598349cf5258a089f2f5502f441fbbc87a4db0af995ba989d5aa2cb5ae02e3c07b30b66b263cf91a43034f5ac81ac68b0f55c8edb441d8b3c3720b59702475a063178459937477f5b0bf2adedcfcffd9e77695b844c27d6baa9b91f533109ac5e1ad78395a3d89e81323bc085b8acf54eaac970e0dcb7087b9121f3fa588e48e3df45994adf30c93facdbc100aa2af0035219cf00f188225a6d4a67a3fefff596c03de5a4f38696aa1eddce6c832603277fec3f6890ce799046ee931c0ffe4d1e1a60335088b012a650dd869e9b87a294eb8cc8a39cfcb131968555e580392ff9b810a0a7c80131c14368e7c88633449c3c6cc27c0a8a88e17be35722ebffca657deab426ff6b8caecf98e66f2301dfe19ad607cf2d063b08244cc3d043bb5ac1ad402bc41cea97e0d4649b18a53905e457d775de5b2f72ba6e939099d39995fee91a00c4f085edab1e6d90f7cf13a1c9f60ae6ef535331406bb7611812e6a1dfb52a7b4d70cb7718affad06a9dbec99dda962055c297d7fd78789c84b08647ca482d23e802fac9a161ee67636b9d4cdd3867c8aea0ff0575758035034341948db59b292f5092ca6dcf6e467c9f328c1cd4ce12880d1f6f1d7378773d22a6ba394b8b1932c80267aaa861a9b6341c879bb4013aa4e0b3a5bd7b01b1701ea751502c1a1efc5dda76572dabcb7d9b43af8cbbcdbbdf0cbf350b6c95519b13afdeb16b725dc684c20516bf623ecf95f825a0ff86a8fab6e4d14bf112094c041083e6a33de617dec22c4fe7144b6c50cb43d6e3118f6bb244abbe37bf16476dcacd2ece22f0eddfe073b8c2efa90f0d810082e6214c1f34d2cef43e2eae26c9899ed2c7393d5d9560d440c9feab50bd93e96c0a37a36c0995f42efe4d1685df52bf752d2deda5ea9ad0013d33f6510c6fb934d60bab489f1b56bbeef43878a2cfbc8480112433b1461e5a4b5961b66a047060783478cc57201a48fc43d281695543dedb6eb1269bd47c9a1b5e8e059b8c86cc6ce3cbe277f04bd02a40b70416d88036396d22a996a0c566eab7e7b0b0b5084fce668920c800fd7f6e88e60b15605a3708c27a6bc8d973aeed1fa5d41ee4c3a2a831b78b780aa00f6620c36f1828b0a624659313041fc646c55af542e83113856d027db0377faa884feec66b728d552a52734f809847817824c51d765f6d7f832e3e85b3becbb84f36dd24b6b573e2a42d765612b1bce9eed470d2332aacc0dc7a47f7469d1f1d6d84c2cd104c38b4713a8b79fbaada42da31f7eaaf661a717921388e466cba42df3cbd6b2b0e1399bc94811e104a37dd147bdbd581b3cb479084e02a553e67c498c9ad495d95a741f74d98fcc8795eceae38c01ad074bf1169a65f431dcd317446b0da7c8de2e6d21b6ce73204a9e11a413aa5258a3e37e1558511ccd60f3a855c7203af145be45d2b1fc96d5f8e95ab84645a988f84ade98f52dcc373048f6f3cdd2585d812ab753d14f3faa549e2ae6c2d3a6f3699c7072025440613433faf683158ff7f212c0b4250e28b93168453bab861ed4e9ccc55a7cb8fe5263bdbe8891175a59faabcaa6b607ea1efaddab229c3e4ee98aa1af82ca6dea3f36076225084914172beb7c0ef162077b6e1534b110a0608110f532be908a005b1e380e380f092fc08ba96c4deb6a413a07df0d4d54ef5f6b37ef6f6fcfbae6c2acaf46467fc12c46d803530e5d8bb85a2ca6d0480d1648bf02a73d2489ecd6586f51ce2babb93b669bf96c0cbbbb708cbd405a328ac86d1aff145468ef2214b6e96614e048bc9b589ed689ed509ce5eebb784d243ad4497fb4114ad32bac0b5b40606a613520982f3d641e910c2c6f50646da9b60521cced832f98c7648b5d56180cafa55fda5927707ea131f7c40023ac1f09f63526b144857590ad788f9bbdd23b7578b66652ef3c5ba84d08fac8b8e7ceeedb7e4dd1ff20cb16d6889bc2947d63fc5f084601018b2081e0ec04c1d8034b55da06eb6d61e5860d8071528270fde4ea8e12d69211a32b9f21c5e4c1362fe34bba97ac0c1b708ddff5f2dd62470d501862ca87fdae96812c3c94f8f32496f4e9e4387346a88a189c983d3b79d7c4f7028b647cdd7555ec37e378f4338139d7cca9500b0dd7defc59d211bb752699088572af62ede689ae76dd106978eee3c944cdf63bd1d7ebe18963e623e0cd0ecced6ee22c4c0118d9485ff4693c03f53398d8e9beb79afe89ac61441ef0b790ec6bc5c8b9d4553718a722a8219d5b4568d005f4e9181d5bec5ab688fb6445a25155ca486c0472679b870e3c52f119d0bc04a7d7a30f0d0f5ded41bcd24c9a51508ea5a76339d6bc10f577213ed6cf4f497dfda955a82dde53ef12adc168b9a3cbd0f49ffa216a8266d5078000a6ce715177a96d7d6b2eb8da3fc656013404fbd00b8d2cff2761b4ccbda3b78eb6caf29f8096a1cf6375dbd17793af2cbec6e65e6466f259e82f95e307fc2eb4e42505c3f40940f0ca61072c84a98b335db921ebb116f692528aa06e43f960c73bdac592ccfee1623ff0c2dd4caf1508f5a3d66c8fa7367f7786e3864d2d47fb2227dd347471a1104e1400ac17e90fe3304aa3967e2bea4c7109a7ac179c57b8abba409b4832ec7cf2a0a4fefa796403bbf0207a20dd08c7a7077bd9f4dfe046c5f0e7251a6ed09d822ba64a78415f8b92a66b7f039569320d789964ce7b4c433cea020674459df51118804dfe31e3c1346a61e5bf81f2206f56eb636914b99a87eb8c6745e06666b41c2e4d4b33b3ce99b7550293ba445d74c464884e6924020021578e63b4690b20f5915de4df132aea29171a03eaf5edbb9dc95c838b2e653ce8b2d9dcba06715966168722f14e08bf540cd8a4c114b9513485ec55d0956e59e046d737a703a9c64dc33a093054bbb267f8250be39f7a6e237458093e7e2c89dd262455535829b0b6f2e86ee7f2292ed56e5c7ad01857a29b4ddeee48fdfe77a0d02d92ebb8e862f8f2a75100636a380a8777db27d840a68e633e5da2e2de509b5734e870b2ab75c1f5d1d2e5c40503d933c9e1add9b599b45102e4b7b98f3ce9ac36ae446a51f320c7b0b09e554904eb478198b1389fb6cb93fbd51cdef0712d8131e8a7ec57cd62a4a553c60cb29e8257020cce65f92ee4c5ac1beda6c3f2165c5c981b066445ef09681a6f42175a5e7473159f6775a7198907f15bb5b8bd9dec530ef94f1bd8791e45c6691c08191d17827fa7856e55b0ea934a62498fa5cedd77c72f51ccda872467d20ebfc9c05906f665afb45795415f882d2d215438989fb3a71c8a5899d87b6b3cf1f4186de986a212e0fa3490d3c30b15e723f02a8839a29610c093b41191ad2698826c355f6afab6d25a5b2e20afaec69527af1b45567d4ce4bffaadb6f5704a68d96ca9187fc88381ebabf3a33216af6d6050f52d590166cc82304f89b9cb0cbebcdd3b17c3c202370c07112c074fb2a2db9c220059c7b6444a16cdeca638d3b77ae942b6694b993dfabf36f5812e97094e2c8229ff720899bea69e6c7beed78ea4094202365c00fa9fc4a2135a506d91dfb4e8e75416669980bfd61f8a4816358e9cdbf449028230c1839b1d8f4616f5bc3235c8a7e7dcde16c7c09432cd2f9e977c9ce2abba6e470116f9fa5ba99ff27883f8bad884296f13712a5f6f9bce4b0e049b7e5372c91795c5302a21cb76fc04bec0a12bca0d64c5e1261d5f820276e71abe8d134568f366ef4114cf07efe960408aa6b0eb8173f3ef17be9cf4d5d3c1345091d2d446353e8d8869bc4186190ecb7198b214a4831700ac0a18302e31469f91bb62041560bf668f7032cc4e7368afc927d2c01bebd2365aea7d6c7445be701928dbd24382630341cd1310e372d81eb3e3139bf8d73e8c5ddfae0d6d1a9cda5d319f32142278b081ef41f7b9ba643783cc677ba1f96e16addb212d8fafde89a118fef57ab2bbf496d6c8873454633c04048e1226793021bd63cd1970e66604bc82f28d8aeb4fa648e2498ff3192b27cfce839b3db07148b9016bcc84f6ea90e1b7982ee0862ca2cb6e790f686cb696edc2e68657f431a6eb47bdff66a2e8489011d2f51529801545c37d5e66f0d580a5a05bea813efd94e6ca54acb1838ecb835bfdab95381e8da436075cab82c262d2f7b9184cc3cc75e6e47fa34685f3f673e669e9cfe12bf5153f4404cd9d2c289561a1a521f103dca1c2ad7edf4ad07867cdb83d9c8574fc8fcc39e10e4e298a340f8f14cbcf5dd8049e1567e299985c457fd73b9739016e9323cc09a126aadab07e5a0f456430fa707ab8c5f3f7290b6c75c59f2ba9841323d06c3311e9615b4eda0dda676be85b73c181ed64b9549fb1da842b086f769890d408fe50f3dfa350ef62d7961fa38e34f821a5817df883b09a9c74de7b7e8d856312fb1d64bf0308c7bdfd29df70fb85241af3b3c5e0d93fa265001ba048162dc17ebd939e8c193fb0f361104042ce3572efa456a1aaebeeb1450dbb4a9730925d340a7c7a64a70657c036b77cf6cd8eb5ff1ffe0268e8c5315cff8bcbf249329751ebd5edc7a481557ab362aa737b211b1cb918301d46313378b984d3f2680a4adafe9d060ab545b69ccffcaf83447e748b3541ceca4b58cddb825cc3175397a41641163964c52e5e6069108e7d579eb098bee34f934d99b14174adf5c9345a4ce98df75e2469f6ee130523c121c4e702dc18de107fc04707365740584830400070bfa83666e25609bed6a05630824147b510f1ccb1ba6293f65cb22742ae3f8521025ff27e1c145c5f2c121e473e8aff0da4a6860f09c9b9aacbfebe42b04612d595b4ad89c66339b0e30c032e307941e22129d2884c1a2213cfbfcad1876ddb0211f0cb7b31d38f6566be7d57fb7c1097e16da409e76a556d7c09e179628939207fc0470736574072103f3a1d8be6b4dbd51150b11dc03097f2d10044c7c28fd7563480f4ef5c6bb292800010308b87c7f000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104000007fc0470736574012108ab2722dcfd8d0721250aba71de0dfb45a244ca0b0cc18fd6fed56e873013295907fc047073657403210a3511a9ab2694c94043986bc4468b9988c09a1d27fb5805a4e49f4dd251ca586c0104160014feb706b47c7e9f69572a9a52faba8668225ad4fc07fc047073657404fd5110fd4e1060330000000000000001f1145a01a9a4f79cd52b0645eb4ff19be22d8183ab088792ed3df8c089456cca5b51bd05f4a269ab4065c257051b03f1121e6f9e631d82421f4c60e7d4be6934126a0103803135325c8fe82fc81510f69eda0591a3e20846fad341f3f277f11f8163a3bc9e4afb0e41ee3e31600618ed74d6e8316c47e3495f379a7f779bc6a2644b2f40d2eef6c97050294f52c0dc61cb9078f7ef13057cae577691ac90d15ed3f5d44f43736dc56e9515c3ae2efad047ea1cc12d7779386a3e097c83f0f6b74e2030d159facac1adcdbdc3881432c9e9656877d4649711864faad9a3462380e0d1a05ca3ca5f3d02c6eb24ec8ad35af7cff5a692e41cebd82c32860cef1a0132c62a6356b89e651515c60df97b80fb66939c25a4744529b58588f77f61da101227c3c1e244b4f53fcdd9edd3e6bb5a182ee976952f3df63e43bf9f5fafa330bf4f0bcf11fb16ef9d8e0fba03cd49a7e9860ea2e2de527633a3c97827a2f69ee149f974f38d6e7320ebe95f21e6faf69823ee64a59062eb9aa29e8883caa9dbafc5203885b0a938e5c0f1b939a6e79b7932df6d2a44ab0a704c3b749df884d35849d05cea3e2ff0eaa231df8505b7b57bb3be5a9b4319a15570a8ea083a45f81c5592aec1e1527b6fc2b0cb895c6f3c674b9119bd653c19e0c06c81f97b319bf3933eb5330d2ee0ad93a9017808020f628b1768fbe24ea23116a8e1a4c1013030c117a47cf6164259e0b147e928c847245fd787c467f63081e4044b880d2506fa05f8c2eb762e6e4d4d6e86797136d88db8b4150c4780e03a68b11da71e9a754d6fe274feaf58544486225cb0a63f7ecd6b35befb89ad4282c34a11b0a57ca445e5b544c29c01488a407da677c4ef14463c0794e3f6b9bc90c65e3cd48c918e22a90c5f3aa6a3db6373d09be01641dd23d70b5ec25eb794476245587e9996aaa1cb7cde51ea6155bbf6db3c3933df6a4aa3483c2fb9b922861c3c01bf2f6cedfad0c03b6cc5e0c0b3bb8d4e60dbd15d1bff83fac956e3da263b4f58c6408d50fc51ddfc181589558b39c83fc028eb5abf30c49a324d4bbaf98ea228042084159c346e7117db1b7858392ba79425ecfbed46e9314d2e02d047ba63183fae73d57ebb3c7e9aabcf0aa477d5f3c1a2183225f4b7c2e5771a27e75dbc99833b2dfc67256e2588cded228ad13ad9c91bd5309b8635f6567d774c246ba7cf44a84c0b7b57baa75493a39af00078d45e790698d59ef83ffd352fc86c19a8cab00e9613c43619e6c93c54d94f08d73d2eefaaa3baae7e512607743ed2e709c27196b7616c31d856a6f243d5d45d4a37655db7a70b716c67a5fe2888e3c2f9f95d92b8066ac3b95d5eb6c1d25b48934944fe3f8963d2f121781cb223af404fae245ba42ca7d589fa91c964b7e9635ad820d74cae6a95cf96b1e6a78cd1ced53d61afeac153184e25ba81ed31ae0044d2f393db229951fa3f10cdd9bc185b05184ef4accb0295c12a0208abfa56009ee6282e1522ce69a7a3c1972696545f779767aabcf3304eb8d7fcf196eeb57a3a1599b8cfd5e55e71b80d27bf116d88c9b1b95f17d372d695a15e559ff6d04aeda4a9faab980684f64a917f102626ffe9fffc6186a4bc11cb4cf251b4a7668517ff9d7d8d3a1b75f002cf5d28490bbe82957ea91a7b932407fae7e8b94969f2baa8bd64662bed9714734dc7b69e99e5a62ae9bb7356314bd228b313d6df7c7e685672a80dfccc1dc939990f4f0c7c9ceda21daf980122c223b7275e5fe284fa4d65d49d85ae25019fc51a76cc28315e8c253a5e4be7de7f43f83cbb5ec9499ca501e2f73ab822db7d0b989720cdfabb7992c8a86ef1f3250ef01ce90762c1fab4c2e2a9398f9be93de61e2f6cde12fd2d12992c715fd95d659348f10d21b9998da7d27b2c06cf24b1371b29bfbd3d5177b5c27b48a06e04c5e3b4b683f60be2320d3d5cd1463612e4a007abcd1c78dea76834abeb56c677f7be2afbb70200b482e872c24666340037c2963d697a472848ed7e115a2159dc1f88b554c1c9ee111b3decd9d8327d9940e0e015ac0572b2981ea7849a30806e5d9763650dc2a44be4e8b82c5b88797be6f494b811c0b5e8cc56d28ea8e23b6ee2263e4c661d91aa90afaf4ce6748eced261762a5fba112f7a111a50a5348dc56e0a725c7831b539538d0ac973bb5059d1faf70a73b220c40973f36284015c22df8527d2a4a8b1d5f3da1de96aa27eef2ed8c7c7792719e0046a7c29ad35fa024e5b15cc7d099336e3bd78f9d205e957f873b6623074756467c23d4546b53de89bc30b8ce89c58e7f5bae453409024da97bec5d56f7d4b30dd315e24661990f409448ae5bbef573a8dbec98623bf29fe2a3d6456f001aaa29ac68322acfa204d2ac046d2988b7c0e1f6277c6da06ec40b779c5279bd49d471ec447b57ca85d8ad90ca08ab52501e67cb08f92dcd93576cc60494b3619d241db4c418e6790878a2dbd32faa46a432a486165641f913cf6c35a16c1b303709524ab263f01ba938d94f91eb71775793640f8ec27c7156026f63e7a09b8493464e7c9dad18f2b3badb46eb52b05bac2e2a40c801083533f6c570898d7e679abc39ae1f01b960bf8a78f31ace7f40e4545d56736113b0dc85ceddff496c303dca26576da9c7e2b161a897b77673aab758e304f7f2c9ef62e0ba565234fb37a4b3e4b0ada19eb5792d7bdb6779b8e233247dd4b6b91e65f0eb7615c855ba827d03c4c913df889ac3b052b0ad85dc57b335ccb6e3794281d6f9198f0836e8b846914643709de3eb314953945252551d027fc7751fecfc44e90a2bac6e5918e8ae32475f170703153d67eca8f521cc17e35555c91a19f229db17a570eaed7044693e362ddbcafa33345c9192bfdcd2b46bfd0c5a634503243208dc8e126df16b477a0491a147420c5219531652d6d00b00323f3025bf651120a74bb1c2ea810b2061ecf28768cf97e88761716d1fcdd03c8b2473315540e9e01d69226bb93d90aee8a423286a3d99a69da103c24691091929b70c6d184e13d45924e7d646f0455301fbf88e2c91a651c6d44254d1415f1f791f28435bad4de684ed82f7e8e2b49b7930474f2f1732f28df65d06b87e0a7c0e7f2b0a9410e25762dd26f407d892327b0ca8dd1ea1e9a1efc0469395f1db89180b7020d552dcdae4cdcc5db4700c0547f1283583d32c7939bbab2fdff055e1f415ca4b4a657f90ce55107c0a90cdf1beb4f73ff0cc870e0e74883205fa6434461ab97acbbd8755637b296df337fd425fcf9076bdaa1a1a6c6025980588d92bfbc6a22b9ce99b517d63f50b0efc70f3409f9f887e851d098e5ee1d211a64b96a5c6a6b352a0bbfdec75d3b38f09278d127149f20ff450a34471a2df81de90f83fd12862777d747c41d3f44e9c62d540ed3ade176ecca2dd8dd6c6f595476714d23b660f1b3586540a948a6004c4a0805b110929dfc4ef8183c215082bb20478a52c13dc8364c7e3b9d220ffd46c3af298538a62b79d3c7b7393814b32255dbf085c62f7178d56ff684b03dc635daf38ffe0d7965e610943294c59fb013c251d11d4601059024a75c2615b32e8477b1931cf8a696f1597f4a865989e6e40d299c890d128acc4f79b759027b5ed94299dbb229add22f42b42f5d6c1abb3666cd7ae70b7e364ef163984c3a452fbe1c68e6ef6147a624cbdca27c069244096b8da00be600ba932e7457359517928a0d0d5ec4c5ff42f008fc69566f3d48031b579af411bd8e14abd699d01a86e45077ccb0c98037c9ad41ac39ac4665aa081cdf4537da890c6606197d526612b16dbb90222df321e1d693d99ccab055d888be9bff482152e35d015bdb7e14ad31f71e86ec3ea8a43c59efbf3269ff4e14455b703c205b798487bec429d56025a3fdc4593f70e545a806c119d8911781d26079c8be79437215c9721e74de4b0ce4f19dd0738ee9594c1b8a36747bcc547352aa8678bfcfac5a5a6baa7af9275970c2602bb5d3fa5c9dff7f9a4e04a2c430bcd662b75d360da1ddb681312de5f1796647ff57ac83a883bbb128830faf00144e20ed542ec94a19f0e1113cc6ee97bd651a2ae226fc163eb8c2542692ae24dddd7dbce19a04291b7bc83ed44e802eb4e3f600504ffe9a5bedc09a3b77b158bc527856861062ce901f3bed043d161e895c905119af847cb48928abf09276c97e7e4ab100b17381c1aefbfa0e43bd965b7b52a6433ebc3df9db889675a296132a6feced0ce34daa52cc29a7681477d164014e58ba4fb37511d81f4549db449b25f7aa2ca8ee17cde9426e55254257449e8706ee09ec2cc01f7a419ae1c90e1c9664f0bf20d4c515433ba5b9104f43f1aa0f1722ead69702a7b828cd5f76006700baf86dd0788f90bca2519525591245a5e9e5f8dfdd1652bb28e22341292482d41fdca4f929018568b783619f091da9f08fdbf34c3a7bedb7e3ef67cfc268182cc65547bc7a03048f1928ae9fb2940420970f4a3dca997a5871f5b379676e1728ef9354e0d64598753668cedb4c60934f9fce26c7a5f968151f97d62bc80aebe17768403f050410557a79e77f236bc892d0f30385bc741eb456b5d68479de1e13a2f1a66a5d7f7a45748b4a0e8a0b1b54590278b3900cbe8ddc93c3dfae172be5d4db4787768a2d98c12f6d7602efffb49be6fc3bd15e7b1d1d86bd7f7296891649a50da4e356d11934af535d76833034e31ade0357ad1ea0cccb7e5d7d7453ad28248c8a8e52581de628b1101525bc5ea7c0c7a1347eb4e02f52f81db9ff93079ed2987f7e2f0d103636d3396e6f6fb798ea841a3a7e9238a01b147f26d2f9a7286d3f8011394a15c048a95f0d3bf5b3453f789e671660de66a943256ff619f8101560b95662c982c3cd7c844bfb98908aa74d53281d5191a71d2951ba799d4b3ef3d2b13fb6793ae74e0cb7b18be03e673ab11e2cbaef43e7f54935d64b443cdde05e5ab1b9a9b3536ad88115fc1313a833e2e37ad88b8737ba0da65b17e7ebc3e4e72b27aaaae363a5f2038d3d769a8275ccf7fb94623d11bc67b68d61079ba1a0609dafba7ee03764a2d685541f14aa4c7705207c14e7032535395ec4f8fd34c0a05919836ef0da1a93e22ac1dc69b8ee820a6df79910caabec981df12c042dde02438ab2654aa6b3a9f0448f5692b8209dad31eb395ca5fa4486bedaf408650efda798d2e252b31e8258f432c3129af7df4426762f8c2a953d9edd661d769c620dc0a01110661f92597a1bd6782be03b94f9708423d0ca60014345ff2b83ab0e07c9275ee7364567c1d15f8745e62dd16f95276f2aa9b9fcac1a5f6fbc6889cf303e0cbbbf59cced565a64e99fba1a8eb4f6dfd6304935ca6e946584291d171c5ec92df6c7b1a0f56855b579e9bf338df1803e825d928e17ec2471aaeaff0bb84fe4652a39d4bf3dc3f20ee6a7851468fb562564548476fe19f49f8f597547180f8de975a37e1ded11607d5cef0c1255bba693aa4eda71cd228441601bf605779f037a16a3d6131431f3e9973e1c35fd7b134efac4f287d1c72ad0c58783305079113d22fa02d0c36e3284ebd442ac6b35d25c6dfc2cc4c2e9fef74d6d7474b0ea8a319abb46295b537232a217d5aef6d2648640eefe56c55eb1d64e4e7108b8a864ce339fde597251816ef1fe92dab6b87d67bf11bb02e1411ed95b3dc1a80c734bcfa37c02172538334d7424bbe16dc26451ba301758403e5200670612c43b54e24c69371d67df0362bfee6b462d27c5de014d201333e7da20bdc8dac3825adfac45842c2d998a61e69cbd15951a873717a1bacb90d147e6564aaccc3fa974ad2468c357716ad01841045f4279a64acd1655b9ffd2e1ed5e298b368607fc0470736574058483040007e0bf0233e5df91a2475970b69dfa8dbe094061b774e84a314f8fc23edd565a17face7a52f8e6ea72e40442739c810cee3942c82c25336f04fb3901bf1fd05ea5e6267e969e3e1bd9fea80a6ab7e962de5d11c1f7965d56986160dda2507b631de221edea5c517a23907ebfac3a6978bb17c811ecc33ae97405cadb2e6de8c01407fc0470736574072102e3a0ca747d6391db8647aea1b0945bc076b78402bdf967cbf17efb2f50f6480d00").unwrap()).unwrap();

        let tx = pset.extract_tx().unwrap();
        // Actual sighash len is 534 since this also serializes
        // the len of outputs
        // It is still more than 520, which causes hashOutputs preimage
        // to be more than 520 which fails the finalization.
        assert_eq!(serialize(&tx.output).len(), 535);
        assert!(serialize(&tx.output).len() - 1 > 520);
        let secp = elements::secp256k1_zkp::Secp256k1::verification_only();
        // Therefore this finalization will fail to satisfy
        finalize_input(&mut pset, &secp, 3).unwrap_err();
    }
}
