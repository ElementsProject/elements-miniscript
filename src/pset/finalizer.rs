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

use super::{sanity_check, Pset};
use super::{Error, InputError, PsetInputSatisfier};
use bitcoin::{self, PublicKey};
use descriptor::DescriptorTrait;
use elements::secp256k1_zkp::{self, Secp256k1};
use elements::{self, confidential, Script};
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
fn get_descriptor(pset: &Pset, index: usize) -> Result<Descriptor<PublicKey>, InputError> {
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
            let ms = Miniscript::<bitcoin::PublicKey, Segwitv0>::parse_insane(witness_script)?;
            Ok(Descriptor::new_wsh(ms)?)
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
                        let ms = Miniscript::<bitcoin::PublicKey, Segwitv0>::parse_insane(
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
                        let ms =
                            Miniscript::<bitcoin::PublicKey, Legacy>::parse_insane(redeem_script)?;
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
        let ms = Miniscript::<bitcoin::PublicKey, BareCtx>::parse_insane(script_pubkey)?;
        Ok(Descriptor::new_bare(ms)?)
    }
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
    let cltv = pset
        .locktime()
        .map_err(|_e| Error::LockTimeCombinationError)?;
    let tx = pset.clone().extract_tx()?;
    for (index, input) in pset.inputs.iter().enumerate() {
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
    }
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
    for (n, input) in pset.inputs.iter().enumerate() {
        let target = input.sighash_type.unwrap_or(elements::SigHashType::All);
        for (key, rawsig) in &input.partial_sigs {
            if rawsig.is_empty() {
                return Err(Error::InputError(
                    InputError::InvalidSignature {
                        pubkey: *key,
                        sig: rawsig.clone(),
                    },
                    n,
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
                    n,
                ));
            }
            match secp256k1_zkp::Signature::from_der(sig) {
                Err(..) => {
                    return Err(Error::InputError(
                        InputError::InvalidSignature {
                            pubkey: *key,
                            sig: Vec::from(sig),
                        },
                        n,
                    ));
                }
                Ok(_sig) => {
                    // Interpreter will check all the sigs later.
                }
            }
        }
    }

    // Actually construct the witnesses
    for index in 0..pset.inputs.len() {
        // Get a descriptor for this input
        let desc = get_descriptor(&pset, index).map_err(|e| Error::InputError(e, index))?;

        //generate the satisfaction witness and scriptsig
        let (witness, script_sig) = desc
            .get_satisfaction(PsetInputSatisfier::new(&pset, index))
            .map_err(|e| Error::InputError(InputError::MiniscriptError(e), index))?;

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
    }
    // Double check everything with the interpreter
    // This only checks whether the script will be executed
    // correctly by the bitcoin interpreter under the current
    // pset context.
    interpreter_check(&pset, secp)?;
    Ok(())
}
