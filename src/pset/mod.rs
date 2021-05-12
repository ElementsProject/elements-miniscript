// Miniscript
// Written in 2019 by
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

//! # Partially-Signed Bitcoin Transactions
//!
//! This module implements the Finalizer and Extractor roles defined in
//! BIP 174, PSBT, described at
//! `https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki`
//!

use std::{error, fmt};

use bitcoin;
use elements::hashes::{hash160, ripemd160, sha256, sha256d};
use elements::pset::PartiallySignedTransaction as Pset;
use elements::secp256k1_zkp::{self, Secp256k1};
use elements::{self, Script, SigHashType};

use interpreter;
use miniscript::limits::SEQUENCE_LOCKTIME_DISABLE_FLAG;
use miniscript::satisfy::{bitcoinsig_from_rawsig, After, Older};
use Satisfier;
use {ElementsSig, Preimage32};
use {MiniscriptKey, ToPublicKey};

mod finalizer;
use descriptor::CovSatisfier;

pub use self::finalizer::{finalize, interpreter_check};

/// Error type for Pbst Input
#[derive(Debug)]
pub enum InputError {
    /// Get the secp Errors directly
    SecpErr(elements::secp256k1_zkp::Error),
    /// Key errors
    KeyErr(bitcoin::util::key::Error),
    /// Error doing an interpreter-check on a finalized pset
    Interpreter(interpreter::Error),
    /// Redeem script does not match the p2sh hash
    InvalidRedeemScript {
        /// Redeem script
        redeem: Script,
        /// Expected p2sh Script
        p2sh_expected: Script,
    },
    /// Witness script does not match the p2wsh hash
    InvalidWitnessScript {
        /// Witness Script
        witness_script: Script,
        /// Expected p2wsh script
        p2wsh_expected: Script,
    },
    /// Invalid sig
    InvalidSignature {
        /// The bitcoin public key
        pubkey: bitcoin::PublicKey,
        /// The (incorrect) signature
        sig: Vec<u8>,
    },
    /// Pass through the underlying errors in miniscript
    MiniscriptError(super::Error),
    /// Missing redeem script for p2sh
    MissingRedeemScript,
    /// Missing witness
    MissingWitness,
    /// used for public key corresponding to pkh/wpkh
    MissingPubkey,
    /// Missing witness script for segwit descriptors
    MissingWitnessScript,
    ///Missing both the witness and non-witness utxo
    MissingUtxo,
    /// Non empty Witness script for p2sh
    NonEmptyWitnessScript,
    /// Non empty Redeem script
    NonEmptyRedeemScript,
    /// Sighash did not match
    WrongSigHashFlag {
        /// required sighash type
        required: SigHashType,
        /// the sighash type we got
        got: SigHashType,
        /// the corresponding publickey
        pubkey: bitcoin::PublicKey,
    },
}

/// Error type for entire Pset
#[derive(Debug)]
pub enum Error {
    /// Cannot combine locktimes
    LockTimeCombinationError,
    /// Upstream Error
    PsetError(elements::pset::Error),
    /// Input Error type
    InputError(InputError, usize),
    /// Wrong Input Count
    WrongInputCount {
        /// Input count in tx
        in_tx: usize,
        /// Input count in pset
        in_map: usize,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InputError::InvalidSignature {
                ref pubkey,
                ref sig,
            } => write!(f, "PSET: bad signature {} for key {:?}", pubkey.key, sig),
            InputError::KeyErr(ref e) => write!(f, "Key Err: {}", e),
            InputError::Interpreter(ref e) => write!(f, "Interpreter: {}", e),
            InputError::SecpErr(ref e) => write!(f, "Secp Err: {}", e),
            InputError::InvalidRedeemScript {
                ref redeem,
                ref p2sh_expected,
            } => write!(
                f,
                "Redeem script {} does not match the p2sh script {}",
                redeem, p2sh_expected
            ),
            InputError::InvalidWitnessScript {
                ref witness_script,
                ref p2wsh_expected,
            } => write!(
                f,
                "Witness script {} does not match the p2wsh script {}",
                witness_script, p2wsh_expected
            ),
            InputError::MiniscriptError(ref e) => write!(f, "Miniscript Error: {}", e),
            InputError::MissingWitness => write!(f, "PSET is missing witness"),
            InputError::MissingRedeemScript => write!(f, "PSET is Redeem script"),
            InputError::MissingUtxo => {
                write!(f, "PSET is missing both witness and non-witness UTXO")
            }
            InputError::MissingWitnessScript => write!(f, "PSET is missing witness script"),
            InputError::MissingPubkey => write!(f, "Missing pubkey for a pkh/wpkh"),
            InputError::NonEmptyRedeemScript => write!(
                f,
                "PSET has non-empty redeem script at for legacy transactions"
            ),
            InputError::NonEmptyWitnessScript => {
                write!(f, "PSET has non-empty witness script at for legacy input")
            }
            InputError::WrongSigHashFlag {
                required,
                got,
                pubkey,
            } => write!(
                f,
                "PSET: signature with key {:?} had \
                 sighashflag {:?} rather than required {:?}",
                pubkey.key, got, required
            ),
        }
    }
}

#[doc(hidden)]
impl From<super::Error> for InputError {
    fn from(e: super::Error) -> InputError {
        InputError::MiniscriptError(e)
    }
}

#[doc(hidden)]
impl From<elements::secp256k1_zkp::Error> for InputError {
    fn from(e: elements::secp256k1_zkp::Error) -> InputError {
        InputError::SecpErr(e)
    }
}

#[doc(hidden)]
impl From<bitcoin::util::key::Error> for InputError {
    fn from(e: bitcoin::util::key::Error) -> InputError {
        InputError::KeyErr(e)
    }
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InputError(ref inp_err, index) => write!(f, "{} at index {}", inp_err, index),
            Error::WrongInputCount { in_tx, in_map } => write!(
                f,
                "PSET had {} inputs in transaction but {} inputs in map",
                in_tx, in_map
            ),
            Error::LockTimeCombinationError => write!(
                f,
                "Cannot combine hieghtlocks and \
                timelocks\n"
            ),
            Error::PsetError(ref e) => write!(f, "Pset Error {}", e),
        }
    }
}

#[doc(hidden)]
impl From<elements::pset::Error> for Error {
    fn from(e: elements::pset::Error) -> Error {
        Error::PsetError(e)
    }
}

/// Pset satisfier for at inputs at a particular index
/// Takes in &pset because multiple inputs will share
/// the same pset structure
/// All operations on this structure will panic if index
/// is more than number of inputs in pbst
/// This does not support satisfaction for Covenant transactoins
/// You are probably looking for [`finalizer::finalize`] method
/// or [`PsetCovInputSatisfier`]
pub struct PsetInputSatisfier<'pset> {
    /// pbst
    pub pset: &'pset Pset,
    /// input index
    pub index: usize,
}

/// Pset Input Satisfier with Covenant support. Users should be
/// using the high level [`finalizer::finalize`] API.
/// The [`CovSatisfier`] should be consistent with the extracted transaction.
pub struct PsetCovInputSatisfier<'pset>(PsetInputSatisfier<'pset>, CovSatisfier<'pset, 'pset>);

impl<'pset> PsetInputSatisfier<'pset> {
    /// create a new PsetInputsatisfier from
    /// pset and index
    pub fn new(pset: &'pset Pset, index: usize) -> Self {
        Self {
            pset: pset,
            index: index,
        }
    }
}

impl<'pset, Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for PsetInputSatisfier<'pset> {
    fn lookup_sig(&self, pk: &Pk) -> Option<ElementsSig> {
        if let Some(rawsig) = self.pset.inputs[self.index]
            .partial_sigs
            .get(&pk.to_public_key())
        {
            // We have already previously checked that all signatures have the
            // correct sighash flag.
            bitcoinsig_from_rawsig(rawsig).ok()
        } else {
            None
        }
    }

    fn lookup_pkh_sig(&self, pkh: &Pk::Hash) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        if let Some((pk, sig)) = self.pset.inputs[self.index]
            .partial_sigs
            .iter()
            .filter(|&(pubkey, _sig)| pubkey.to_pubkeyhash() == Pk::hash_to_hash160(pkh))
            .next()
        {
            // If the mapping is incorrect, return None
            bitcoinsig_from_rawsig(sig)
                .ok()
                .map(|bitcoinsig| (*pk, bitcoinsig))
        } else {
            None
        }
    }

    fn check_after(&self, n: u32) -> bool {
        let locktime = match self.pset.locktime() {
            Ok(locktime) => locktime,
            Err(..) => return false,
        };
        let seq = self.pset.inputs[self.index].sequence.unwrap_or(0xffffffff);

        // https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
        // fail if TxIn is finalized
        if seq == 0xffffffff {
            false
        } else {
            <Satisfier<Pk>>::check_after(&After(locktime), n)
        }
    }

    fn check_older(&self, n: u32) -> bool {
        let seq = self.pset.inputs[self.index].sequence.unwrap_or(0xffffffff);
        // https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
        // Disable flag set. return true
        if n & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            true
        } else if self.pset.global.tx_data.version < 2
            || (seq & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0)
        {
            // transaction version and sequence check
            false
        } else {
            <Satisfier<Pk>>::check_older(&Older(seq), n)
        }
    }

    fn lookup_hash160(&self, h: hash160::Hash) -> Option<Preimage32> {
        self.pset.inputs[self.index]
            .hash160_preimages
            .get(&h)
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_sha256(&self, h: sha256::Hash) -> Option<Preimage32> {
        self.pset.inputs[self.index]
            .sha256_preimages
            .get(&h)
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_hash256(&self, h: sha256d::Hash) -> Option<Preimage32> {
        self.pset.inputs[self.index]
            .hash256_preimages
            .get(&h)
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_ripemd160(&self, h: ripemd160::Hash) -> Option<Preimage32> {
        self.pset.inputs[self.index]
            .ripemd160_preimages
            .get(&h)
            .and_then(try_vec_as_preimage32)
    }
}

fn try_vec_as_preimage32(vec: &Vec<u8>) -> Option<Preimage32> {
    if vec.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);
        Some(arr)
    } else {
        None
    }
}

fn sanity_check(pset: &Pset) -> Result<(), Error> {
    if pset.global.n_inputs() != pset.inputs.len() {
        return Err(Error::WrongInputCount {
            in_tx: pset.global.n_inputs(),
            in_map: pset.inputs.len(),
        }
        .into());
    }

    Ok(())
}

/// Pset extractor as defined in BIP174 that takes in a pset reference
/// and outputs a extracted elements::Transaction
/// Also does the interpreter sanity check
/// Will error if the final ScriptSig or final Witness are missing
/// or the interpreter check fails.
pub fn extract<C: secp256k1_zkp::Verification>(
    pset: &Pset,
    secp: &Secp256k1<C>,
) -> Result<elements::Transaction, Error> {
    sanity_check(pset)?;

    let ret = pset.clone().extract_tx()?;
    // Extractor in rust-elements
    interpreter_check(pset, secp)?;
    Ok(ret)
}

#[cfg(test)]
mod tests {
    // use super::*;

    // use elements::encode::deserialize;
    // use elements::hashes::hex::FromHex;

    // #[test]
    // fn test_extract_bip174() {
    //     let pset: Pset = deserialize(&Vec::<u8>::from_hex("70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000").unwrap()).unwrap();
    //     let secp = Secp256k1::verification_only();
    //     let tx = extract(&pset, &secp).unwrap();
    //     let expected: elements::Transaction = deserialize(&Vec::<u8>::from_hex("0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000").unwrap()).unwrap();
    //     assert_eq!(tx, expected);
    // }
}
