// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! # Partially-Signed Bitcoin Transactions
//!
//! This module implements the Finalizer and Extractor roles defined in
//! BIP 174, PSBT, described at
//! `https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki`
//!

use std::collections::BTreeMap;
use std::ops::Deref;
use std::{error, fmt};

use bitcoin;
use bitcoin::bip32;
use elements::hashes::{hash160, sha256d, Hash};
use elements::pset::PartiallySignedTransaction as Psbt;
use elements::secp256k1_zkp::{self as secp256k1, Secp256k1, VerifyOnly};
use elements::sighash::SighashCache;
use elements::taproot::{self, ControlBlock, LeafVersion, TapLeafHash};
use elements::{
    self, pset as psbt, EcdsaSighashType, LockTime, SchnorrSighashType, Script, Sequence,
};

use crate::extensions::{CovExtArgs, CovenantExt, ParseableExt};
use crate::{
    descriptor, elementssig_from_rawsig, interpreter, DefiniteDescriptorKey, Descriptor,
    DescriptorPublicKey, ElementsSig, Extension, MiniscriptKey, Preimage32, Satisfier, ToPublicKey,
    TranslatePk, Translator,
};
mod finalizer;
pub use finalizer::finalize;

use self::finalizer::interpreter_check;
use crate::descriptor::{LegacyCovSatisfier, Tr};
use crate::{util, SigType};

/// Error type for entire Psbt
#[derive(Debug)]
pub enum Error {
    /// Cannot combine locktimes
    LockTimeCombinationError,
    /// Upstream Error
    PsbtError(elements::pset::Error),
    /// Input Error type
    InputError(InputError, usize),
    /// Wrong Input Count
    WrongInputCount {
        /// Input count in tx
        in_tx: usize,
        /// Input count in psbt
        in_map: usize,
    },
    /// Input index out of bounds
    InputIdxOutofBounds {
        /// Number of inputs in psbt
        psbt_inp: usize,
        /// The input index
        index: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::InputError(ref inp_err, index) => write!(f, "{} at index {}", inp_err, index),
            Error::WrongInputCount { in_tx, in_map } => write!(
                f,
                "PSET had {} inputs in transaction but {} inputs in map",
                in_tx, in_map
            ),
            Error::LockTimeCombinationError => writeln!(
                f,
                "Cannot combine hieghtlocks and \
                timelocks"
            ),
            Error::PsbtError(ref e) => write!(f, "Psbt Error {}", e),
            Error::InputIdxOutofBounds { psbt_inp, index } => write!(
                f,
                "Index {} is out of bounds for psbt inputs len {}",
                index, psbt_inp
            ),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::Error::*;

        match self {
            InputError(e, _) => Some(e),
            WrongInputCount { .. } | InputIdxOutofBounds { .. } => None,
            LockTimeCombinationError => None,
            PsbtError(e) => Some(e),
        }
    }
}

/// Error type for Pbst Input
#[derive(Debug)]
pub enum InputError {
    /// Could not satisfy Tr
    CouldNotSatisfyTr,
    /// Get the secp Errors directly
    SecpErr(elements::secp256k1_zkp::Error),
    /// Key errors
    KeyErr(bitcoin::key::FromSliceError),
    /// Error doing an interpreter-check on a finalized psbt
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
    /// Non standard sighash type
    NonStandardSighashType,
    /// Sighash did not match
    WrongSighashFlag {
        /// required sighash type
        required: EcdsaSighashType,
        /// the sighash type we got
        got: EcdsaSighashType,
        /// the corresponding publickey
        pubkey: bitcoin::PublicKey,
    },
}

impl error::Error for InputError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::InputError::*;

        match self {
            CouldNotSatisfyTr
            | InvalidRedeemScript { .. }
            | InvalidWitnessScript { .. }
            | InvalidSignature { .. }
            | MissingRedeemScript
            | MissingWitness
            | MissingPubkey
            | MissingWitnessScript
            | MissingUtxo
            | NonEmptyWitnessScript
            | NonEmptyRedeemScript
            | NonStandardSighashType
            | WrongSighashFlag { .. } => None,
            SecpErr(e) => Some(e),
            KeyErr(e) => Some(e),
            Interpreter(e) => Some(e),
            MiniscriptError(e) => Some(e),
        }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            InputError::InvalidSignature {
                ref pubkey,
                ref sig,
            } => write!(f, "PSET: bad signature {} for key {:?}", pubkey, sig),
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
            InputError::WrongSighashFlag {
                required,
                got,
                pubkey,
            } => write!(
                f,
                "PSET: signature with key {} had \
                 sighashflag {:?} rather than required {:?}",
                pubkey, got, required
            ),
            InputError::CouldNotSatisfyTr => write!(f, "Cannot satisfy Tr descriptor"),
            InputError::NonStandardSighashType => write!(f, "Non-standard sighash type"),
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
impl From<bitcoin::key::FromSliceError> for InputError {
    fn from(e: bitcoin::key::FromSliceError) -> InputError {
        InputError::KeyErr(e)
    }
}

#[doc(hidden)]
impl From<elements::pset::Error> for Error {
    fn from(e: elements::pset::Error) -> Error {
        Error::PsbtError(e)
    }
}

/// Psbt satisfier for at inputs at a particular index
/// Takes in &psbt because multiple inputs will share
/// the same psbt structure
/// All operations on this structure will panic if index
/// is more than number of inputs in pbst
/// This does not support satisfaction for Covenant transactoins
/// You are probably looking for [`finalizer::finalize`] method
/// or [`PsbtCovInputSatisfier`]
pub struct PsbtInputSatisfier<'psbt> {
    /// pbst
    pub psbt: &'psbt Psbt,
    /// input index
    pub index: usize,
}

/// Psbt Input Satisfier with Covenant support. Users should be
/// using the high level [`finalizer::finalize`] API.
/// The [`LegacyCovSatisfier`] should be consistent with the extracted transaction.
pub type PsbtCovInputSatisfier<'psbt> =
    (PsbtInputSatisfier<'psbt>, LegacyCovSatisfier<'psbt, 'psbt>);

impl<'psbt> PsbtInputSatisfier<'psbt> {
    /// create a new PsbtInputsatisfier from
    /// psbt and index
    pub fn new(psbt: &'psbt Psbt, index: usize) -> Self {
        Self { psbt, index }
    }
}

impl<'psbt, Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for PsbtInputSatisfier<'psbt> {
    fn lookup_tap_key_spend_sig(&self) -> Option<elements::SchnorrSig> {
        self.psbt.inputs()[self.index].tap_key_sig
    }

    fn lookup_tap_leaf_script_sig(
        &self,
        pk: &Pk,
        lh: &TapLeafHash,
    ) -> Option<elements::SchnorrSig> {
        self.psbt.inputs()[self.index]
            .tap_script_sigs
            .get(&(pk.to_x_only_pubkey(), *lh))
            .copied()
    }

    fn lookup_raw_pkh_pk(&self, pkh: &hash160::Hash) -> Option<bitcoin::PublicKey> {
        self.psbt.inputs()[self.index]
            .bip32_derivation
            .iter()
            .find(|&(pubkey, _)| pubkey.to_pubkeyhash(SigType::Ecdsa) == *pkh)
            .map(|(pubkey, _)| *pubkey)
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (elements::Script, LeafVersion)>> {
        Some(&self.psbt.inputs()[self.index].tap_scripts)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pkh: &(hash160::Hash, TapLeafHash),
    ) -> Option<(
        elements::secp256k1_zkp::XOnlyPublicKey,
        elements::SchnorrSig,
    )> {
        self.psbt.inputs()[self.index]
            .tap_script_sigs
            .iter()
            .find(|&((pubkey, lh), _sig)| {
                pubkey.to_pubkeyhash(SigType::Schnorr) == pkh.0 && *lh == pkh.1
            })
            .map(|((x_only_pk, _leaf_hash), sig)| (*x_only_pk, *sig))
    }

    fn lookup_ecdsa_sig(&self, pk: &Pk) -> Option<ElementsSig> {
        if let Some(rawsig) = self.psbt.inputs()[self.index]
            .partial_sigs
            .get(&pk.to_public_key())
        {
            // We have already previously checked that all signatures have the
            // correct sighash flag.
            elementssig_from_rawsig(rawsig).ok()
        } else {
            None
        }
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pkh: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        if let Some((pk, sig)) = self.psbt.inputs()[self.index]
            .partial_sigs
            .iter()
            .find(|&(pubkey, _sig)| pubkey.to_pubkeyhash(SigType::Ecdsa) == *pkh)
        {
            // If the mapping is incorrect, return None
            elementssig_from_rawsig(sig)
                .ok()
                .map(|bitcoinsig| (*pk, bitcoinsig))
        } else {
            None
        }
    }

    fn check_after(&self, n: LockTime) -> bool {
        let seq = self.psbt.inputs()[self.index]
            .sequence
            .unwrap_or(Sequence::MAX);
        if !seq.enables_absolute_lock_time() {
            return false;
        }

        let lock_time = self
            .psbt
            .global
            .tx_data
            .fallback_locktime
            .unwrap_or(LockTime::ZERO);

        <dyn Satisfier<Pk>>::check_after(&lock_time, n)
    }

    fn check_older(&self, n: Sequence) -> bool {
        let seq = self.psbt.inputs()[self.index]
            .sequence
            .unwrap_or(Sequence::MAX);

        // https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
        // Disable flag set => return true.
        if !n.is_relative_lock_time() {
            return true;
        }

        if self.psbt.global.tx_data.version < 2 || !seq.is_relative_lock_time() {
            return false;
        }

        <dyn Satisfier<Pk>>::check_older(&seq, n)
    }

    fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
        self.psbt.inputs()[self.index]
            .hash160_preimages
            .get(&Pk::to_hash160(h))
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
        self.psbt.inputs()[self.index]
            .sha256_preimages
            .get(&Pk::to_sha256(h))
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
        self.psbt.inputs()[self.index]
            .hash256_preimages
            .get(&sha256d::Hash::from_byte_array(
                Pk::to_hash256(h).to_byte_array(),
            )) // upstream psbt operates on hash256
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
        self.psbt.inputs()[self.index]
            .ripemd160_preimages
            .get(&Pk::to_ripemd160(h))
            .and_then(try_vec_as_preimage32)
    }
}

#[allow(clippy::ptr_arg)] // complains about &Vec but this is used in a closure context
fn try_vec_as_preimage32(vec: &Vec<u8>) -> Option<Preimage32> {
    if vec.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(vec);
        Some(arr)
    } else {
        None
    }
}

fn sanity_check(psbt: &Psbt) -> Result<(), Error> {
    if psbt.global.n_inputs() != psbt.inputs().len() {
        return Err(Error::WrongInputCount {
            in_tx: psbt.global.n_inputs(),
            in_map: psbt.inputs().len(),
        });
    }

    Ok(())
}

/// Additional operations for miniscript descriptors for various psbt roles.
/// Note that these APIs would generally error when used on scripts that are not
/// miniscripts.
pub trait PsbtExt {
    /// Finalize the psbt. This function takes in a mutable reference to psbt
    /// and populates the final_witness and final_scriptsig
    /// for all miniscript inputs.
    ///
    /// Finalizes all inputs that it can finalize, and returns an error for each input
    /// that it cannot finalize. Also performs a sanity interpreter check on the
    /// finalized psbt which involves checking the signatures/ preimages/timelocks.
    ///
    /// Input finalization also fails if it is not possible to satisfy any of the inputs non-malleably
    /// See `finalize_mall_*` if you want to allow malleable satisfactions
    ///
    /// For finalizing individual inputs, see also [`PsbtExt::finalize_inp`]
    ///
    /// # Errors:
    ///
    /// - A vector of errors, one of each of failed finalized input
    fn finalize_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Vec<Error>>;

    /// Same as [`PsbtExt::finalize_mut`], but does not mutate the input psbt and
    /// returns a new psbt
    ///
    /// # Errors:
    ///
    /// - Returns a mutated psbt with all inputs `finalize_mut` could finalize
    /// - A vector of input errors, one of each of failed finalized input
    fn finalize<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Vec<Error>)>;

    /// Same as [PsbtExt::finalize_mut], but allows for malleable satisfactions
    fn finalize_mall_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Vec<Error>>;

    /// Same as [PsbtExt::finalize], but allows for malleable satisfactions
    fn finalize_mall<C: secp256k1::Verification>(
        self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Vec<Error>)>;

    /// Same as [`PsbtExt::finalize_mut`], but only tries to finalize a single input leaving other
    /// inputs as is. Use this when not all of inputs that you are trying to
    /// satisfy are miniscripts
    ///
    /// # Errors:
    ///
    /// - Input error detailing why the finalization failed. The psbt is not mutated when the finalization fails
    fn finalize_inp_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Error>;

    /// Same as [`PsbtExt::finalize_inp_mut`], but does not mutate the psbt and returns a new one
    ///
    /// # Errors:
    ///  Returns a tuple containing
    /// - Original psbt
    /// - Input Error detailing why the input finalization failed
    fn finalize_inp<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Error)>;

    /// Same as [`PsbtExt::finalize_inp_mut`], but allows for malleable satisfactions
    fn finalize_inp_mall_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Error>;

    /// Same as [`PsbtExt::finalize_inp`], but allows for malleable satisfactions
    fn finalize_inp_mall<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Error)>;

    /// Psbt extractor as defined in BIP174 that takes in a psbt reference
    /// and outputs a extracted bitcoin::Transaction
    /// Also does the interpreter sanity check
    /// Will error if the final ScriptSig or final Witness are missing
    /// or the interpreter check fails.
    fn extract<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<elements::Transaction, Error>;

    /// Update PSBT input with a descriptor and check consistency of `*_utxo` fields.
    ///
    /// This is the checked version of [`update_with_descriptor_unchecked`]. It checks that the
    /// `witness_utxo` and `non_witness_utxo` are sane and have a `script_pubkey` that matches the
    /// descriptor. In particular, it makes sure pre-segwit descriptors always have `non_witness_utxo`
    /// present (and the txid matches). If both `witness_utxo` and `non_witness_utxo` are present
    /// then it also checks they are consistent with each other.
    ///
    /// Hint: because of the *[segwit bug]* some PSBT signers require that `non_witness_utxo` is
    /// present on segwitv0 inputs regardless but this function doesn't enforce this so you will
    /// have to do this check its presence manually (if it is present this *will* check its
    /// validity).
    ///
    /// The `descriptor` **must not have any wildcards** in it
    /// otherwise an error will be returned however it can (and should) have extended keys in it.
    ///
    /// [`update_with_descriptor_unchecked`]: PsbtInputExt::update_with_descriptor_unchecked
    /// [segwit bug]: https://bitcoinhackers.org/@lukedashjr/104287698361196952
    fn update_input_with_descriptor(
        &mut self,
        input_index: usize,
        descriptor: &Descriptor<DefiniteDescriptorKey, CovenantExt<CovExtArgs>>,
    ) -> Result<(), UtxoUpdateError>;

    /// Update PSBT output with a descriptor and check consistency of the output's `script_pubkey`
    ///
    /// This is the checked version of [`update_with_descriptor_unchecked`]. It checks that the
    /// output's `script_pubkey` matches the descriptor.
    ///
    /// The `descriptor` **must not have any wildcards** in it
    /// otherwise an error will be returned however it can (and should) have extended keys in it.
    ///
    /// [`update_with_descriptor_unchecked`]: PsbtOutputExt::update_with_descriptor_unchecked
    fn update_output_with_descriptor(
        &mut self,
        output_index: usize,
        descriptor: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<(), OutputUpdateError>;

    /// Get the sighash message(data to sign) at input index `idx` based on the sighash
    /// flag specified in the [`Psbt`] sighash field. If the input sighash flag psbt field is `None`
    /// the [`SchnorrSighashType::Default`](elements::sighash::SchnorrSighashType::Default) is chosen
    /// for for taproot spends, otherwise [`EcdsaSignatureHashType::All`](elements::EcdsaSighashType::All) is chosen.
    /// If the utxo at `idx` is a taproot output, returns a [`PsbtSighashMsg::TapSighash`] variant.
    /// If the utxo at `idx` is a pre-taproot output, returns a [`PsbtSighashMsg::EcdsaSighash`] variant.
    /// The `tapleaf_hash` parameter can be used to specify which tapleaf script hash has to be computed. If
    /// `tapleaf_hash` is [`None`], and the output is taproot output, the key spend hash is computed. This parameter must be
    /// set to [`None`] while computing sighash for pre-taproot outputs.
    /// The function also updates the sighash cache with transaction computed during sighash computation of this input
    ///
    /// # Arguments:
    ///
    /// * `idx`: The input index of psbt to sign
    /// * `cache`: The [`SighashCache`] for used to cache/read previously cached computations
    /// * `tapleaf_hash`: If the output is taproot, compute the sighash for this particular leaf.
    ///
    /// [`SighashCache`]: bitcoin::sighash::SighashCache
    fn sighash_msg<T: Deref<Target = elements::Transaction>>(
        &self,
        idx: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>,
        genesis_hash: elements::BlockHash,
    ) -> Result<PsbtSighashMsg, SighashError>;
}

impl PsbtExt for Psbt {
    fn finalize_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Vec<Error>> {
        // Actually construct the witnesses
        let mut errors = vec![];
        for index in 0..self.inputs().len() {
            match finalizer::finalize_input(
                self,
                secp,
                index,
                /*allow_mall*/ false,
                genesis_hash,
            ) {
                Ok(..) => {}
                Err(e) => {
                    errors.push(e);
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn finalize<C: secp256k1::Verification>(
        mut self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Vec<Error>)> {
        match self.finalize_mut(secp, genesis_hash) {
            Ok(..) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }

    fn finalize_mall_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Vec<Error>> {
        let mut errors = vec![];
        for index in 0..self.inputs().len() {
            match finalizer::finalize_input(
                self,
                secp,
                index,
                /*allow_mall*/ true,
                genesis_hash,
            ) {
                Ok(..) => {}
                Err(e) => {
                    errors.push(e);
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn finalize_mall<C: secp256k1::Verification>(
        mut self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Vec<Error>)> {
        match self.finalize_mall_mut(secp, genesis_hash) {
            Ok(..) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }

    fn finalize_inp_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Error> {
        if index >= self.inputs().len() {
            return Err(Error::InputIdxOutofBounds {
                psbt_inp: self.inputs().len(),
                index,
            });
        }
        finalizer::finalize_input(self, secp, index, /*allow_mall*/ false, genesis_hash)
    }

    fn finalize_inp<C: secp256k1::Verification>(
        mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Error)> {
        match self.finalize_inp_mut(secp, index, genesis_hash) {
            Ok(..) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }

    fn finalize_inp_mall_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Error> {
        if index >= self.inputs().len() {
            return Err(Error::InputIdxOutofBounds {
                psbt_inp: self.inputs().len(),
                index,
            });
        }
        finalizer::finalize_input(self, secp, index, /*allow_mall*/ true, genesis_hash)
    }

    fn finalize_inp_mall<C: secp256k1::Verification>(
        mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Error)> {
        match self.finalize_inp_mall_mut(secp, index, genesis_hash) {
            Ok(..) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }

    fn extract<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<elements::Transaction, Error> {
        sanity_check(self)?;

        let ret = self.extract_tx()?;
        interpreter_check(self, secp, genesis_hash)?;
        Ok(ret)
    }

    fn update_input_with_descriptor(
        &mut self,
        input_index: usize,
        desc: &Descriptor<DefiniteDescriptorKey, CovenantExt<CovExtArgs>>,
    ) -> Result<(), UtxoUpdateError> {
        let n_inputs = self.inputs().len();
        let input = self
            .inputs()
            .get(input_index)
            .ok_or(UtxoUpdateError::IndexOutOfBounds(input_index, n_inputs))?;
        let txin = self
            .inputs()
            .get(input_index)
            .ok_or(UtxoUpdateError::MissingInputUtxo)?;

        let desc_type = desc.desc_type();

        if let Some(non_witness_utxo) = &input.non_witness_utxo {
            if txin.previous_txid != non_witness_utxo.txid() {
                return Err(UtxoUpdateError::UtxoCheck);
            }
        }

        let expected_spk = {
            match (&input.witness_utxo, &input.non_witness_utxo) {
                (Some(witness_utxo), None) => {
                    if desc_type.segwit_version().is_some() {
                        witness_utxo.script_pubkey.clone()
                    } else {
                        return Err(UtxoUpdateError::UtxoCheck);
                    }
                }
                (None, Some(non_witness_utxo)) => non_witness_utxo
                    .output
                    .get(txin.previous_output_index as usize)
                    .ok_or(UtxoUpdateError::UtxoCheck)?
                    .script_pubkey
                    .clone(),
                (Some(witness_utxo), Some(non_witness_utxo)) => {
                    if witness_utxo
                        != non_witness_utxo
                            .output
                            .get(txin.previous_output_index as usize)
                            .ok_or(UtxoUpdateError::UtxoCheck)?
                    {
                        return Err(UtxoUpdateError::UtxoCheck);
                    }

                    witness_utxo.script_pubkey.clone()
                }
                (None, None) => return Err(UtxoUpdateError::UtxoCheck),
            }
        };

        let input = self
            .inputs_mut()
            .get_mut(input_index)
            .ok_or(UtxoUpdateError::IndexOutOfBounds(input_index, n_inputs))?;
        let (_, spk_check_passed) =
            update_item_with_descriptor_helper(input, desc, Some(&expected_spk))
                .map_err(UtxoUpdateError::DerivationError)?;

        if !spk_check_passed {
            return Err(UtxoUpdateError::MismatchedScriptPubkey);
        }

        Ok(())
    }

    fn update_output_with_descriptor(
        &mut self,
        output_index: usize,
        desc: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<(), OutputUpdateError> {
        let n_outputs = self.outputs().len();
        let output = self
            .outputs_mut()
            .get_mut(output_index)
            .ok_or(OutputUpdateError::IndexOutOfBounds(output_index, n_outputs))?;
        // Possible to avoid clone, but requires partial borrow by separating out the script_pubkey field
        let txout_spk = output.script_pubkey.clone();

        let (_, spk_check_passed) =
            update_item_with_descriptor_helper(output, desc, Some(&txout_spk))
                .map_err(OutputUpdateError::DerivationError)?;

        if !spk_check_passed {
            return Err(OutputUpdateError::MismatchedScriptPubkey);
        }

        Ok(())
    }

    fn sighash_msg<T: Deref<Target = elements::Transaction>>(
        &self,
        idx: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>,
        genesis_hash: elements::BlockHash,
    ) -> Result<PsbtSighashMsg, SighashError> {
        // Infer a descriptor at idx
        if idx >= self.inputs().len() {
            return Err(SighashError::IndexOutOfBounds(idx, self.inputs().len()));
        }
        let inp = &self.inputs()[idx];
        let prevouts = finalizer::prevouts(self).map_err(|_e| SighashError::MissingSpendUtxos)?;
        // Note that as per Psbt spec we should have access to spent_utxos for the transaction
        // Even if the transaction does not require SighashAll, we create `Prevouts::All` for code simplicity
        let prevouts = elements::sighash::Prevouts::All(&prevouts);
        let inp_spk =
            finalizer::get_scriptpubkey(self, idx).map_err(|_e| SighashError::MissingInputUtxo)?;
        if util::is_v1_p2tr(inp_spk) {
            let hash_ty = inp
                .sighash_type
                .map(|h| h.schnorr_hash_ty())
                .unwrap_or(Some(SchnorrSighashType::Default))
                .ok_or(SighashError::InvalidSighashType)?;
            match tapleaf_hash {
                Some(leaf_hash) => {
                    let tap_sighash_msg = cache.taproot_script_spend_signature_hash(
                        idx,
                        &prevouts,
                        leaf_hash,
                        hash_ty,
                        genesis_hash,
                    )?;
                    Ok(PsbtSighashMsg::TapSighash(tap_sighash_msg))
                }
                None => {
                    let tap_sighash_msg = cache.taproot_key_spend_signature_hash(
                        idx,
                        &prevouts,
                        hash_ty,
                        genesis_hash,
                    )?;
                    Ok(PsbtSighashMsg::TapSighash(tap_sighash_msg))
                }
            }
        } else {
            let hash_ty = inp
                .sighash_type
                .map(|h| h.ecdsa_hash_ty())
                .unwrap_or(Some(EcdsaSighashType::All))
                .ok_or(SighashError::InvalidSighashType)?;
            let amt = finalizer::get_utxo(self, idx)
                .map_err(|_e| SighashError::MissingInputUtxo)?
                .value;
            let is_nested_wpkh = inp_spk.is_p2sh()
                && inp
                    .redeem_script
                    .as_ref()
                    .map(|x| x.is_v0_p2wpkh())
                    .unwrap_or(false);
            let is_nested_wsh = inp_spk.is_p2sh()
                && inp
                    .redeem_script
                    .as_ref()
                    .map(|x| x.is_v0_p2wsh())
                    .unwrap_or(false);
            if inp_spk.is_v0_p2wpkh() || inp_spk.is_v0_p2wsh() || is_nested_wpkh || is_nested_wsh {
                let msg = if inp_spk.is_v0_p2wpkh() {
                    let script_code = script_code_wpkh(inp_spk);
                    cache.segwitv0_sighash(idx, &script_code, amt, hash_ty)
                } else if is_nested_wpkh {
                    let script_code = script_code_wpkh(
                        inp.redeem_script
                            .as_ref()
                            .expect("Redeem script non-empty checked earlier"),
                    );
                    cache.segwitv0_sighash(idx, &script_code, amt, hash_ty)
                } else {
                    // wsh and nested wsh, script code is witness script
                    let script_code = inp
                        .witness_script
                        .as_ref()
                        .ok_or(SighashError::MissingWitnessScript)?;
                    cache.segwitv0_sighash(idx, script_code, amt, hash_ty)
                };
                Ok(PsbtSighashMsg::EcdsaSighash(msg))
            } else {
                // legacy sighash case
                let script_code = if inp_spk.is_p2sh() {
                    inp.redeem_script
                        .as_ref()
                        .ok_or(SighashError::MissingRedeemScript)?
                } else {
                    inp_spk
                };
                let msg = cache.legacy_sighash(idx, script_code, hash_ty);
                Ok(PsbtSighashMsg::EcdsaSighash(msg))
            }
        }
    }
}

/// Extension trait for PSBT inputs
pub trait PsbtInputExt {
    /// Given the descriptor for a utxo being spent populate the PSBT input's fields so it can be signed.
    ///
    /// If the descriptor contains wildcards or otherwise cannot be transformed into a concrete
    /// descriptor an error will be returned. The descriptor *can* (and should) have extended keys in
    /// it so PSBT fields like `bip32_derivation` and `tap_key_origins` can be populated.
    ///
    /// Note that his method doesn't check that the `witness_utxo` or `non_witness_utxo` is
    /// consistent with the descriptor. To do that see [`update_input_with_descriptor`].
    ///
    /// ## Return value
    ///
    /// For convenience, this returns the concrete descriptor that is computed internally to fill
    /// out the PSBT input fields. This can be used to manually check that the `script_pubkey` in
    /// `witness_utxo` and/or `non_witness_utxo` is consistent with the descriptor.
    ///
    /// [`update_input_with_descriptor`]: PsbtExt::update_input_with_descriptor
    fn update_with_descriptor_unchecked(
        &mut self,
        descriptor: &Descriptor<DefiniteDescriptorKey, CovenantExt<CovExtArgs>>,
    ) -> Result<Descriptor<bitcoin::PublicKey, CovenantExt<CovExtArgs>>, descriptor::ConversionError>;
}

impl PsbtInputExt for psbt::Input {
    fn update_with_descriptor_unchecked(
        &mut self,
        descriptor: &Descriptor<DefiniteDescriptorKey, CovenantExt<CovExtArgs>>,
    ) -> Result<Descriptor<bitcoin::PublicKey, CovenantExt<CovExtArgs>>, descriptor::ConversionError>
    {
        let (derived, _) = update_item_with_descriptor_helper(self, descriptor, None)?;
        Ok(derived)
    }
}

/// Extension trait for PSBT outputs
pub trait PsbtOutputExt {
    /// Given the descriptor of a PSBT output populate the relevant metadata
    ///
    /// If the descriptor contains wildcards or otherwise cannot be transformed into a concrete
    /// descriptor an error will be returned. The descriptor *can* (and should) have extended keys in
    /// it so PSBT fields like `bip32_derivation` and `tap_key_origins` can be populated.
    ///
    /// Note that this method doesn't check that the `script_pubkey` of the output being
    /// updated matches the descriptor. To do that see [`update_output_with_descriptor`].
    ///
    /// ## Return value
    ///
    /// For convenience, this returns the concrete descriptor that is computed internally to fill
    /// out the PSBT output fields. This can be used to manually check that the `script_pubkey` is
    /// consistent with the descriptor.
    ///
    /// [`update_output_with_descriptor`]: PsbtExt::update_output_with_descriptor
    fn update_with_descriptor_unchecked(
        &mut self,
        descriptor: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<Descriptor<bitcoin::PublicKey>, descriptor::ConversionError>;
}

impl PsbtOutputExt for psbt::Output {
    fn update_with_descriptor_unchecked(
        &mut self,
        descriptor: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<Descriptor<bitcoin::PublicKey>, descriptor::ConversionError> {
        let (derived, _) = update_item_with_descriptor_helper(self, descriptor, None)?;
        Ok(derived)
    }
}

// Traverse the pkh lookup while maintaining a reverse map for storing the map
// hash160 -> (XonlyPublicKey)/PublicKey
struct KeySourceLookUp(
    pub BTreeMap<bitcoin::PublicKey, bip32::KeySource>,
    pub secp256k1::Secp256k1<VerifyOnly>,
);

impl Translator<DefiniteDescriptorKey, bitcoin::PublicKey, descriptor::ConversionError>
    for KeySourceLookUp
{
    fn pk(
        &mut self,
        xpk: &DefiniteDescriptorKey,
    ) -> Result<bitcoin::PublicKey, descriptor::ConversionError> {
        let derived = xpk.derive_public_key(&self.1)?;
        self.0.insert(
            derived.to_public_key(),
            (
                xpk.master_fingerprint(),
                xpk.full_derivation_path()
                    .ok_or(descriptor::ConversionError::MultiKey)?,
            ),
        );
        Ok(derived)
    }

    translate_hash_clone!(
        DescriptorPublicKey,
        bitcoin::PublicKey,
        descriptor::ConversionError
    );
}

// Provides generalized access to PSBT fields common to inputs and outputs
trait PsbtFields {
    // Common fields are returned as a mutable ref of the same type
    fn redeem_script(&mut self) -> &mut Option<Script>;
    fn witness_script(&mut self) -> &mut Option<Script>;
    fn bip32_derivation(&mut self) -> &mut BTreeMap<bitcoin::PublicKey, bip32::KeySource>;
    fn tap_internal_key(&mut self) -> &mut Option<bitcoin::key::XOnlyPublicKey>;
    fn tap_key_origins(
        &mut self,
    ) -> &mut BTreeMap<bitcoin::key::XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)>;
    #[allow(dead_code)]
    fn proprietary(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>;
    #[allow(dead_code)]
    fn unknown(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>>;

    // `tap_tree` only appears in psbt::Output, so it's returned as an option of a mutable ref
    fn tap_tree(&mut self) -> Option<&mut Option<psbt::TapTree>> {
        None
    }

    // `tap_scripts` and `tap_merkle_root` only appear in psbt::Input
    fn tap_scripts(&mut self) -> Option<&mut BTreeMap<ControlBlock, (Script, LeafVersion)>> {
        None
    }
    fn tap_merkle_root(&mut self) -> Option<&mut Option<taproot::TapNodeHash>> {
        None
    }
}

impl PsbtFields for psbt::Input {
    fn redeem_script(&mut self) -> &mut Option<Script> {
        &mut self.redeem_script
    }
    fn witness_script(&mut self) -> &mut Option<Script> {
        &mut self.witness_script
    }
    fn bip32_derivation(&mut self) -> &mut BTreeMap<bitcoin::PublicKey, bip32::KeySource> {
        &mut self.bip32_derivation
    }
    fn tap_internal_key(&mut self) -> &mut Option<bitcoin::key::XOnlyPublicKey> {
        &mut self.tap_internal_key
    }
    fn tap_key_origins(
        &mut self,
    ) -> &mut BTreeMap<bitcoin::key::XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)> {
        &mut self.tap_key_origins
    }
    fn proprietary(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
        &mut self.proprietary
    }
    fn unknown(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>> {
        &mut self.unknown
    }

    fn tap_scripts(&mut self) -> Option<&mut BTreeMap<ControlBlock, (Script, LeafVersion)>> {
        Some(&mut self.tap_scripts)
    }
    fn tap_merkle_root(&mut self) -> Option<&mut Option<taproot::TapNodeHash>> {
        Some(&mut self.tap_merkle_root)
    }
}

impl PsbtFields for psbt::Output {
    fn redeem_script(&mut self) -> &mut Option<Script> {
        &mut self.redeem_script
    }
    fn witness_script(&mut self) -> &mut Option<Script> {
        &mut self.witness_script
    }
    fn bip32_derivation(&mut self) -> &mut BTreeMap<bitcoin::PublicKey, bip32::KeySource> {
        &mut self.bip32_derivation
    }
    fn tap_internal_key(&mut self) -> &mut Option<bitcoin::key::XOnlyPublicKey> {
        &mut self.tap_internal_key
    }
    fn tap_key_origins(
        &mut self,
    ) -> &mut BTreeMap<bitcoin::key::XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)> {
        &mut self.tap_key_origins
    }
    fn proprietary(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
        &mut self.proprietary
    }
    fn unknown(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>> {
        &mut self.unknown
    }

    fn tap_tree(&mut self) -> Option<&mut Option<psbt::TapTree>> {
        Some(&mut self.tap_tree)
    }
}

fn update_item_with_descriptor_helper<F: PsbtFields>(
    item: &mut F,
    descriptor: &Descriptor<DefiniteDescriptorKey, CovenantExt<CovExtArgs>>,
    check_script: Option<&Script>,
    // the return value is a tuple here since the two internal calls to it require different info.
    // One needs the derived descriptor and the other needs to know whether the script_pubkey check
    // failed.
) -> Result<
    (
        Descriptor<bitcoin::PublicKey, CovenantExt<CovExtArgs>>,
        bool,
    ),
    descriptor::ConversionError,
> {
    let secp = secp256k1::Secp256k1::verification_only();

    let derived = if let Descriptor::Tr(_) = &descriptor {
        let derived = descriptor.derived_descriptor(&secp)?;

        if let Some(check_script) = check_script {
            if check_script != &derived.script_pubkey() {
                println!("{:x}", &check_script);
                println!("{:x}", &derived.script_pubkey());
                return Ok((derived, false));
            }
        }

        // NOTE: they will both always be Tr
        if let (Descriptor::Tr(tr_derived), Descriptor::Tr(tr_xpk)) = (&derived, descriptor) {
            update_tr_psbt_helper(item, tr_derived, tr_xpk)?;
        }

        derived
    } else if let Descriptor::TrExt(_) = &descriptor {
        // Repeat the same code for Tr with extensions. Annoying to dedup this code without macros
        let derived = descriptor.derived_descriptor(&secp)?;

        if let Some(check_script) = check_script {
            if check_script != &derived.script_pubkey() {
                return Ok((derived, false));
            }
        }

        // NOTE: they will both always be Tr
        if let (Descriptor::TrExt(tr_derived), Descriptor::TrExt(tr_xpk)) = (&derived, descriptor) {
            update_tr_psbt_helper(item, tr_derived, tr_xpk)?;
        }

        derived
    } else {
        let mut bip32_derivation = KeySourceLookUp(BTreeMap::new(), Secp256k1::verification_only());
        let derived = descriptor.translate_pk(&mut bip32_derivation)?;

        if let Some(check_script) = check_script {
            if check_script != &derived.script_pubkey() {
                return Ok((derived, false));
            }
        }

        item.bip32_derivation().append(&mut bip32_derivation.0);

        match &derived {
            Descriptor::Bare(_) | Descriptor::Pkh(_) | Descriptor::Wpkh(_) => {}
            Descriptor::Sh(sh) => match sh.as_inner() {
                descriptor::ShInner::Wsh(wsh) => {
                    *item.witness_script() = Some(wsh.inner_script());
                    *item.redeem_script() = Some(wsh.inner_script().to_v0_p2wsh());
                }
                descriptor::ShInner::Wpkh(..) => *item.redeem_script() = Some(sh.inner_script()),
                descriptor::ShInner::SortedMulti(_) | descriptor::ShInner::Ms(_) => {
                    *item.redeem_script() = Some(sh.inner_script())
                }
            },
            Descriptor::Wsh(wsh) => *item.witness_script() = Some(wsh.inner_script()),
            Descriptor::Tr(_) => unreachable!("Tr is dealt with separately"),
            Descriptor::TrExt(_) => unreachable!("TrExt is dealt with separately"),
            Descriptor::LegacyCSFSCov(_) => {
                // Information for covenants is available directly in the transaction itself
            }
        }

        derived
    };

    Ok((derived, true))
}

fn update_tr_psbt_helper<Ext, Ext2, F: PsbtFields>(
    item: &mut F,
    tr_derived: &Tr<bitcoin::PublicKey, Ext>,
    tr_xpk: &Tr<DefiniteDescriptorKey, Ext2>,
) -> Result<(), descriptor::ConversionError>
where
    Ext: ParseableExt,
    Ext2: Extension,
{
    let spend_info = tr_derived.spend_info();
    let ik_derived = spend_info.internal_key();
    let ik_xpk = tr_xpk.internal_key();
    *item.tap_internal_key() = Some(ik_derived);
    if let Some(merkle_root) = item.tap_merkle_root() {
        *merkle_root = spend_info.merkle_root();
    }
    item.tap_key_origins().insert(
        ik_derived,
        (
            vec![],
            (
                ik_xpk.master_fingerprint(),
                ik_xpk
                    .full_derivation_path()
                    .ok_or(descriptor::ConversionError::MultiKey)?,
            ),
        ),
    );

    let mut builder = taproot::TaprootBuilder::new();

    for ((_depth_der, script_derived), (depth, script)) in
        tr_derived.iter_scripts().zip(tr_xpk.iter_scripts())
    {
        debug_assert_eq!(_depth_der, depth);
        let leaf_script = (script_derived.encode(), script.version());
        let tapleaf_hash = TapLeafHash::from_script(&leaf_script.0, leaf_script.1);
        builder = builder
            .add_leaf(depth, leaf_script.0.clone())
            .expect("Computing spend data on a valid tree should always succeed");
        if let Some(tap_scripts) = item.tap_scripts() {
            let control_block = spend_info
                .control_block(&leaf_script)
                .expect("Control block must exist in script map for every known leaf");
            tap_scripts.insert(control_block, leaf_script);
        }

        for (derived_pk, xpk) in script_derived.iter_pk().zip(script.iter_pk()) {
            let (xonly, xpk) = (derived_pk.to_x_only_pubkey(), xpk);

            item.tap_key_origins()
                .entry(xonly)
                .and_modify(|(tapleaf_hashes, _)| {
                    if tapleaf_hashes.last() != Some(&tapleaf_hash) {
                        tapleaf_hashes.push(tapleaf_hash);
                    }
                })
                .or_insert({
                    (
                        vec![tapleaf_hash],
                        (
                            xpk.master_fingerprint(),
                            xpk.full_derivation_path()
                                .ok_or(descriptor::ConversionError::MultiKey)?,
                        ),
                    )
                });
        }
    }
    // Ensure there are no duplicated leaf hashes. This can happen if some of them were
    // already present in the map when this function is called, since this only appends new
    // data to the psbt without checking what's already present.
    for (tapleaf_hashes, _) in item.tap_key_origins().values_mut() {
        tapleaf_hashes.sort();
        tapleaf_hashes.dedup();
    }

    match item.tap_tree() {
        // Only set the tap_tree if the item supports it (it's an output) and the descriptor actually
        // contains one, otherwise it'll just be empty
        Some(tap_tree) if tr_derived.taptree().is_some() => {
            *tap_tree =
                Some(psbt::TapTree::from_inner(builder).expect("The tree should always be valid"));
        }
        _ => {}
    }
    Ok(())
}

// Get a script from witness script pubkey hash
fn script_code_wpkh(script: &Script) -> Script {
    assert!(script.is_v0_p2wpkh());
    // ugly segwit stuff
    let mut script_code = vec![0x76u8, 0xa9, 0x14];
    script_code.extend(&script.as_bytes()[2..]);
    script_code.push(0x88);
    script_code.push(0xac);
    Script::from(script_code)
}

/// Return error type for [`PsbtExt::update_input_with_descriptor`]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum UtxoUpdateError {
    /// Index out of bounds
    IndexOutOfBounds(usize, usize),
    /// The unsigned transaction didn't have an input at that index
    MissingInputUtxo,
    /// Derivation error
    DerivationError(descriptor::ConversionError),
    /// The PSBT's `witness_utxo` and/or `non_witness_utxo` were invalid or missing
    UtxoCheck,
    /// The PSBT's `witness_utxo` and/or `non_witness_utxo` had a script_pubkey that did not match
    /// the descriptor
    MismatchedScriptPubkey,
}

impl fmt::Display for UtxoUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UtxoUpdateError::IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt input len: {}", ind, len)
            }
            UtxoUpdateError::MissingInputUtxo => {
                write!(f, "Missing input in unsigned transaction")
            }
            UtxoUpdateError::DerivationError(e) => write!(f, "Key derivation error {}", e),
            UtxoUpdateError::UtxoCheck => write!(
                f,
                "The input's witness_utxo and/or non_witness_utxo were invalid or missing"
            ),
            UtxoUpdateError::MismatchedScriptPubkey => {
                write!(f, "The input's witness_utxo and/or non_witness_utxo had a script pubkey that didn't match the descriptor")
            }
        }
    }
}

impl error::Error for UtxoUpdateError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::UtxoUpdateError::*;

        match self {
            IndexOutOfBounds(_, _) | MissingInputUtxo | UtxoCheck | MismatchedScriptPubkey => None,
            DerivationError(e) => Some(e),
        }
    }
}

/// Return error type for [`PsbtExt::update_output_with_descriptor`]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum OutputUpdateError {
    /// Index out of bounds
    IndexOutOfBounds(usize, usize),
    /// The raw unsigned transaction didn't have an output at that index
    MissingTxOut,
    /// Derivation error
    DerivationError(descriptor::ConversionError),
    /// The output's script_pubkey did not match the descriptor
    MismatchedScriptPubkey,
}

impl fmt::Display for OutputUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputUpdateError::IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt output len: {}", ind, len)
            }
            OutputUpdateError::MissingTxOut => {
                write!(f, "Missing txout in the unsigned transaction")
            }
            OutputUpdateError::DerivationError(e) => write!(f, "Key derivation error {}", e),
            OutputUpdateError::MismatchedScriptPubkey => {
                write!(f, "The output's script pubkey didn't match the descriptor")
            }
        }
    }
}

impl error::Error for OutputUpdateError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::OutputUpdateError::*;

        match self {
            IndexOutOfBounds(_, _) | MissingTxOut | MismatchedScriptPubkey => None,
            DerivationError(e) => Some(e),
        }
    }
}

/// Return error type for [`PsbtExt::sighash_msg`]
// We need to implement auto-derives upstream
#[derive(Debug)]
pub enum SighashError {
    /// Index out of bounds
    IndexOutOfBounds(usize, usize),
    /// Missing input utxo
    MissingInputUtxo,
    /// Missing Prevouts
    MissingSpendUtxos,
    /// Invalid Sighash type
    InvalidSighashType,
    /// Sighash computation error
    /// Only happens when single does not have corresponding output as psbts
    /// already have information to compute the sighash
    SighashComputationError(elements::sighash::Error),
    /// Missing Witness script
    MissingWitnessScript,
    /// Missing Redeem script,
    MissingRedeemScript,
}

impl fmt::Display for SighashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SighashError::IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt input len: {}", ind, len)
            }
            SighashError::MissingInputUtxo => write!(f, "Missing input utxo in pbst"),
            SighashError::MissingSpendUtxos => write!(f, "Missing Psbt spend utxos"),
            SighashError::InvalidSighashType => write!(f, "Invalid Sighash type"),
            SighashError::SighashComputationError(e) => {
                write!(f, "Sighash computation error : {}", e)
            }
            SighashError::MissingWitnessScript => write!(f, "Missing Witness Script"),
            SighashError::MissingRedeemScript => write!(f, "Missing Redeem Script"),
        }
    }
}

impl From<elements::sighash::Error> for SighashError {
    fn from(e: elements::sighash::Error) -> Self {
        SighashError::SighashComputationError(e)
    }
}

impl error::Error for SighashError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::SighashError::*;

        match self {
            IndexOutOfBounds(_, _)
            | MissingInputUtxo
            | MissingSpendUtxos
            | InvalidSighashType
            | MissingWitnessScript
            | MissingRedeemScript => None,
            SighashComputationError(e) => Some(e),
        }
    }
}

/// Sighash message(signing data) for a given psbt transaction input.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum PsbtSighashMsg {
    /// Taproot Signature hash
    TapSighash(taproot::TapSighashHash),
    /// Ecdsa Sighash message (includes sighash for legacy/p2sh/segwitv0 outputs)
    EcdsaSighash(elements::Sighash),
}

impl PsbtSighashMsg {
    /// Convert the message to a [`secp256k1::Message`].
    pub fn to_secp_msg(&self) -> secp256k1::Message {
        match *self {
            PsbtSighashMsg::TapSighash(msg) => {
                secp256k1::Message::from_digest_slice(msg.as_ref()).expect("Sighashes are 32 bytes")
            }
            PsbtSighashMsg::EcdsaSighash(msg) => {
                secp256k1::Message::from_digest_slice(msg.as_ref()).expect("Sighashes are 32 bytes")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::bip32::{DerivationPath, Xpub};
    use elements::encode::deserialize;
    use elements::hex::FromHex;
    use elements::secp256k1_zkp::XOnlyPublicKey;
    use elements::{
        confidential, AssetId, AssetIssuance, LockTime, OutPoint, TxIn, TxInWitness, TxOut,
    };

    use super::*;
    use crate::psbt::finalizer::finalize;
    use crate::Miniscript;

    #[test]
    fn test_extract_psbt() {
        let psbt: Psbt = deserialize(&Vec::<u8>::from_hex("70736574ff01020402000000010401020105010401fb04020000000001017a0bab8c49f1fce77440be124c72ce22bb23b58c6f52baf4cdde1f656056cd6b96440980610bc88e4ab656c2e5ff6fe6c6a39967a1c0d386682240c5ff039148dc335d03b636cc4beba2967c418a9443e161cd0ac77bec5e44c4bf98e72fc28857abca331600142d2186719dc0c245e7b4a30f17834f371ca7377c01086b02473044022040d1802d6e10da4c27f05eff807550e614b3d2fa20c663dbf1ebf162d3952689022001f477c953b7c543bce877e3297fccb00ef5dba21d427e79c8bfb8522713309801210334c307ad8142e7c8a6bf1ad3552b12fbb860885ea7f2d76c1f49f93a7c4bbbe7010e20cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae010f04000000000001017a0b90df52169792d13db9b7d074d091aaa3e83aff261b1cc19d291441b62e7a03190899a91403ca5cd8bded09945bc99c2f980fd27601cada66833a5f4bc108baf63902e8bed2778bf381d17241be029f228664c7d1522ced55379e275b83fe805b370216001403bb7619d51d2af2c5538d3908ead081a7ef2b2b01086b02473044022017c696503f5e1539fe5cb8dd05f793bd3b6e39f193028a7299a80c94c817a02d022007889009088f46cd9d9f4d137815704170410f53d503b68c1e020292a85b93fa012103df8f51c053ba0dfb443cce9793b6dc3339ffb0ce97af4792dade3aae1eb890f6010e20cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae010f04010000000007fc0470736574012108a337e7e0ecf24c121a17193623254c277a306e9fd39cd5aaf8b7d374f4011c6507fc047073657403210b8e11e3b8904ac80caeb16af1c93053f8a11a963269bcefa96823d75b8640ae940104220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d9307fc047073657404fd4e1060330000000000000001efdfbc0022a6437ec10c672d76c513868f403f6b9706e09733d6624e3cda831c2c199dd4c5763054a1c219e079e8cf3ce0c00dc2f16516972e1e64d576adfd9f5d778675c8a3172450a4cc82d6e6c59f2b16dffddc902d0aaa647b750d6224cafca7239a4fa81219cf2ee89741ffc5b7dd7e47d332ca931cffb1d1d432935a6013207629118c965b7a5102e62c43ca9d06bca191307a476738548536809ff6b01c6b5b25d76ff2f67d99e20fdf7d2eff6fc248186d21d054196023c5e4f572ccf0f3aad8728c46f2ff6756ea39de46028610a3d26cd42978b09e0e29e0a8aa46e4fd39d28d028592560264cf1a794c27f6c95d382f486dfe900a81d9d92935c7e0e6306549b3e49b1f60182512ccb994338c3541a2956139b2ccb3dd156853105abf5fb394cb2c45915dfd4106c7472dc5d360ab5bca408203a3fef58b4dd33b0c11c367dde2f19c8af7682be067244bf49a2b8cd4685f5481cc31ba27fe2f3d7b7a353be9b41e4eee2342fd70b8408c91951c71c75dde8fbc03e3f28e6d3d3b41e0e963d3ba0c25b2eb50560c21221950b0699d2615f0128e6cb7fa1b04ac1a046e569a7e87df98c14360b8ffc43db5e17548c7ea5056f84ffd14f4cdfc68a4f10e9b391cfa63eef2c2d623e7cdcdfae2fc4d63496d81462174ff360809b7e3b4305979d9cb8e9ad5b0f012494d31ce51ee6489555b09dddb16641ed9e2534fc34db99d2a4fa736eeabacf2f8cdca97f9e84c964277c6f30f1af7fe2b51b39b487d56ebaf593a3f98e811cb09849c5b445d5b7c9ba37807bd0189c8bdb2709fa70c230f9aba41dd3c62384aea6e1ca098ffec26367aa65a09459fca074d1da0365cf7fc2d8310ae099b838ca78e62cee10f95ec549faac1ff0f8236fb8cf2c0f6654e471d3950ef45e0159c44f9e343d05b3af59b939cf76090d040376407c41661eeda7d2cb61cad0088a286948787dae0cc5abdcb97f7f42026c65a13e1df1357c25d376955942adc858e73876e1d8812969055d55decac9a689dcd11dffe5cf6e06088b93a11e153ffed104266bba472cebffb2b0cfc8ef132309bd7836071d3b6ed459a5950c64cccf230015c98f9210f2d57b7f3a07c382f3df09f055c88e1f312db0d60d471afdc0b780d319a6229babd8f45edecff8d1073fa850f755219a3ea14e7234cbc7590c60eba0ba0cc1afde6ce91c8e8835b1ca809926b3e7d8d7a0941425e5f08e884f12693eeea1b3651f53da90972aaa37d426f37db3edae4285db114cbad5964c269e03b15358ad2a7242e0af538a594fc779ec3c43c3d94fab2028310c6d0acf3efdf0acf028ee757c5c02bb5b8b691aa5eed1a62acbabd0d61faa478cdcd54c6db2cec6144d8d1185115097a7da79c16ad3118d12e36dbcb7a70b0ddb27bddfcb1c6e5426b7e411f607d22c3ac2b8d3e41f55faf5e2105bf3b943846cc4c33edc64f902c1eeda09c8110d4f3ed0a5e511156a3e368f02161b92126abf649341ddb8ed03d1d41b91fc34548c6d94dfb47c088ef27a3cbfe1c9cb05f2ab2f18b8746394c8080c4cd92e818e46f861614ab870cb7ae3446e376793f3a6568a2ccfc2ab0ed0365567671436fee6cf427b6410a046d80b9d88f094924ad370da363e8eb70355b711687e92d88a08ed811ff241c7a6dbbad9dcfc18e6a42493483b938e36c1edd2a1c6e078a17c5d145c9c058b4dd69afc44c345f1c88afb95c1deb5c4994161ba25783165d43b9e50a2d8333a8037cec2ae809a3dbe026d6ba40d60badd05bce73b0f9f36966c30b9c0cb5776544c1182024a96e746a3b01f9db10b45aaffd3b055b02b40bccd41e57c10719bedb0fba99a0f6b0868b186fca0397ab8c219f33190f81e4cce2fbcbc0975c394919c98fdfd7e25a33e5f31fefd06c8dc409cbd3e743f0f48dc90abe45b2e68948436caa37fe9932a77b7e0fe0819d8283964b0eee2249d9190f3eb0bb8178e10a287be1059f35cc1a153dda14def65f3c49cdc5186da86bd3e965446f914e3c9b4cbfcfd2c379f306c5ef8844c4fd398b3c6f96601e90d2dc8810875663939f63abe3ee2e1c8a9c2c2010a01d0dcaebb556a7c98421f8e6465cb0434c07dcea9db1a142f9684e50b06c545785f0dee4def1257e4bb22d87a2b37ca9eb53081eb8f1ea0439c4575abac435868a36552df569ccc63477594ccf7eadfed6adbb8e81800a2e2fdd7effdd1e2f09cf76c9e780f6f8eb8408a3fcc06cb8bcd28db7a37edb0232a6f0e509c684318f179d0c91a97718ce3956c266790361ea3a1bf70cdb8a2f2a59b06dee18075745c7302db9b13a452c188c5624964af2d5d4bbb1138dec59df5dfb077a0f62ac4db3de81f54365f2a4a6dee63a6092b4660d3f5dca3cc8de3bb5350f5dcebabd515c72c9114bc58d96e2e863106f0982c2632bbacf2fe5cf6a8df880c550f7008fd09227baff82d4eb031802fbe7d50f6174860c70fcd9f0356e34c0d45df66492dc309b260b7158adf678e2da66348ca84de3e721c6196e0c717f59cb802c6866defdd9032a4b7da82b816d9681e5eb9115fc2a572fbbe105f479ab339bfa5961aa1920346c9ae4185a74aa828da78a71e55876c657249e83f5812cfb055400da1db8bbb5ed3ce2ca4655b0c39b698ed7d235fb0ed4f29a7e8925cb873176efcd1c6981dd23865468c6e01ddf61fa3e40d6fed18d8e3dbd97a08c68bfb092e441e512d44089cf563509785dd58203949a1ca9b66a700db14060a760aa404e5e9f31eaac015f1527f6d760d8714c88040b87fc8a4d183230cfae35326947e28a7a37eefe1d77070f5232a0d67e278a45d649709a7398cbd43094c5001263671517f83e62e79fb75e6f9bc592fb3bbececa3f597dee71dda0fc909079ea49d81554d2fd79d1cf3cf25d1186efb83cf972b7426600d7d6eb6c48a5f0e26af640c733f3f771e0926e6b38b6f39d7882b0538dcf281d92a6bd361bb32e16f3988d6790fa0a45f549e983f4eb68ce5ff11647b37f8e4c444aae8bc0f7c49ce7215545a29215b55f37dc42aa6add6fd1fb45d9ae580434097e7a8686e23cdbdbf6f8b6b1e5579a7908bafd8878b004c7c94e045fdf2b94f8c1a75ccee7bfabd9bb6d0ea8a60dca61053636160c19f8f3fff3d0330fc95d20a1393629f33f281e5da80a5ff66aaa5eefcf495f8bf7e24744778841d7c633f01af2305a122ee093837998e87f060105ffbc083c0d71f68c2c63820d7a547d9af5618544efb9736af56736e73cb696f191c68970ea1deb587231c889672b3b5399b9b5e915e3c567474c3905ec5b6468da826f1a6438ec335da847db540a091ab311c6846f96a2f17befa2f29ea491a41d7630e42583ad1212e6c606dc258a49f756e2480f90775c04c5c533300e37f8bc7afe7b155fb95877252ce4a53f78491ebf9d8a4aa41da1848633816542901d56e66f126316c80efdaf4b457f9ce771edb012a0b3c27c717f5cb3cc99ffcc959a02289e30d5b1ff936320579c469bd55cba6e79a0c5f1bda59981b71840a8c1ca56863e91eb21fbaf84525d5f04e0f282d03bb56d6dc2352f163d8357b86bc6e4e621bb693db3565eb9ef5629af537874c1cb3459582463362dab3c6fed7e574ce9bffcc685b8eea61599292cc69860c4f9584818182f94d719dcc463e9a6f854405ca2deb3de29ffa1826f795b7e7ac2555c0ee576c75494cb832c59de8d9620927167bc136549b731ef79a39fbf8789831cc003a772fa00d4d699d089d47037e12e1c6eb8c20c5535225a33a1a787ba866ad481e9a4d689c83d75f1986405c82154e312ce8b3494ac5721b96193c025bb75b2cc974f9171297da058d2ed4f00d94e60737af29da660fc51fb9bb4d241e78c9d1815d7e3ea90aa541c4c512ab423ece93f9ff2f479f464b953b4171217b758b280c5d8acda32cced7bb0c92cd9b405afb3a8405602da914e1831fec5b6a291f90635afe82b9389a8b41d957f81be125de2f943b7cda9e873fcd74b446bacc00bdfcbe643053f6cc8162c0a98343242b489f59f7ebac016a7fbf620dafc15c8ecfe20b954153dba19eb81087673a1e847238864036e9a300239a00a5a03d8b39aae2bc201c04c477b1f2a37552670c06ea65551c5c88a42476d0d797af494b077737cb48050bd35f4980964b8b9b98bde84615e8fdca407230f5d15e97ae65d63a96f3d88518fde12d6a82881db5c8d4cd79e724312e88b394129de3569c5c99bf842a90f193c91fa55a82116e237c877dec2da6dc652cb33e33df47420c5238fb6ba5fd96cb77f0cf6c8a12be1a95186680d16a064d9b1a7c2461fdf5e0a512a5a3ed2f8dc0eeadb6c95a658aa1c2713fea473de51f65b13a40a2fe64e5227bc9248f59c2bd60dd2fc14918e333faab6e792ce2f0597be47cee70f5a8b788a50c9cd153bf24786aa80f631ad21926e3285f41c5125a15c12cc889112df0b1857020160122c2595ab3359bcab184ecb32f7cf8f38eea23f4f9135104629d8f1e8273c44f8afa129d3a74cf58ce494214629cd53b99a8489ddc5d339e317ce75dd6c5dbd098d811c56ec5f19c00fa00b5465e39f8f2022c71ab3ed0d5a24058c197719551985ab30a851390ab5e11420c521b1398bff0038d904e5879db37d60c623a0a82e191cd0b6bd20a9e956d41d5daef703bdedd6bd0e20fb096423dd39706e939e796aa8bdf071e44791d2e1ed4a81ffd018cb79c5b6bdfd6297cc6cd379845fd7ddfdb0b83d7b26c21e3edb58185e71472a79cb65322579bd5e0e7b1fe081dcae5447834d70459f8a96b341a26d8922a2b1412f95f3533e04b5f65be112cca03ca45ee0eca10adc7593c78c041281c880d879125e585e68f5c7fbf8686f245cd736ab5aadc57c032c637b753b49575acf4bbff46883382f408417438d7817097accae3fc54afc6015b84b3b05627d7c83c4627c87727bd24c4b4d96a08c64164ab8d4abe3fff5c3b09e8fd12498e3cc3627e799e4ef72a870cd89598d51ba396655b4de66e48997faa51d05d581c52f52852cffc9f89252f26d314d2fb8fcbce197f3a8f330339c2ec3c710710b74f0915da3bbb638b1f1a0cb0c176adc151da0ab52796d466b23e8a269c5b22b76fe7586cbc217621acc955a43571dc04f69deb50066cc587595cf0ca4e9a00a261ff2791ada8de04bcbbea249d2a7840bd8fd3ef98a248eacb7fea5318b2e207668e13ab4e5578c03315d44b478df5247d8afd0624d2a57adf85fd16d86ae54cca21f6c91d8cafb3b31e3f9c4e903c04f39d67c90560dd10b2d28c6ee937cae01e921c98ddd833a9b9247053110c0f29d2f35f8ea322a738636f17648b627db622a9cc891fc1d066d5fcabc168f1b492479b0578d0bd8de0298d4bb96a4351714a10a39de49d57ad66bd6b458ae0d799a19da54bf620c0e6979a95b61a83cd06e46d7d263d53d66f77557232983268f5fd01d10442af0c840ab09c6cc4ad77add6379eeaf98f7cdbd70fffcb035abae4efecdb7e6f63ed8acebd8449b3a910e5eb06b0ee6d80dd45026c9e6c2f978f813b2800386a4d7ad9d127d76c4286c1b2facccfd16e6a263ba3e2893ae5e42049d421e08a62ee9e9574a1f70f0add7b68344256592513cc15f4bc64c5a029f60d617c245c1c34d06c095b2d0a9647e65dadb33ea79e3e0ea62ce55347d24eaab7cf9fc33fd70c07363771f78a13d92941daf7970c97b43d2fbe3e789a52ae7bed64736e6ce59f95322d20f9d6dc00b5824a0ce9072dd051c66ac20d39bd953f567a831d75fa91fb4d49b200fc893489e60df95c2810f7fc57b7f6b7725ae600e1c2def6a943b8d111ff3e9a5ac80aa981fad8709e98ee1550005bb8f65dedffbfe3793abb407fc0470736574056302000359a33e8f3d0439eb7d60aa79255858269bc1011e4cd0d4aa753bc2793f9638fe70dda4a99191f08700047a8b66d9cf7a53bf70756013c8630419e3a0bf428158dd02ab6e16822f239df0a6f1b67b6e1335509a286b30c4b11a22dcea9f95d51307fc04707365740721027fa518c54bb326d5ce3da5c2eb8a6521ab99df86b511477d0f5ebcd616f063ac0007fc04707365740121081271c10f0caf52a40e015e7d35966dbad39525a6c0691d4beeb3bfb22af5304d07fc047073657403210b85bd6dc21b4919f6ebda7ab86ac8122c793be3fad19e44455945ddec8b59e9f6010422002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84507fc047073657404fd4e1060330000000000000001cb6f1101e2b960c9a2fe480eb88fc76c63e58b57445c78d88e04f740580a36d6956006ef12ba606aaca89796dad5ff7cb4c4c7f4e65a07fea8a2ce3b58b265d4b3220013a09ecf4e01023aabca5586d61ecd5d7f2bedceb8b18a8e41451c97a192098b196add06a8a6b619e1e731fd9ae2973741aff6358c1ad45cc873a2d497271e3a20873a6f701d4c44ef670c8c7a9793079d9bdfe956bdc02a52d1de8b2de58b0f7d309240999f13985fa8c98e57fe1bb75219ae6330e9495b523e891dba7885a5302817d68a9891ae0c2597d4d7833b91b073c4f9b27be1cf81ca1c2c1014c57a4affe7b402c0e0c1862bd17bc1d43428671a106c26cab61d5e4ffd1c01f6af1c6e97f7a25ae8aaa8d2c91c57881df52bd5f242b127ec7aed5880101caa01783884dfe943ec9764473323f59b27a204f34aa1fe7fd4433fa606608b0f253247d149e3e269ae5445e917390be83d5650c05859e3a817a6c7e561e2b12baf6d4ca4221df0b7f29fa134269139afd9cee5c7d60149dfa23031705c6a8b72d00d659d7a085de8330de2e5c168ee3eba2180a9319f5e8e0806dadaf0fffbc2df839571360b8cd32300504a527cf914da7a1e788261c9cca2872ebec5a17cad33b15a7a7427c200b8746761359194520f0da1d7ae03f26190d07cf92d515e04815f514c66a98997320a028ad24e83182f213d991accf19a8a59003a2ca666ca505c0d8349e2cb22887efb7db9e4a4e3e2d8da0d5f032603e03f48fb967fd018fc99c6eb72acee4178edeb48703903a89e9462a2d1f447234c3373fff8b205848c7a9d6e45ccc31eeeb0105ed3af1188fb847cf6f03a7f0a646fa325b672796168dbbd9d1d19b2f41685b18c3c96f1cfb7ecb1dea132e8815b62647820ac4b12597d8e737a01a970704b03ba5ae68f8d64a1810db10427fbff1d74cfac91561484cfc8d3b23f74ba0f37e7db2f942c58fb1dd30f6a50c57b5eae720c6ed69b0fb81a6e0260c53028c732a544391e319987a24548230378f8f1ddf65a2d654c7b26951d5c6546cc8fda6003228e8913c9e3c5adf7b7b72f4ff5c4aedba6096097f9a4b58ea1e060609e8d1f0fb0e5dd905b29fec72b118d40c5f599a63f9a37041742a7f1af3ef951c31833621842ec212f9fc5cd3e8c08278ea192f8032ade447d2f35ab59810aff371f598b7dd57b3cde2ad854ecad0c786150748ac241ecd67cb868663a6fcbe9d68c3dc221d4fcec9b0ad89c337c1e10b91a38ab1357f260ca3a084da536e56262973e6c6cca838601fb2f335811375aed78295c4b17d3798d39d4cbf6254ce57680a102907e5c08b5c7ec0a1e73bf3d7b8babdc6156c6ca3f09c0423d6716ff4e6ee0338cfd778158202b5ffb60b74558dc6d0be9b5aed6892c4e0ad3e20de5b604b2b010af09ceaba7c0fba5a7fed39d31cb2769909a251ba5b0668330f734728f5c6786a8f1a35df77f3d739eec71d9268fb2a494a14bf7ab91c075023e76856d1745f5813d83878822934d0b4cc0538048c3f96cad7aef2bbc49bab139915dd4998ed3c6701973eb7913530b14c688f0b344ca9cb990de2a9b12fa7ad8b292234a33428b4d16813693964365bd412fb936c1461fdf8dfb0bba31202685f29addf95fc65f841e97042bc5d82f103e41017c6ac91d3d266e12db2dc195ac4f6d4353924270c7144cd96dcd07b9612e2bf1e0f7fc46ef83690648395c575a13c2b2df0fa04f740340e6b116b0866a401de22f68fa3f621d75b9f5f625cd5d5d7e12a5b0ff795749d742eb2648ddf068a451059390da566b3de84f9d528b2663de7dcc562eb014071e8277a054783d322fa67b9e5261b87e9c354ff58fc52bf9df404139311d6bf9650658fc94835a6220ca02a4bfbf46b2af4f30b1ba681c0de7c134d98dd52eb1e937c191cc9557aa73a343b99ae0b8954a3e929174984b574da75e90a9b71af1215317b04e4090770ab596091fc05c82235a324f86280f7fa081360ac758c1980c6a6763453e6b344611e46b05760941f9517ceb298ed7a2d6f96b11f5719ed0dec803c511dadb8d056d4ca06ca0ad090558a4fbf3a886f3ea9c33e1bb4bb5ddef4798cdfb384bea75a3794c42a53af60f12c95fe9b38d7f6a5d914ef100508091fc84756b596b9ba08d1dc42a7e253435b5481d1470ef00a1172cb036b5bdfaccaee02b15d099da17f9753846226325232e71ed9b48f57697bb3d1db75ed214310e6e3608ded6f188e37b21b96eefaa396db0df05a86416fe64aa950eea87e7af4407c828a8822b17be661269c9f9e365cdc79d20503e2d5e575c5387fa961206118dd379834aade7727a1b2477a24f05f6c2ba3156fe7f5b5ba6d7487b1a124f38e3ed3cda92a8edf05f28e3d699f0c12de9cfeb30ec8d4cd253287a6d3f596db0c06006a531e80083f5b41ee26c05d529e0a59ec151b4a9260a7ea8c1a175ca41b59f464adc122f448fc43e90dfa7b88f81caa7a84e3d6d4dbb85e5828b6ae7455dc2c87c8d9c706af2e62763675851b4ca449c9c0f95d953ce53c5327ba8981321a1cbfb76bafac7fa17c99567725d8e0ac288f3ccd3bad666e515156517281c97a3dbfbd5f345f8eb80bb3c4230301a38b7c920d74eb910d380f884a683f7d3e2738fabf9646138e8a32c35e43786e67925508e4cc7b1e7a36abdf6a497077704e216f1e730c20ecfcddfbdf2484d8eb0ef9b7478f77063fa90b8afbcd019d1a584df58c537b40b193f246598ae4c53958a947dd3916b14a5a4227f01bf543a8c5d6ab8eaefdfb959c8715b756a9c797fe39229dc56a86364cb367fa37e16e96cf8dca1fdc8b6a46ce88e3d29c75b6cc718ca8c28e9e1ae991b28c286107c1dced150814d6369cc8003b2976018941df7fb8eeb68be57adcf8a0e813d2fcd16dc390ce17dd0a91dd674d766d21b5de7f4678a548d75cc3de7d099b418fbdb66b2a2b12a56b1dd8b3f84a7b45e36db9bb63b3ef9fdadebc21c6a75364173925ffc69d481024e49076dca105795e7a64a3c82011889aacf0114a1bd31414e288cbb63eb47d399d0e025a54f11670c8ad4a793d0e7ebd3b0d8eb30b87cf62b131c61a4c55d2e56e47ae99fc543c57a1877ce44dac4c6f9fd99552701ade43858e0b4020230cb4d42d1990bfb509471a5c1c5557c29c00072c5cbbc056de6d465ea2ba2f4a1a5dd604dbf998e834b9200c59fdf90bec38af9218e47ea5ed5512cf8b0146126a15d49bf915eb893ad1ef83d8faf6c93f944ebce3704f930b6f69a1afe767ac2c9fdf092c804c7372ae1a64bca3a3b5a31f2ad430ba9e61dab3daa3be90a538cf0fba00796de511cddb5a594f14aa6d215bd0be19c0ca5f043403b7dc56c87b092d9436eb79509c3dbe367c2fcbc2b09f9818cf5a55d5ee0e477888166bbfece661b62812ffed3e4167ecc81dba148f89a8f2e7c27424a2ee091ac487e68fbbf9798e8caf46b35de8dde66a7cad6dc98a426ea7b8b930cf2d7d71fe71066dbe51e8a1c7151e97fecbeedef3d6f8e01cd5576dd58097b46153f9c3bcecf30bc82b4cdfb1bbfa826c7c5b217a023e4da02a35d0947b2c4d24d50a292e4c70fe854a420c54490d4850ee8c372756671fe130532f89878a64977ead60bf604b73859ae64ed62536423bb51b30c6fedbc819fdae05cb64b87b153f4252b832d6b866100a7b307d1e705643f96f0724858e6211802b2ce706d5424b99315db90c7d74fac66951251f6cb739ea008f839c7f62318f795337ca4ff05886a2640819873ae00b933081b64da1101d1b17451357921a2f4d4dc86c92a5eb346fd6cd3a63315768b94b90a15162aec91cea706b9221330db154d1fd71acac90be47055c725bce38710f1b4b4144f331cfa9fe15ebf6535747669e4aa1f0d72092ef395f16a4ec9014029b5c9d1b4bed9ec81a7568f8f1c87e0ce0f4ef9cf49e3fe4960b0b7904614772c63147f3c5463fffed182919c4973a8256346116be40b10a38cdea5bad5878760daaeda57476e86ec65e58030bc8ff99ebf017e9bf6383f981edc83b538e2bf4bb573637e6f4717d74a3ac71f5e151259b29c1b7226e3a8ab176baa2f27e3e385cd48c6f072bb6e8e9c92e35d7ff51177f4e3553555d967c04befc1847003a8592738c82eef231ce3d372372a19a01b27dc7916f986ff3f3ea8872d4986bc1ca649a92924c8f582ae2b44028e711e955d2563c33db3b7734aa246de553dab2c5268538f7c2b6dbe9a70657e2a26e52f5d216dfa9aa8e197a227c86a7d3b468880a721b804a0c51af1592043eee7fe3657b40c1832a858cfb4e037d208ee69c4fd697b929383a971b2a0864544505af2267e334db5f3f3f4ed88e2f6f2b3d7b96016ff92a120556e4d1e50440943893b00508c6242bcc41b6d06dc29ba20564b42257b9fa1b5f4f453e94e72501d31e8947e09a38261020400db4b8cf675b1854639a962a57905cbbee14ea0daa9bd281fd635c8f900fcabdcbcfb140f4f24b47731782ca899284fadfc9d0d6eff77045792e139afad34c7672bacfa22d85fcc05652178cc169bcf52ee3cef281d99935abf9c9910caa7994cfe33b9319d9854aa6e2590a86297f23b0cada7251a6ee1b2f3d2cb5a193cae8768d92f556994e416d4bcf5bba3a295d9e2215291237df74e3c493189bc5a27b3fec3e1a1329c6c6c75e0802b40fc74776476dd2d9e3453ec1709a8a2d162a936d9fe7dd4b6f7abdadfa429aed4cbd5896cfb24a2d91f1cee781d0ed73cf7306d6f9545fd3346c2232b8799553357a5a531d6085d04af5f183019dfd3483baf23b0ba5a6b58bba4b7a1eb0a32626bebb5cc0c4dad45c55d135be8b0a4dee787ed48b90a2a3fc120a753b52290c27ad0eb32b668a9540986ca0256c1676debc4d19b1b80bedd81e505154264a199ef1a54e1fff1b3589fbb6b2d87a1e04e67066571b68fe04f030d473f8d135585f8b7be91f0ae1a4fa2f44008c0f727f6aba9c5c60c3a9ff22911e267ffa2a5d1c71ff25f96ad257be29a2ec641e2055d785765cadd0c2fe513c44154e74f4b8cc4b24d9ee2f6cfe245549713f9dada1935247a2ac7ccc13c4a5c00c6ffe7ca33c0cde4c75c4fe2ea041a965e4c7385ebfdbc348da8c4216a02fa829892c827adbcbb87745120667cdc5a4aef28b190a54b422df45b8547c447765838dbf9f05de338ab672706b59b2f0644d6735d9316e64a1a15d3dfad893bb1bbcbe1b574a0b8ef5265e195a929148cc5e97c8bfb032d4528b523b6a6b29209428f38115cd102e3b4e268333e490140964278238e7ea9638ac34559e05300dad0c3f18e9228474cd3a7186102967c33fc14f086b4f1ec3957d87f2609d140dbb9e7ff793101d1cb90d004565c6a32924715b1bcab483e6389e2e824054edef350f328870f16412aca0fee39edcbd02a6a667aaaeabb6654c4762c639a26286a3c1730ab75defcd9451b4377f6acdc3b905684658c0844d904c47d313d85eb54963fd71a9a76dc8e345e479004f00e446b886ec41cf7bbb9311463e877aa4e357a0dd0b185a5cf12244296f5f8568e84cf6ac3b6125db6897e4e7c183cafc04f61b3263456f61a7880b446e3cffe986c3bf027c7deba490ec8544d2627e6596ef8f8a5cb577796e7c36ffc4f4346263b5d86ae1d7b8d04709367349d590047a8bfb34fbf6481adce60eddfdd1e148ab83874d70b5303fa0ce60c0ba7a047a477dc4c513d2218b0bb2bdf9b60be9a39e928976464e333ce0cb19aa21fda1c6851c6db9d5bbc6552e080f8e448637af711fed92e72c8d8530187de94603377dc387041a9eb42ac70b3923b9828de33bb337d55409cb419bf4089cb2bec79ffc3afc6dcc3cb82bc903d956d28e307fc0470736574056302000318eb22887126df9062243038440ef3fca2aa024fff8739db4930b314822b00cab172e83c33b7e5b959b0c3f27c714e447120833ef69bd634d1e011fc3c2585beaa882a29c2dabddfd31a48c0255d1ab57c6796aa4625a546a02cef51a9ee2e8007fc047073657407210302e71fc2fff37aeb6d2e2a7b7f2308d4ab7d4bf0a4cf9be7c06e89a66442b48300010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104000007fc047073657401210970cb1dff96101101e24bed1a66fb0794d2fcb26aba11e7f2393edc1534df8a9607fc047073657403210b9991881df2ec384ff5616f6c03d45cf033ee64536297c3557f9fffec716c1fbe0104220020cd4ed5f0db8c450e8b0be595b6410c1759c19f1f6926279095c83dade9862b6d07fc047073657404fd4e10603300000000000000018b6d2d00790f618171a9e8eb6051fc14dc27c502a54f5ccecacb4bcb350581a8f4b1a887a1e58865a21f51ef5098400c115cca84f489637718d8c3ca4350ad677374d40d2b64fe949ca34bd4ba845a87c7693421b70aa8d852e021aee329762883b9820bc0a47ea2fc6a8411ef773703632849094e51c73997c67f3e922d2801b6abc445375cd963a62c2bb28d733bf9274fe503081b51a56023a94200743e7d38865c190331449d19bf3d4eb7bf0b2a9b90696484aab906b9470e10946744838fc428f88461864d6601e93f10909e049a315fcc0ea7f4d71507fe5ed19b9ac2f55b0d3902b153ee27da9c55ab66debfb5ca440dfbb1a600cd8875049c4c13bbf242d26b10035002c7859f9c3ea631d955914adfa0817e4801e85b3f250cd9e7523db62c4ecb17a49028a02a1b61eb96a410643f1fec0ac664d96f99a1db4ac335c2bfec2946707c3c779a56373db197039af9a903e833af6f51de5cf8fc667dbf5416845d415dc98641e0984ebdfab88bbcdf305f605d36f7a472a516206d7ec722251e269800a00e8adb8f2ce161395c1c6ad4b406e1fda77bc7f0af07ea075011cee6cc5e7fd1b6e96e321171ca7d28a35595ddf0b0c831d28a88d30c7391c5832d90f906539aa49185fc6c0864e2d10b21160991fc19a1d084006d03fe3fb6f571f1ffd9f06ffbc0c076689373f9c2f8655758f7f44618345a6d5f8edae46e73a09c38157d5c39dd51a47756ea761e6320d6a91a1bb22d8dd35e4e7806b0242bcc4cae8720a953c6f933c0ee3216513cce6742a2cb4bf44553d8eaf175471dbc0f71c7c245fe99ab4240ccac637a16c82f0c60586f00d83ff852af48a239289d8b70a2638b0aff02572d6d2d68e22b87ba93f3db51bb27825265607ba4b6e9a194c7351f220b9e715a23237c40024fb7cfedaf7c8e0a1c4c6aebef8841fcf2609a3dd7f44dfd8895077df41f10790372eac8adff5ea7eeb28e371b4700d5044b41fd358dc4ba29158213e0f93711026fac8abfbe7cd80a939477ce545bc91cd1d32e8f2268563b0fe3e80855777d51cdf4835050a557d3c7b7f6905ba744ae5450d22837d2c2fa0c0755934654a78601a1fe236f11b6d72f368880ed938ff4a2e8d82c118493a1bb9a9ee95cf329f2d175d467aacc2c6cd73ed59ce64d508604db77942f9b7f3b0f86d913d3e1b489d2190a6da1ed997ab1eee356c885270e4e0192acc9c2b8702107c96aed654318bbb7724b913808dd2cfbbf6ace8db9c4cbf26f2c90a76eb967e365c58855b83550819cb5b28ea5e6ec1ea153ad3ee5e6292a174f7cab1b39e852194a6926bdc4d42326e17998cc057f614e91f6acab5a5bbedd93d9a13dc61977aa2accaf35370a3f1d3819c43c9430d0e767e92de96bb225007a7b6576ed7c4f05c984ce2e437d3b7f7f50c270caf90f8e5dbecb992be2972ef8d79c7674e025ee06b1302bcbd57fe5be9d9b4e38f17d9dca898ef3d71918550fd77a15c7aa2b66ee1a2f38b81040f3d6ec6693f54cc3fe39515275849e9e24b0af3e81705dea95e8f1bb1b4665cfdeb0630a5542a2857f2b58c36761d743299d77872d6894302123f4347702572f04d9876191d771e87655c071fbd29338eef0f9acb0a8ca3f0327ead8e875bc2e7ba38f249e6eda1fb74162e972ff523d20c6638b93297d406e9b2264187c06d0a78203d771f2525227d029b27b23192f747492b9774b12b039729ef75d11ce8d701e56fbb202f3e4bd68686f096f13680456529e5f132915595e0e0b4061b3014219f1fbef4d7403dbfcac01c701b7727c2463cb838d427e07706400be4fdd9140a800e47e7ac15a7a8a897187a38a0080726349d8b7566252076b1ae1366496b50e9a6d236837ffa0c4c3e61bb409a7d9faf8662109ef7213007a76a6d94cb79ad07183a33a4cdedd78896278a3b5531ec0efda9d77076d85a63536b426a6b58c3d0e8a46faf0fdf678e4964272e8410b346cc753edb94a61a2f309f8e753ff332f5b15215e0a20ef32e6a6faa044a431764e008e66b4af820bb6afe4d8dc1679219fe7614482517fdc523d4d7ce2bad9d59f7b9aed89b813e5b36b58a7c668e53181c0e1da45e4ba3851b46de8e056d63e440c471fbe23fbffc31ece7cd20658784f2d2fca3f730a1f8a90ea6995ccb490fca475b1441e38468433d1423c1d83a20b04f1216aff13c8e035c2ed389695c2bb0bedadc38c8a6222d687f0235bda3566c0865774bb6098acd674ff9091db1a6c4f0c2955c1759730b361f310d956f892089f500eae0084022e610ca4e758ce2c680d213bd1b5e00a6c991976e93189159bb98a1e4eff14f681d47694060126c0852ad52489c15d7302d82c66aa830208a9fd13da87a2aac3e44dddae632f2e4d56dc768ee6b3622c61e59aee27fee5aa0bfa9c56402ae3525f00634b11381d0b9637ac699e4c4b225c32bef9dc563e87cfc33bf07450c2cdd015bbd94df63697cdd9b6cf4169cfe1f626c126dbb588c57542662d02eeed561946ce94b46571f72ca3cf7fe52a8a6ea24fa216f01655dadbeb0f74e383e522da69db64b368cb155c2ba4c4fc8aea8745b1081223317003f0cd7ae620fc7d9a6c9c4f39a237d5d9d7f3e756c77daeccbd5d06ed28ac2f089db5449340872bc444aa4aecf6552621b84e4fabfd6baf0e1b61cab00e5c2050bfa38899e9840e2dac55c7d5e7105f65dc3afe3c35dd3e8ebb1a013d65fb0b9d76665f3c4eff5b766fbb0c03cc10c411987ef516405296437a91a67d7398d788e30f55bc1e6236b317784504c53800cc07f4eaf78bac03a025a7943573edcc67db3d5d5281f85ee993238fee3580cb846efae33b45ee2ee1ad640b1d068302504521269a31a166435e8fd964d2e15048f299a95ec1cbeb0c8d5d119e24670112d61d56ea120d7bc30fcd924fc7b812404ac45798af3fb590570a4d7a3f41639b879d1bdf2c72c979105460892fb41570cffee716679eb7b4124be188e28ca4c68d206c1cc9d49cd7489d63372853dbe83f874579238ecdd28c0dc265871d6dccf782b571f1004702121e8b15c9d8af9e6812dbbe742812c7e7cd1dafbdbe3d189f618936e270855700be8f6a7b528f271a936a2cae204b44d909ae3f6a8bcbfcda44b430397b1c96187e5a8362afe92bb9afb0a0a482cb6c8cac39a0fb1fe0034f8a965a3be425b4b34f67ff38a8ab30f8219a8933539c1d06d9b2997b6de743c568caea8b269642b8503b546c9e136d0e47775c8fef45d4489e6b4747c6accd6fad3d34fdd6cbafe07264e7ae1e025306c97d77a130093cc8d5ab8e4abe095787183a9084c569168011766b47dade4e3e1353a78f9f3464d8237b7de02da10c7a7b8951bafbaa898003ad9de997c89d8507393c6fb782b8f41aa99d5c92d5ed93e02a2e7550d42f178739898406badb6da850e305c10063b1a687a2b321a1f867ddfc7949d9764493af4f9681137101f87ec3c3733c0ee23a758a69dd5dbfccd20e0e7cc8543c213688ef9cc85bf9c539d3b6758e24befb3c1b617b7d59a17e915bb985df8229429430dd3057a8225d22afc2775e352a2d7c2f2f46786d4e6e984fb35ac6d7e1b57da82a6d1470895e56521c88c166f8124a4f0c5ada7d5e43174e319c21b9416735858ab50958def63c9a38e853d28a0f47b8e601beb0cdfb30d87070003f957ae347d5b03e80890311ded8018de0227c430f29ff20f0d0d1331dd5f22cff547847c0a26c1fdc272cd234b668823635f68e0797bf68fb1e531a423b1fae9b056fb8c0589908cd2774a7bea8da465248a438a22919d35e0ed8c5020f06824aa856c1a75e0d50d8e9c2dca471d249a97e8e8055d0927432577ef07e6658aa6ab3e9f5f4f50848b12dcdcd9594dae732864f9c6253cccf39922b5f1f8e16458a0c11db397017821de73a331400a76c2a5a29c7661405e9f244a92862a8ca13bc86a78a36744e52019c067573574f75e01b21c36e19a714e9cc0860e9df8e659cefab57002dc2b3d1a2918dc20ff25bc0d87023813abcbbe29defa514bd71fedf314a140508c7e8dd4ace82d56cfd6307fc8299a65c8b3b0719881dc06070d670729902ebfa1dc0b88050e5824cc186454ec2727d0fb2f95eb677f949375a0a31661c7f2bc452426a052b160b0654bffae35766a5317b845582176f1ec52e5bb7d814651781e268cfaefcf6da560810d84343dab8a8b2f2f7976334043498f529d75f9dec893bafdde0ebf003ea7d43f22d8e4eb3afea7be8bd22a9adb9334db2d6b05b8bfe72a96ca2c5ecc925333e4076bf5b7d9ed519ac3eb87c73d0c8121b1034424991561eccb669807a722bcd43141915c9db90f7a8a8e732054970645da1845b988f21cd5d2a89abd8e14c0e6532a3db89e43571b795d6f475b11c16cd7253a4538f4e73d0e3791e0c8f3e51ce3d9645062f249549d9165185fe6920659fe72ae01f69c6d5cef5a01cbbce0fcfd671e1a0aac35d541210a723d2fde91f37c130657d8825662bc46ca7780e07422ce2e7e5cbc1b15ad29b8473ffb832f45c480e960d620267561b3e3112c54359459c3f0235eb6eb2720dd5cf65f88267e099ae87ec7e35b3a915f18a4ab67583ccb4d907637812d797dfa51acc7b5cb13ab58934217a562b00a4a3d030bd9d3565a47c95396034bd65d39d39a6e7795f13e5031d148db16eddba996e1e70730eee02c47bd8b5c42812a12a2db5490fc3ad50d7d03c72c0e933ed8b43f8e34124e272cb39e06e628f18acfe4488dcced67a2c47008801e8d2db5dc7f7556d38020d53512993f3efeb4b07fd1e7b631deeeda74983011ca401ec7b86eb2a7a4d341f97337d37ada0dbbe124fe481ecac3e9b8e8f3b8b90ccf81ec028f2ee4e62934abcfcc2647966f6eea6563a0fc8fc75348f5fb3d2390db24d49858bbca822217fa81d240cacb7b2f6c2e4bad8a7a112b83a5d35ad68ec1cd599afee41fd4e860097f33afbc2cd790b2933f1194549c5aa3fe5c651a456c8ba7c8fa5ee5492233c21a80bd9216fcfccc03ecb76af3849711a0f69d5a261ce94484c30f4b74ca6cb4d7d5c4dcc0be1f0390c208e1e7e863700c6dce7ea5ab3831c00e586094a6a1f3b32dfbbf99a7581f90001dd558738804d0663a59d77407b6ab1ef3a82c156bc58d5a694a365b300a90ebbcddc49bbe5ba63c88e7a6e0faf5364ea17cabc602ddbf87a4c2f55b068ef296be5bb66befc1e37ad77f8e97c08f02d17dcdeb47959b0f46c2ae2c3d99a948f2a52c5793d53fe57876c38336a74786042abafb63c2154096eaed98598aed76da5a17ae179e79f848b237bdd6db63e5fbe77ee28b2bdcae462905ce1827800407317c2a42fc0dc234b2183db9097c0fae23da91aca6b1b7894537b0dc8524536573a34ef68596021cba863ece0de4a068f806d888aa03ed88ad92f375860f8885c5533c637a7a330c24aa0357f007ac3678e59cb1f6aa7c6979e15fd107a98ab42a635a3c3e70b58a19ec73b4bdc482000c3dfb4af84012ea3957d3d30b80857d9e06a2e677c84e5d9041ad4bf22afbdf0351f6d5c7a7a2ada3dd5ab4e48e37d51e5fad56cf9963715438c5f04b9772773893a59e2e46c6b7e19e9001650b66b469f4b1c4d188b286d5ce8b21269179e772147c7cb09eaee9b9de684ffc33068e5d346e79b710d82fd1278aee64ddd4ed37a944e6c745217c6a626444aa95b565c1f68a12cd2b86a61927896884bd5a76a9df4f6fe548bc16444272ec1e856334d64e0f32ba90daa77085b0683e3e010abf571dc564fc703a12998c72b6712386cfa4ccc802c850a3604bb0b2d5cd2eb6e788d475ff198f94a220c925a32ab6d69b037f1b9f0f4ce1d1b89cc0d07fc047073657405630200033fb971149dc9881cf31b7bd90de445f0ada69611016c5fde4af5bffe2b40a1a27d651a1d2127b0a95539b18fbb835f5145c1c4c7492866c6bd08ba260abb300720d2d42b729b72c6166f9ae0e4ac09a0f6851ca65444bed00b72b7f12befbbd007fc047073657407210252a4b012198c2131d70498b5939c401c01eb1178dfd58123b55766b03f008f7b00").unwrap()).unwrap();
        let secp = Secp256k1::verification_only();
        let dummy_hash = elements::BlockHash::all_zeros();
        let tx = psbt.extract(&secp, dummy_hash).unwrap();
        let expected: elements::Transaction = deserialize(&Vec::<u8>::from_hex("020000000102cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae0000000000ffffffffcbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae0100000000ffffffff040b8e11e3b8904ac80caeb16af1c93053f8a11a963269bcefa96823d75b8640ae9408a337e7e0ecf24c121a17193623254c277a306e9fd39cd5aaf8b7d374f4011c65027fa518c54bb326d5ce3da5c2eb8a6521ab99df86b511477d0f5ebcd616f063ac220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d930b85bd6dc21b4919f6ebda7ab86ac8122c793be3fad19e44455945ddec8b59e9f6081271c10f0caf52a40e015e7d35966dbad39525a6c0691d4beeb3bfb22af5304d0302e71fc2fff37aeb6d2e2a7b7f2308d4ab7d4bf0a4cf9be7c06e89a66442b48322002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84501230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000000001f400000b9991881df2ec384ff5616f6c03d45cf033ee64536297c3557f9fffec716c1fbe0970cb1dff96101101e24bed1a66fb0794d2fcb26aba11e7f2393edc1534df8a960252a4b012198c2131d70498b5939c401c01eb1178dfd58123b55766b03f008f7b220020cd4ed5f0db8c450e8b0be595b6410c1759c19f1f6926279095c83dade9862b6d00000000000002473044022040d1802d6e10da4c27f05eff807550e614b3d2fa20c663dbf1ebf162d3952689022001f477c953b7c543bce877e3297fccb00ef5dba21d427e79c8bfb8522713309801210334c307ad8142e7c8a6bf1ad3552b12fbb860885ea7f2d76c1f49f93a7c4bbbe700000002473044022017c696503f5e1539fe5cb8dd05f793bd3b6e39f193028a7299a80c94c817a02d022007889009088f46cd9d9f4d137815704170410f53d503b68c1e020292a85b93fa012103df8f51c053ba0dfb443cce9793b6dc3339ffb0ce97af4792dade3aae1eb890f6006302000359a33e8f3d0439eb7d60aa79255858269bc1011e4cd0d4aa753bc2793f9638fe70dda4a99191f08700047a8b66d9cf7a53bf70756013c8630419e3a0bf428158dd02ab6e16822f239df0a6f1b67b6e1335509a286b30c4b11a22dcea9f95d513fd4e1060330000000000000001efdfbc0022a6437ec10c672d76c513868f403f6b9706e09733d6624e3cda831c2c199dd4c5763054a1c219e079e8cf3ce0c00dc2f16516972e1e64d576adfd9f5d778675c8a3172450a4cc82d6e6c59f2b16dffddc902d0aaa647b750d6224cafca7239a4fa81219cf2ee89741ffc5b7dd7e47d332ca931cffb1d1d432935a6013207629118c965b7a5102e62c43ca9d06bca191307a476738548536809ff6b01c6b5b25d76ff2f67d99e20fdf7d2eff6fc248186d21d054196023c5e4f572ccf0f3aad8728c46f2ff6756ea39de46028610a3d26cd42978b09e0e29e0a8aa46e4fd39d28d028592560264cf1a794c27f6c95d382f486dfe900a81d9d92935c7e0e6306549b3e49b1f60182512ccb994338c3541a2956139b2ccb3dd156853105abf5fb394cb2c45915dfd4106c7472dc5d360ab5bca408203a3fef58b4dd33b0c11c367dde2f19c8af7682be067244bf49a2b8cd4685f5481cc31ba27fe2f3d7b7a353be9b41e4eee2342fd70b8408c91951c71c75dde8fbc03e3f28e6d3d3b41e0e963d3ba0c25b2eb50560c21221950b0699d2615f0128e6cb7fa1b04ac1a046e569a7e87df98c14360b8ffc43db5e17548c7ea5056f84ffd14f4cdfc68a4f10e9b391cfa63eef2c2d623e7cdcdfae2fc4d63496d81462174ff360809b7e3b4305979d9cb8e9ad5b0f012494d31ce51ee6489555b09dddb16641ed9e2534fc34db99d2a4fa736eeabacf2f8cdca97f9e84c964277c6f30f1af7fe2b51b39b487d56ebaf593a3f98e811cb09849c5b445d5b7c9ba37807bd0189c8bdb2709fa70c230f9aba41dd3c62384aea6e1ca098ffec26367aa65a09459fca074d1da0365cf7fc2d8310ae099b838ca78e62cee10f95ec549faac1ff0f8236fb8cf2c0f6654e471d3950ef45e0159c44f9e343d05b3af59b939cf76090d040376407c41661eeda7d2cb61cad0088a286948787dae0cc5abdcb97f7f42026c65a13e1df1357c25d376955942adc858e73876e1d8812969055d55decac9a689dcd11dffe5cf6e06088b93a11e153ffed104266bba472cebffb2b0cfc8ef132309bd7836071d3b6ed459a5950c64cccf230015c98f9210f2d57b7f3a07c382f3df09f055c88e1f312db0d60d471afdc0b780d319a6229babd8f45edecff8d1073fa850f755219a3ea14e7234cbc7590c60eba0ba0cc1afde6ce91c8e8835b1ca809926b3e7d8d7a0941425e5f08e884f12693eeea1b3651f53da90972aaa37d426f37db3edae4285db114cbad5964c269e03b15358ad2a7242e0af538a594fc779ec3c43c3d94fab2028310c6d0acf3efdf0acf028ee757c5c02bb5b8b691aa5eed1a62acbabd0d61faa478cdcd54c6db2cec6144d8d1185115097a7da79c16ad3118d12e36dbcb7a70b0ddb27bddfcb1c6e5426b7e411f607d22c3ac2b8d3e41f55faf5e2105bf3b943846cc4c33edc64f902c1eeda09c8110d4f3ed0a5e511156a3e368f02161b92126abf649341ddb8ed03d1d41b91fc34548c6d94dfb47c088ef27a3cbfe1c9cb05f2ab2f18b8746394c8080c4cd92e818e46f861614ab870cb7ae3446e376793f3a6568a2ccfc2ab0ed0365567671436fee6cf427b6410a046d80b9d88f094924ad370da363e8eb70355b711687e92d88a08ed811ff241c7a6dbbad9dcfc18e6a42493483b938e36c1edd2a1c6e078a17c5d145c9c058b4dd69afc44c345f1c88afb95c1deb5c4994161ba25783165d43b9e50a2d8333a8037cec2ae809a3dbe026d6ba40d60badd05bce73b0f9f36966c30b9c0cb5776544c1182024a96e746a3b01f9db10b45aaffd3b055b02b40bccd41e57c10719bedb0fba99a0f6b0868b186fca0397ab8c219f33190f81e4cce2fbcbc0975c394919c98fdfd7e25a33e5f31fefd06c8dc409cbd3e743f0f48dc90abe45b2e68948436caa37fe9932a77b7e0fe0819d8283964b0eee2249d9190f3eb0bb8178e10a287be1059f35cc1a153dda14def65f3c49cdc5186da86bd3e965446f914e3c9b4cbfcfd2c379f306c5ef8844c4fd398b3c6f96601e90d2dc8810875663939f63abe3ee2e1c8a9c2c2010a01d0dcaebb556a7c98421f8e6465cb0434c07dcea9db1a142f9684e50b06c545785f0dee4def1257e4bb22d87a2b37ca9eb53081eb8f1ea0439c4575abac435868a36552df569ccc63477594ccf7eadfed6adbb8e81800a2e2fdd7effdd1e2f09cf76c9e780f6f8eb8408a3fcc06cb8bcd28db7a37edb0232a6f0e509c684318f179d0c91a97718ce3956c266790361ea3a1bf70cdb8a2f2a59b06dee18075745c7302db9b13a452c188c5624964af2d5d4bbb1138dec59df5dfb077a0f62ac4db3de81f54365f2a4a6dee63a6092b4660d3f5dca3cc8de3bb5350f5dcebabd515c72c9114bc58d96e2e863106f0982c2632bbacf2fe5cf6a8df880c550f7008fd09227baff82d4eb031802fbe7d50f6174860c70fcd9f0356e34c0d45df66492dc309b260b7158adf678e2da66348ca84de3e721c6196e0c717f59cb802c6866defdd9032a4b7da82b816d9681e5eb9115fc2a572fbbe105f479ab339bfa5961aa1920346c9ae4185a74aa828da78a71e55876c657249e83f5812cfb055400da1db8bbb5ed3ce2ca4655b0c39b698ed7d235fb0ed4f29a7e8925cb873176efcd1c6981dd23865468c6e01ddf61fa3e40d6fed18d8e3dbd97a08c68bfb092e441e512d44089cf563509785dd58203949a1ca9b66a700db14060a760aa404e5e9f31eaac015f1527f6d760d8714c88040b87fc8a4d183230cfae35326947e28a7a37eefe1d77070f5232a0d67e278a45d649709a7398cbd43094c5001263671517f83e62e79fb75e6f9bc592fb3bbececa3f597dee71dda0fc909079ea49d81554d2fd79d1cf3cf25d1186efb83cf972b7426600d7d6eb6c48a5f0e26af640c733f3f771e0926e6b38b6f39d7882b0538dcf281d92a6bd361bb32e16f3988d6790fa0a45f549e983f4eb68ce5ff11647b37f8e4c444aae8bc0f7c49ce7215545a29215b55f37dc42aa6add6fd1fb45d9ae580434097e7a8686e23cdbdbf6f8b6b1e5579a7908bafd8878b004c7c94e045fdf2b94f8c1a75ccee7bfabd9bb6d0ea8a60dca61053636160c19f8f3fff3d0330fc95d20a1393629f33f281e5da80a5ff66aaa5eefcf495f8bf7e24744778841d7c633f01af2305a122ee093837998e87f060105ffbc083c0d71f68c2c63820d7a547d9af5618544efb9736af56736e73cb696f191c68970ea1deb587231c889672b3b5399b9b5e915e3c567474c3905ec5b6468da826f1a6438ec335da847db540a091ab311c6846f96a2f17befa2f29ea491a41d7630e42583ad1212e6c606dc258a49f756e2480f90775c04c5c533300e37f8bc7afe7b155fb95877252ce4a53f78491ebf9d8a4aa41da1848633816542901d56e66f126316c80efdaf4b457f9ce771edb012a0b3c27c717f5cb3cc99ffcc959a02289e30d5b1ff936320579c469bd55cba6e79a0c5f1bda59981b71840a8c1ca56863e91eb21fbaf84525d5f04e0f282d03bb56d6dc2352f163d8357b86bc6e4e621bb693db3565eb9ef5629af537874c1cb3459582463362dab3c6fed7e574ce9bffcc685b8eea61599292cc69860c4f9584818182f94d719dcc463e9a6f854405ca2deb3de29ffa1826f795b7e7ac2555c0ee576c75494cb832c59de8d9620927167bc136549b731ef79a39fbf8789831cc003a772fa00d4d699d089d47037e12e1c6eb8c20c5535225a33a1a787ba866ad481e9a4d689c83d75f1986405c82154e312ce8b3494ac5721b96193c025bb75b2cc974f9171297da058d2ed4f00d94e60737af29da660fc51fb9bb4d241e78c9d1815d7e3ea90aa541c4c512ab423ece93f9ff2f479f464b953b4171217b758b280c5d8acda32cced7bb0c92cd9b405afb3a8405602da914e1831fec5b6a291f90635afe82b9389a8b41d957f81be125de2f943b7cda9e873fcd74b446bacc00bdfcbe643053f6cc8162c0a98343242b489f59f7ebac016a7fbf620dafc15c8ecfe20b954153dba19eb81087673a1e847238864036e9a300239a00a5a03d8b39aae2bc201c04c477b1f2a37552670c06ea65551c5c88a42476d0d797af494b077737cb48050bd35f4980964b8b9b98bde84615e8fdca407230f5d15e97ae65d63a96f3d88518fde12d6a82881db5c8d4cd79e724312e88b394129de3569c5c99bf842a90f193c91fa55a82116e237c877dec2da6dc652cb33e33df47420c5238fb6ba5fd96cb77f0cf6c8a12be1a95186680d16a064d9b1a7c2461fdf5e0a512a5a3ed2f8dc0eeadb6c95a658aa1c2713fea473de51f65b13a40a2fe64e5227bc9248f59c2bd60dd2fc14918e333faab6e792ce2f0597be47cee70f5a8b788a50c9cd153bf24786aa80f631ad21926e3285f41c5125a15c12cc889112df0b1857020160122c2595ab3359bcab184ecb32f7cf8f38eea23f4f9135104629d8f1e8273c44f8afa129d3a74cf58ce494214629cd53b99a8489ddc5d339e317ce75dd6c5dbd098d811c56ec5f19c00fa00b5465e39f8f2022c71ab3ed0d5a24058c197719551985ab30a851390ab5e11420c521b1398bff0038d904e5879db37d60c623a0a82e191cd0b6bd20a9e956d41d5daef703bdedd6bd0e20fb096423dd39706e939e796aa8bdf071e44791d2e1ed4a81ffd018cb79c5b6bdfd6297cc6cd379845fd7ddfdb0b83d7b26c21e3edb58185e71472a79cb65322579bd5e0e7b1fe081dcae5447834d70459f8a96b341a26d8922a2b1412f95f3533e04b5f65be112cca03ca45ee0eca10adc7593c78c041281c880d879125e585e68f5c7fbf8686f245cd736ab5aadc57c032c637b753b49575acf4bbff46883382f408417438d7817097accae3fc54afc6015b84b3b05627d7c83c4627c87727bd24c4b4d96a08c64164ab8d4abe3fff5c3b09e8fd12498e3cc3627e799e4ef72a870cd89598d51ba396655b4de66e48997faa51d05d581c52f52852cffc9f89252f26d314d2fb8fcbce197f3a8f330339c2ec3c710710b74f0915da3bbb638b1f1a0cb0c176adc151da0ab52796d466b23e8a269c5b22b76fe7586cbc217621acc955a43571dc04f69deb50066cc587595cf0ca4e9a00a261ff2791ada8de04bcbbea249d2a7840bd8fd3ef98a248eacb7fea5318b2e207668e13ab4e5578c03315d44b478df5247d8afd0624d2a57adf85fd16d86ae54cca21f6c91d8cafb3b31e3f9c4e903c04f39d67c90560dd10b2d28c6ee937cae01e921c98ddd833a9b9247053110c0f29d2f35f8ea322a738636f17648b627db622a9cc891fc1d066d5fcabc168f1b492479b0578d0bd8de0298d4bb96a4351714a10a39de49d57ad66bd6b458ae0d799a19da54bf620c0e6979a95b61a83cd06e46d7d263d53d66f77557232983268f5fd01d10442af0c840ab09c6cc4ad77add6379eeaf98f7cdbd70fffcb035abae4efecdb7e6f63ed8acebd8449b3a910e5eb06b0ee6d80dd45026c9e6c2f978f813b2800386a4d7ad9d127d76c4286c1b2facccfd16e6a263ba3e2893ae5e42049d421e08a62ee9e9574a1f70f0add7b68344256592513cc15f4bc64c5a029f60d617c245c1c34d06c095b2d0a9647e65dadb33ea79e3e0ea62ce55347d24eaab7cf9fc33fd70c07363771f78a13d92941daf7970c97b43d2fbe3e789a52ae7bed64736e6ce59f95322d20f9d6dc00b5824a0ce9072dd051c66ac20d39bd953f567a831d75fa91fb4d49b200fc893489e60df95c2810f7fc57b7f6b7725ae600e1c2def6a943b8d111ff3e9a5ac80aa981fad8709e98ee1550005bb8f65dedffbfe3793abb46302000318eb22887126df9062243038440ef3fca2aa024fff8739db4930b314822b00cab172e83c33b7e5b959b0c3f27c714e447120833ef69bd634d1e011fc3c2585beaa882a29c2dabddfd31a48c0255d1ab57c6796aa4625a546a02cef51a9ee2e80fd4e1060330000000000000001cb6f1101e2b960c9a2fe480eb88fc76c63e58b57445c78d88e04f740580a36d6956006ef12ba606aaca89796dad5ff7cb4c4c7f4e65a07fea8a2ce3b58b265d4b3220013a09ecf4e01023aabca5586d61ecd5d7f2bedceb8b18a8e41451c97a192098b196add06a8a6b619e1e731fd9ae2973741aff6358c1ad45cc873a2d497271e3a20873a6f701d4c44ef670c8c7a9793079d9bdfe956bdc02a52d1de8b2de58b0f7d309240999f13985fa8c98e57fe1bb75219ae6330e9495b523e891dba7885a5302817d68a9891ae0c2597d4d7833b91b073c4f9b27be1cf81ca1c2c1014c57a4affe7b402c0e0c1862bd17bc1d43428671a106c26cab61d5e4ffd1c01f6af1c6e97f7a25ae8aaa8d2c91c57881df52bd5f242b127ec7aed5880101caa01783884dfe943ec9764473323f59b27a204f34aa1fe7fd4433fa606608b0f253247d149e3e269ae5445e917390be83d5650c05859e3a817a6c7e561e2b12baf6d4ca4221df0b7f29fa134269139afd9cee5c7d60149dfa23031705c6a8b72d00d659d7a085de8330de2e5c168ee3eba2180a9319f5e8e0806dadaf0fffbc2df839571360b8cd32300504a527cf914da7a1e788261c9cca2872ebec5a17cad33b15a7a7427c200b8746761359194520f0da1d7ae03f26190d07cf92d515e04815f514c66a98997320a028ad24e83182f213d991accf19a8a59003a2ca666ca505c0d8349e2cb22887efb7db9e4a4e3e2d8da0d5f032603e03f48fb967fd018fc99c6eb72acee4178edeb48703903a89e9462a2d1f447234c3373fff8b205848c7a9d6e45ccc31eeeb0105ed3af1188fb847cf6f03a7f0a646fa325b672796168dbbd9d1d19b2f41685b18c3c96f1cfb7ecb1dea132e8815b62647820ac4b12597d8e737a01a970704b03ba5ae68f8d64a1810db10427fbff1d74cfac91561484cfc8d3b23f74ba0f37e7db2f942c58fb1dd30f6a50c57b5eae720c6ed69b0fb81a6e0260c53028c732a544391e319987a24548230378f8f1ddf65a2d654c7b26951d5c6546cc8fda6003228e8913c9e3c5adf7b7b72f4ff5c4aedba6096097f9a4b58ea1e060609e8d1f0fb0e5dd905b29fec72b118d40c5f599a63f9a37041742a7f1af3ef951c31833621842ec212f9fc5cd3e8c08278ea192f8032ade447d2f35ab59810aff371f598b7dd57b3cde2ad854ecad0c786150748ac241ecd67cb868663a6fcbe9d68c3dc221d4fcec9b0ad89c337c1e10b91a38ab1357f260ca3a084da536e56262973e6c6cca838601fb2f335811375aed78295c4b17d3798d39d4cbf6254ce57680a102907e5c08b5c7ec0a1e73bf3d7b8babdc6156c6ca3f09c0423d6716ff4e6ee0338cfd778158202b5ffb60b74558dc6d0be9b5aed6892c4e0ad3e20de5b604b2b010af09ceaba7c0fba5a7fed39d31cb2769909a251ba5b0668330f734728f5c6786a8f1a35df77f3d739eec71d9268fb2a494a14bf7ab91c075023e76856d1745f5813d83878822934d0b4cc0538048c3f96cad7aef2bbc49bab139915dd4998ed3c6701973eb7913530b14c688f0b344ca9cb990de2a9b12fa7ad8b292234a33428b4d16813693964365bd412fb936c1461fdf8dfb0bba31202685f29addf95fc65f841e97042bc5d82f103e41017c6ac91d3d266e12db2dc195ac4f6d4353924270c7144cd96dcd07b9612e2bf1e0f7fc46ef83690648395c575a13c2b2df0fa04f740340e6b116b0866a401de22f68fa3f621d75b9f5f625cd5d5d7e12a5b0ff795749d742eb2648ddf068a451059390da566b3de84f9d528b2663de7dcc562eb014071e8277a054783d322fa67b9e5261b87e9c354ff58fc52bf9df404139311d6bf9650658fc94835a6220ca02a4bfbf46b2af4f30b1ba681c0de7c134d98dd52eb1e937c191cc9557aa73a343b99ae0b8954a3e929174984b574da75e90a9b71af1215317b04e4090770ab596091fc05c82235a324f86280f7fa081360ac758c1980c6a6763453e6b344611e46b05760941f9517ceb298ed7a2d6f96b11f5719ed0dec803c511dadb8d056d4ca06ca0ad090558a4fbf3a886f3ea9c33e1bb4bb5ddef4798cdfb384bea75a3794c42a53af60f12c95fe9b38d7f6a5d914ef100508091fc84756b596b9ba08d1dc42a7e253435b5481d1470ef00a1172cb036b5bdfaccaee02b15d099da17f9753846226325232e71ed9b48f57697bb3d1db75ed214310e6e3608ded6f188e37b21b96eefaa396db0df05a86416fe64aa950eea87e7af4407c828a8822b17be661269c9f9e365cdc79d20503e2d5e575c5387fa961206118dd379834aade7727a1b2477a24f05f6c2ba3156fe7f5b5ba6d7487b1a124f38e3ed3cda92a8edf05f28e3d699f0c12de9cfeb30ec8d4cd253287a6d3f596db0c06006a531e80083f5b41ee26c05d529e0a59ec151b4a9260a7ea8c1a175ca41b59f464adc122f448fc43e90dfa7b88f81caa7a84e3d6d4dbb85e5828b6ae7455dc2c87c8d9c706af2e62763675851b4ca449c9c0f95d953ce53c5327ba8981321a1cbfb76bafac7fa17c99567725d8e0ac288f3ccd3bad666e515156517281c97a3dbfbd5f345f8eb80bb3c4230301a38b7c920d74eb910d380f884a683f7d3e2738fabf9646138e8a32c35e43786e67925508e4cc7b1e7a36abdf6a497077704e216f1e730c20ecfcddfbdf2484d8eb0ef9b7478f77063fa90b8afbcd019d1a584df58c537b40b193f246598ae4c53958a947dd3916b14a5a4227f01bf543a8c5d6ab8eaefdfb959c8715b756a9c797fe39229dc56a86364cb367fa37e16e96cf8dca1fdc8b6a46ce88e3d29c75b6cc718ca8c28e9e1ae991b28c286107c1dced150814d6369cc8003b2976018941df7fb8eeb68be57adcf8a0e813d2fcd16dc390ce17dd0a91dd674d766d21b5de7f4678a548d75cc3de7d099b418fbdb66b2a2b12a56b1dd8b3f84a7b45e36db9bb63b3ef9fdadebc21c6a75364173925ffc69d481024e49076dca105795e7a64a3c82011889aacf0114a1bd31414e288cbb63eb47d399d0e025a54f11670c8ad4a793d0e7ebd3b0d8eb30b87cf62b131c61a4c55d2e56e47ae99fc543c57a1877ce44dac4c6f9fd99552701ade43858e0b4020230cb4d42d1990bfb509471a5c1c5557c29c00072c5cbbc056de6d465ea2ba2f4a1a5dd604dbf998e834b9200c59fdf90bec38af9218e47ea5ed5512cf8b0146126a15d49bf915eb893ad1ef83d8faf6c93f944ebce3704f930b6f69a1afe767ac2c9fdf092c804c7372ae1a64bca3a3b5a31f2ad430ba9e61dab3daa3be90a538cf0fba00796de511cddb5a594f14aa6d215bd0be19c0ca5f043403b7dc56c87b092d9436eb79509c3dbe367c2fcbc2b09f9818cf5a55d5ee0e477888166bbfece661b62812ffed3e4167ecc81dba148f89a8f2e7c27424a2ee091ac487e68fbbf9798e8caf46b35de8dde66a7cad6dc98a426ea7b8b930cf2d7d71fe71066dbe51e8a1c7151e97fecbeedef3d6f8e01cd5576dd58097b46153f9c3bcecf30bc82b4cdfb1bbfa826c7c5b217a023e4da02a35d0947b2c4d24d50a292e4c70fe854a420c54490d4850ee8c372756671fe130532f89878a64977ead60bf604b73859ae64ed62536423bb51b30c6fedbc819fdae05cb64b87b153f4252b832d6b866100a7b307d1e705643f96f0724858e6211802b2ce706d5424b99315db90c7d74fac66951251f6cb739ea008f839c7f62318f795337ca4ff05886a2640819873ae00b933081b64da1101d1b17451357921a2f4d4dc86c92a5eb346fd6cd3a63315768b94b90a15162aec91cea706b9221330db154d1fd71acac90be47055c725bce38710f1b4b4144f331cfa9fe15ebf6535747669e4aa1f0d72092ef395f16a4ec9014029b5c9d1b4bed9ec81a7568f8f1c87e0ce0f4ef9cf49e3fe4960b0b7904614772c63147f3c5463fffed182919c4973a8256346116be40b10a38cdea5bad5878760daaeda57476e86ec65e58030bc8ff99ebf017e9bf6383f981edc83b538e2bf4bb573637e6f4717d74a3ac71f5e151259b29c1b7226e3a8ab176baa2f27e3e385cd48c6f072bb6e8e9c92e35d7ff51177f4e3553555d967c04befc1847003a8592738c82eef231ce3d372372a19a01b27dc7916f986ff3f3ea8872d4986bc1ca649a92924c8f582ae2b44028e711e955d2563c33db3b7734aa246de553dab2c5268538f7c2b6dbe9a70657e2a26e52f5d216dfa9aa8e197a227c86a7d3b468880a721b804a0c51af1592043eee7fe3657b40c1832a858cfb4e037d208ee69c4fd697b929383a971b2a0864544505af2267e334db5f3f3f4ed88e2f6f2b3d7b96016ff92a120556e4d1e50440943893b00508c6242bcc41b6d06dc29ba20564b42257b9fa1b5f4f453e94e72501d31e8947e09a38261020400db4b8cf675b1854639a962a57905cbbee14ea0daa9bd281fd635c8f900fcabdcbcfb140f4f24b47731782ca899284fadfc9d0d6eff77045792e139afad34c7672bacfa22d85fcc05652178cc169bcf52ee3cef281d99935abf9c9910caa7994cfe33b9319d9854aa6e2590a86297f23b0cada7251a6ee1b2f3d2cb5a193cae8768d92f556994e416d4bcf5bba3a295d9e2215291237df74e3c493189bc5a27b3fec3e1a1329c6c6c75e0802b40fc74776476dd2d9e3453ec1709a8a2d162a936d9fe7dd4b6f7abdadfa429aed4cbd5896cfb24a2d91f1cee781d0ed73cf7306d6f9545fd3346c2232b8799553357a5a531d6085d04af5f183019dfd3483baf23b0ba5a6b58bba4b7a1eb0a32626bebb5cc0c4dad45c55d135be8b0a4dee787ed48b90a2a3fc120a753b52290c27ad0eb32b668a9540986ca0256c1676debc4d19b1b80bedd81e505154264a199ef1a54e1fff1b3589fbb6b2d87a1e04e67066571b68fe04f030d473f8d135585f8b7be91f0ae1a4fa2f44008c0f727f6aba9c5c60c3a9ff22911e267ffa2a5d1c71ff25f96ad257be29a2ec641e2055d785765cadd0c2fe513c44154e74f4b8cc4b24d9ee2f6cfe245549713f9dada1935247a2ac7ccc13c4a5c00c6ffe7ca33c0cde4c75c4fe2ea041a965e4c7385ebfdbc348da8c4216a02fa829892c827adbcbb87745120667cdc5a4aef28b190a54b422df45b8547c447765838dbf9f05de338ab672706b59b2f0644d6735d9316e64a1a15d3dfad893bb1bbcbe1b574a0b8ef5265e195a929148cc5e97c8bfb032d4528b523b6a6b29209428f38115cd102e3b4e268333e490140964278238e7ea9638ac34559e05300dad0c3f18e9228474cd3a7186102967c33fc14f086b4f1ec3957d87f2609d140dbb9e7ff793101d1cb90d004565c6a32924715b1bcab483e6389e2e824054edef350f328870f16412aca0fee39edcbd02a6a667aaaeabb6654c4762c639a26286a3c1730ab75defcd9451b4377f6acdc3b905684658c0844d904c47d313d85eb54963fd71a9a76dc8e345e479004f00e446b886ec41cf7bbb9311463e877aa4e357a0dd0b185a5cf12244296f5f8568e84cf6ac3b6125db6897e4e7c183cafc04f61b3263456f61a7880b446e3cffe986c3bf027c7deba490ec8544d2627e6596ef8f8a5cb577796e7c36ffc4f4346263b5d86ae1d7b8d04709367349d590047a8bfb34fbf6481adce60eddfdd1e148ab83874d70b5303fa0ce60c0ba7a047a477dc4c513d2218b0bb2bdf9b60be9a39e928976464e333ce0cb19aa21fda1c6851c6db9d5bbc6552e080f8e448637af711fed92e72c8d8530187de94603377dc387041a9eb42ac70b3923b9828de33bb337d55409cb419bf4089cb2bec79ffc3afc6dcc3cb82bc903d956d28e30000630200033fb971149dc9881cf31b7bd90de445f0ada69611016c5fde4af5bffe2b40a1a27d651a1d2127b0a95539b18fbb835f5145c1c4c7492866c6bd08ba260abb300720d2d42b729b72c6166f9ae0e4ac09a0f6851ca65444bed00b72b7f12befbbd0fd4e10603300000000000000018b6d2d00790f618171a9e8eb6051fc14dc27c502a54f5ccecacb4bcb350581a8f4b1a887a1e58865a21f51ef5098400c115cca84f489637718d8c3ca4350ad677374d40d2b64fe949ca34bd4ba845a87c7693421b70aa8d852e021aee329762883b9820bc0a47ea2fc6a8411ef773703632849094e51c73997c67f3e922d2801b6abc445375cd963a62c2bb28d733bf9274fe503081b51a56023a94200743e7d38865c190331449d19bf3d4eb7bf0b2a9b90696484aab906b9470e10946744838fc428f88461864d6601e93f10909e049a315fcc0ea7f4d71507fe5ed19b9ac2f55b0d3902b153ee27da9c55ab66debfb5ca440dfbb1a600cd8875049c4c13bbf242d26b10035002c7859f9c3ea631d955914adfa0817e4801e85b3f250cd9e7523db62c4ecb17a49028a02a1b61eb96a410643f1fec0ac664d96f99a1db4ac335c2bfec2946707c3c779a56373db197039af9a903e833af6f51de5cf8fc667dbf5416845d415dc98641e0984ebdfab88bbcdf305f605d36f7a472a516206d7ec722251e269800a00e8adb8f2ce161395c1c6ad4b406e1fda77bc7f0af07ea075011cee6cc5e7fd1b6e96e321171ca7d28a35595ddf0b0c831d28a88d30c7391c5832d90f906539aa49185fc6c0864e2d10b21160991fc19a1d084006d03fe3fb6f571f1ffd9f06ffbc0c076689373f9c2f8655758f7f44618345a6d5f8edae46e73a09c38157d5c39dd51a47756ea761e6320d6a91a1bb22d8dd35e4e7806b0242bcc4cae8720a953c6f933c0ee3216513cce6742a2cb4bf44553d8eaf175471dbc0f71c7c245fe99ab4240ccac637a16c82f0c60586f00d83ff852af48a239289d8b70a2638b0aff02572d6d2d68e22b87ba93f3db51bb27825265607ba4b6e9a194c7351f220b9e715a23237c40024fb7cfedaf7c8e0a1c4c6aebef8841fcf2609a3dd7f44dfd8895077df41f10790372eac8adff5ea7eeb28e371b4700d5044b41fd358dc4ba29158213e0f93711026fac8abfbe7cd80a939477ce545bc91cd1d32e8f2268563b0fe3e80855777d51cdf4835050a557d3c7b7f6905ba744ae5450d22837d2c2fa0c0755934654a78601a1fe236f11b6d72f368880ed938ff4a2e8d82c118493a1bb9a9ee95cf329f2d175d467aacc2c6cd73ed59ce64d508604db77942f9b7f3b0f86d913d3e1b489d2190a6da1ed997ab1eee356c885270e4e0192acc9c2b8702107c96aed654318bbb7724b913808dd2cfbbf6ace8db9c4cbf26f2c90a76eb967e365c58855b83550819cb5b28ea5e6ec1ea153ad3ee5e6292a174f7cab1b39e852194a6926bdc4d42326e17998cc057f614e91f6acab5a5bbedd93d9a13dc61977aa2accaf35370a3f1d3819c43c9430d0e767e92de96bb225007a7b6576ed7c4f05c984ce2e437d3b7f7f50c270caf90f8e5dbecb992be2972ef8d79c7674e025ee06b1302bcbd57fe5be9d9b4e38f17d9dca898ef3d71918550fd77a15c7aa2b66ee1a2f38b81040f3d6ec6693f54cc3fe39515275849e9e24b0af3e81705dea95e8f1bb1b4665cfdeb0630a5542a2857f2b58c36761d743299d77872d6894302123f4347702572f04d9876191d771e87655c071fbd29338eef0f9acb0a8ca3f0327ead8e875bc2e7ba38f249e6eda1fb74162e972ff523d20c6638b93297d406e9b2264187c06d0a78203d771f2525227d029b27b23192f747492b9774b12b039729ef75d11ce8d701e56fbb202f3e4bd68686f096f13680456529e5f132915595e0e0b4061b3014219f1fbef4d7403dbfcac01c701b7727c2463cb838d427e07706400be4fdd9140a800e47e7ac15a7a8a897187a38a0080726349d8b7566252076b1ae1366496b50e9a6d236837ffa0c4c3e61bb409a7d9faf8662109ef7213007a76a6d94cb79ad07183a33a4cdedd78896278a3b5531ec0efda9d77076d85a63536b426a6b58c3d0e8a46faf0fdf678e4964272e8410b346cc753edb94a61a2f309f8e753ff332f5b15215e0a20ef32e6a6faa044a431764e008e66b4af820bb6afe4d8dc1679219fe7614482517fdc523d4d7ce2bad9d59f7b9aed89b813e5b36b58a7c668e53181c0e1da45e4ba3851b46de8e056d63e440c471fbe23fbffc31ece7cd20658784f2d2fca3f730a1f8a90ea6995ccb490fca475b1441e38468433d1423c1d83a20b04f1216aff13c8e035c2ed389695c2bb0bedadc38c8a6222d687f0235bda3566c0865774bb6098acd674ff9091db1a6c4f0c2955c1759730b361f310d956f892089f500eae0084022e610ca4e758ce2c680d213bd1b5e00a6c991976e93189159bb98a1e4eff14f681d47694060126c0852ad52489c15d7302d82c66aa830208a9fd13da87a2aac3e44dddae632f2e4d56dc768ee6b3622c61e59aee27fee5aa0bfa9c56402ae3525f00634b11381d0b9637ac699e4c4b225c32bef9dc563e87cfc33bf07450c2cdd015bbd94df63697cdd9b6cf4169cfe1f626c126dbb588c57542662d02eeed561946ce94b46571f72ca3cf7fe52a8a6ea24fa216f01655dadbeb0f74e383e522da69db64b368cb155c2ba4c4fc8aea8745b1081223317003f0cd7ae620fc7d9a6c9c4f39a237d5d9d7f3e756c77daeccbd5d06ed28ac2f089db5449340872bc444aa4aecf6552621b84e4fabfd6baf0e1b61cab00e5c2050bfa38899e9840e2dac55c7d5e7105f65dc3afe3c35dd3e8ebb1a013d65fb0b9d76665f3c4eff5b766fbb0c03cc10c411987ef516405296437a91a67d7398d788e30f55bc1e6236b317784504c53800cc07f4eaf78bac03a025a7943573edcc67db3d5d5281f85ee993238fee3580cb846efae33b45ee2ee1ad640b1d068302504521269a31a166435e8fd964d2e15048f299a95ec1cbeb0c8d5d119e24670112d61d56ea120d7bc30fcd924fc7b812404ac45798af3fb590570a4d7a3f41639b879d1bdf2c72c979105460892fb41570cffee716679eb7b4124be188e28ca4c68d206c1cc9d49cd7489d63372853dbe83f874579238ecdd28c0dc265871d6dccf782b571f1004702121e8b15c9d8af9e6812dbbe742812c7e7cd1dafbdbe3d189f618936e270855700be8f6a7b528f271a936a2cae204b44d909ae3f6a8bcbfcda44b430397b1c96187e5a8362afe92bb9afb0a0a482cb6c8cac39a0fb1fe0034f8a965a3be425b4b34f67ff38a8ab30f8219a8933539c1d06d9b2997b6de743c568caea8b269642b8503b546c9e136d0e47775c8fef45d4489e6b4747c6accd6fad3d34fdd6cbafe07264e7ae1e025306c97d77a130093cc8d5ab8e4abe095787183a9084c569168011766b47dade4e3e1353a78f9f3464d8237b7de02da10c7a7b8951bafbaa898003ad9de997c89d8507393c6fb782b8f41aa99d5c92d5ed93e02a2e7550d42f178739898406badb6da850e305c10063b1a687a2b321a1f867ddfc7949d9764493af4f9681137101f87ec3c3733c0ee23a758a69dd5dbfccd20e0e7cc8543c213688ef9cc85bf9c539d3b6758e24befb3c1b617b7d59a17e915bb985df8229429430dd3057a8225d22afc2775e352a2d7c2f2f46786d4e6e984fb35ac6d7e1b57da82a6d1470895e56521c88c166f8124a4f0c5ada7d5e43174e319c21b9416735858ab50958def63c9a38e853d28a0f47b8e601beb0cdfb30d87070003f957ae347d5b03e80890311ded8018de0227c430f29ff20f0d0d1331dd5f22cff547847c0a26c1fdc272cd234b668823635f68e0797bf68fb1e531a423b1fae9b056fb8c0589908cd2774a7bea8da465248a438a22919d35e0ed8c5020f06824aa856c1a75e0d50d8e9c2dca471d249a97e8e8055d0927432577ef07e6658aa6ab3e9f5f4f50848b12dcdcd9594dae732864f9c6253cccf39922b5f1f8e16458a0c11db397017821de73a331400a76c2a5a29c7661405e9f244a92862a8ca13bc86a78a36744e52019c067573574f75e01b21c36e19a714e9cc0860e9df8e659cefab57002dc2b3d1a2918dc20ff25bc0d87023813abcbbe29defa514bd71fedf314a140508c7e8dd4ace82d56cfd6307fc8299a65c8b3b0719881dc06070d670729902ebfa1dc0b88050e5824cc186454ec2727d0fb2f95eb677f949375a0a31661c7f2bc452426a052b160b0654bffae35766a5317b845582176f1ec52e5bb7d814651781e268cfaefcf6da560810d84343dab8a8b2f2f7976334043498f529d75f9dec893bafdde0ebf003ea7d43f22d8e4eb3afea7be8bd22a9adb9334db2d6b05b8bfe72a96ca2c5ecc925333e4076bf5b7d9ed519ac3eb87c73d0c8121b1034424991561eccb669807a722bcd43141915c9db90f7a8a8e732054970645da1845b988f21cd5d2a89abd8e14c0e6532a3db89e43571b795d6f475b11c16cd7253a4538f4e73d0e3791e0c8f3e51ce3d9645062f249549d9165185fe6920659fe72ae01f69c6d5cef5a01cbbce0fcfd671e1a0aac35d541210a723d2fde91f37c130657d8825662bc46ca7780e07422ce2e7e5cbc1b15ad29b8473ffb832f45c480e960d620267561b3e3112c54359459c3f0235eb6eb2720dd5cf65f88267e099ae87ec7e35b3a915f18a4ab67583ccb4d907637812d797dfa51acc7b5cb13ab58934217a562b00a4a3d030bd9d3565a47c95396034bd65d39d39a6e7795f13e5031d148db16eddba996e1e70730eee02c47bd8b5c42812a12a2db5490fc3ad50d7d03c72c0e933ed8b43f8e34124e272cb39e06e628f18acfe4488dcced67a2c47008801e8d2db5dc7f7556d38020d53512993f3efeb4b07fd1e7b631deeeda74983011ca401ec7b86eb2a7a4d341f97337d37ada0dbbe124fe481ecac3e9b8e8f3b8b90ccf81ec028f2ee4e62934abcfcc2647966f6eea6563a0fc8fc75348f5fb3d2390db24d49858bbca822217fa81d240cacb7b2f6c2e4bad8a7a112b83a5d35ad68ec1cd599afee41fd4e860097f33afbc2cd790b2933f1194549c5aa3fe5c651a456c8ba7c8fa5ee5492233c21a80bd9216fcfccc03ecb76af3849711a0f69d5a261ce94484c30f4b74ca6cb4d7d5c4dcc0be1f0390c208e1e7e863700c6dce7ea5ab3831c00e586094a6a1f3b32dfbbf99a7581f90001dd558738804d0663a59d77407b6ab1ef3a82c156bc58d5a694a365b300a90ebbcddc49bbe5ba63c88e7a6e0faf5364ea17cabc602ddbf87a4c2f55b068ef296be5bb66befc1e37ad77f8e97c08f02d17dcdeb47959b0f46c2ae2c3d99a948f2a52c5793d53fe57876c38336a74786042abafb63c2154096eaed98598aed76da5a17ae179e79f848b237bdd6db63e5fbe77ee28b2bdcae462905ce1827800407317c2a42fc0dc234b2183db9097c0fae23da91aca6b1b7894537b0dc8524536573a34ef68596021cba863ece0de4a068f806d888aa03ed88ad92f375860f8885c5533c637a7a330c24aa0357f007ac3678e59cb1f6aa7c6979e15fd107a98ab42a635a3c3e70b58a19ec73b4bdc482000c3dfb4af84012ea3957d3d30b80857d9e06a2e677c84e5d9041ad4bf22afbdf0351f6d5c7a7a2ada3dd5ab4e48e37d51e5fad56cf9963715438c5f04b9772773893a59e2e46c6b7e19e9001650b66b469f4b1c4d188b286d5ce8b21269179e772147c7cb09eaee9b9de684ffc33068e5d346e79b710d82fd1278aee64ddd4ed37a944e6c745217c6a626444aa95b565c1f68a12cd2b86a61927896884bd5a76a9df4f6fe548bc16444272ec1e856334d64e0f32ba90daa77085b0683e3e010abf571dc564fc703a12998c72b6712386cfa4ccc802c850a3604bb0b2d5cd2eb6e788d475ff198f94a220c925a32ab6d69b037f1b9f0f4ce1d1b89cc0d").unwrap()).unwrap();
        assert_eq!(tx, expected);
    }

    #[test]
    fn test_finalize_psbt() {
        let mut psbt: Psbt = deserialize(&Vec::<u8>::from_hex("70736574ff01020402000000010401020105010401fb04020000000001017a0bab8c49f1fce77440be124c72ce22bb23b58c6f52baf4cdde1f656056cd6b96440980610bc88e4ab656c2e5ff6fe6c6a39967a1c0d386682240c5ff039148dc335d03b636cc4beba2967c418a9443e161cd0ac77bec5e44c4bf98e72fc28857abca331600142d2186719dc0c245e7b4a30f17834f371ca7377c22020334c307ad8142e7c8a6bf1ad3552b12fbb860885ea7f2d76c1f49f93a7c4bbbe7473044022040d1802d6e10da4c27f05eff807550e614b3d2fa20c663dbf1ebf162d3952689022001f477c953b7c543bce877e3297fccb00ef5dba21d427e79c8bfb8522713309801010e20cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae010f04000000000001017a0b90df52169792d13db9b7d074d091aaa3e83aff261b1cc19d291441b62e7a03190899a91403ca5cd8bded09945bc99c2f980fd27601cada66833a5f4bc108baf63902e8bed2778bf381d17241be029f228664c7d1522ced55379e275b83fe805b370216001403bb7619d51d2af2c5538d3908ead081a7ef2b2b220203df8f51c053ba0dfb443cce9793b6dc3339ffb0ce97af4792dade3aae1eb890f6473044022017c696503f5e1539fe5cb8dd05f793bd3b6e39f193028a7299a80c94c817a02d022007889009088f46cd9d9f4d137815704170410f53d503b68c1e020292a85b93fa01010e20cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae010f04010000000007fc0470736574012108a337e7e0ecf24c121a17193623254c277a306e9fd39cd5aaf8b7d374f4011c6507fc047073657403210b8e11e3b8904ac80caeb16af1c93053f8a11a963269bcefa96823d75b8640ae940104220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d9307fc047073657404fd4e1060330000000000000001efdfbc0022a6437ec10c672d76c513868f403f6b9706e09733d6624e3cda831c2c199dd4c5763054a1c219e079e8cf3ce0c00dc2f16516972e1e64d576adfd9f5d778675c8a3172450a4cc82d6e6c59f2b16dffddc902d0aaa647b750d6224cafca7239a4fa81219cf2ee89741ffc5b7dd7e47d332ca931cffb1d1d432935a6013207629118c965b7a5102e62c43ca9d06bca191307a476738548536809ff6b01c6b5b25d76ff2f67d99e20fdf7d2eff6fc248186d21d054196023c5e4f572ccf0f3aad8728c46f2ff6756ea39de46028610a3d26cd42978b09e0e29e0a8aa46e4fd39d28d028592560264cf1a794c27f6c95d382f486dfe900a81d9d92935c7e0e6306549b3e49b1f60182512ccb994338c3541a2956139b2ccb3dd156853105abf5fb394cb2c45915dfd4106c7472dc5d360ab5bca408203a3fef58b4dd33b0c11c367dde2f19c8af7682be067244bf49a2b8cd4685f5481cc31ba27fe2f3d7b7a353be9b41e4eee2342fd70b8408c91951c71c75dde8fbc03e3f28e6d3d3b41e0e963d3ba0c25b2eb50560c21221950b0699d2615f0128e6cb7fa1b04ac1a046e569a7e87df98c14360b8ffc43db5e17548c7ea5056f84ffd14f4cdfc68a4f10e9b391cfa63eef2c2d623e7cdcdfae2fc4d63496d81462174ff360809b7e3b4305979d9cb8e9ad5b0f012494d31ce51ee6489555b09dddb16641ed9e2534fc34db99d2a4fa736eeabacf2f8cdca97f9e84c964277c6f30f1af7fe2b51b39b487d56ebaf593a3f98e811cb09849c5b445d5b7c9ba37807bd0189c8bdb2709fa70c230f9aba41dd3c62384aea6e1ca098ffec26367aa65a09459fca074d1da0365cf7fc2d8310ae099b838ca78e62cee10f95ec549faac1ff0f8236fb8cf2c0f6654e471d3950ef45e0159c44f9e343d05b3af59b939cf76090d040376407c41661eeda7d2cb61cad0088a286948787dae0cc5abdcb97f7f42026c65a13e1df1357c25d376955942adc858e73876e1d8812969055d55decac9a689dcd11dffe5cf6e06088b93a11e153ffed104266bba472cebffb2b0cfc8ef132309bd7836071d3b6ed459a5950c64cccf230015c98f9210f2d57b7f3a07c382f3df09f055c88e1f312db0d60d471afdc0b780d319a6229babd8f45edecff8d1073fa850f755219a3ea14e7234cbc7590c60eba0ba0cc1afde6ce91c8e8835b1ca809926b3e7d8d7a0941425e5f08e884f12693eeea1b3651f53da90972aaa37d426f37db3edae4285db114cbad5964c269e03b15358ad2a7242e0af538a594fc779ec3c43c3d94fab2028310c6d0acf3efdf0acf028ee757c5c02bb5b8b691aa5eed1a62acbabd0d61faa478cdcd54c6db2cec6144d8d1185115097a7da79c16ad3118d12e36dbcb7a70b0ddb27bddfcb1c6e5426b7e411f607d22c3ac2b8d3e41f55faf5e2105bf3b943846cc4c33edc64f902c1eeda09c8110d4f3ed0a5e511156a3e368f02161b92126abf649341ddb8ed03d1d41b91fc34548c6d94dfb47c088ef27a3cbfe1c9cb05f2ab2f18b8746394c8080c4cd92e818e46f861614ab870cb7ae3446e376793f3a6568a2ccfc2ab0ed0365567671436fee6cf427b6410a046d80b9d88f094924ad370da363e8eb70355b711687e92d88a08ed811ff241c7a6dbbad9dcfc18e6a42493483b938e36c1edd2a1c6e078a17c5d145c9c058b4dd69afc44c345f1c88afb95c1deb5c4994161ba25783165d43b9e50a2d8333a8037cec2ae809a3dbe026d6ba40d60badd05bce73b0f9f36966c30b9c0cb5776544c1182024a96e746a3b01f9db10b45aaffd3b055b02b40bccd41e57c10719bedb0fba99a0f6b0868b186fca0397ab8c219f33190f81e4cce2fbcbc0975c394919c98fdfd7e25a33e5f31fefd06c8dc409cbd3e743f0f48dc90abe45b2e68948436caa37fe9932a77b7e0fe0819d8283964b0eee2249d9190f3eb0bb8178e10a287be1059f35cc1a153dda14def65f3c49cdc5186da86bd3e965446f914e3c9b4cbfcfd2c379f306c5ef8844c4fd398b3c6f96601e90d2dc8810875663939f63abe3ee2e1c8a9c2c2010a01d0dcaebb556a7c98421f8e6465cb0434c07dcea9db1a142f9684e50b06c545785f0dee4def1257e4bb22d87a2b37ca9eb53081eb8f1ea0439c4575abac435868a36552df569ccc63477594ccf7eadfed6adbb8e81800a2e2fdd7effdd1e2f09cf76c9e780f6f8eb8408a3fcc06cb8bcd28db7a37edb0232a6f0e509c684318f179d0c91a97718ce3956c266790361ea3a1bf70cdb8a2f2a59b06dee18075745c7302db9b13a452c188c5624964af2d5d4bbb1138dec59df5dfb077a0f62ac4db3de81f54365f2a4a6dee63a6092b4660d3f5dca3cc8de3bb5350f5dcebabd515c72c9114bc58d96e2e863106f0982c2632bbacf2fe5cf6a8df880c550f7008fd09227baff82d4eb031802fbe7d50f6174860c70fcd9f0356e34c0d45df66492dc309b260b7158adf678e2da66348ca84de3e721c6196e0c717f59cb802c6866defdd9032a4b7da82b816d9681e5eb9115fc2a572fbbe105f479ab339bfa5961aa1920346c9ae4185a74aa828da78a71e55876c657249e83f5812cfb055400da1db8bbb5ed3ce2ca4655b0c39b698ed7d235fb0ed4f29a7e8925cb873176efcd1c6981dd23865468c6e01ddf61fa3e40d6fed18d8e3dbd97a08c68bfb092e441e512d44089cf563509785dd58203949a1ca9b66a700db14060a760aa404e5e9f31eaac015f1527f6d760d8714c88040b87fc8a4d183230cfae35326947e28a7a37eefe1d77070f5232a0d67e278a45d649709a7398cbd43094c5001263671517f83e62e79fb75e6f9bc592fb3bbececa3f597dee71dda0fc909079ea49d81554d2fd79d1cf3cf25d1186efb83cf972b7426600d7d6eb6c48a5f0e26af640c733f3f771e0926e6b38b6f39d7882b0538dcf281d92a6bd361bb32e16f3988d6790fa0a45f549e983f4eb68ce5ff11647b37f8e4c444aae8bc0f7c49ce7215545a29215b55f37dc42aa6add6fd1fb45d9ae580434097e7a8686e23cdbdbf6f8b6b1e5579a7908bafd8878b004c7c94e045fdf2b94f8c1a75ccee7bfabd9bb6d0ea8a60dca61053636160c19f8f3fff3d0330fc95d20a1393629f33f281e5da80a5ff66aaa5eefcf495f8bf7e24744778841d7c633f01af2305a122ee093837998e87f060105ffbc083c0d71f68c2c63820d7a547d9af5618544efb9736af56736e73cb696f191c68970ea1deb587231c889672b3b5399b9b5e915e3c567474c3905ec5b6468da826f1a6438ec335da847db540a091ab311c6846f96a2f17befa2f29ea491a41d7630e42583ad1212e6c606dc258a49f756e2480f90775c04c5c533300e37f8bc7afe7b155fb95877252ce4a53f78491ebf9d8a4aa41da1848633816542901d56e66f126316c80efdaf4b457f9ce771edb012a0b3c27c717f5cb3cc99ffcc959a02289e30d5b1ff936320579c469bd55cba6e79a0c5f1bda59981b71840a8c1ca56863e91eb21fbaf84525d5f04e0f282d03bb56d6dc2352f163d8357b86bc6e4e621bb693db3565eb9ef5629af537874c1cb3459582463362dab3c6fed7e574ce9bffcc685b8eea61599292cc69860c4f9584818182f94d719dcc463e9a6f854405ca2deb3de29ffa1826f795b7e7ac2555c0ee576c75494cb832c59de8d9620927167bc136549b731ef79a39fbf8789831cc003a772fa00d4d699d089d47037e12e1c6eb8c20c5535225a33a1a787ba866ad481e9a4d689c83d75f1986405c82154e312ce8b3494ac5721b96193c025bb75b2cc974f9171297da058d2ed4f00d94e60737af29da660fc51fb9bb4d241e78c9d1815d7e3ea90aa541c4c512ab423ece93f9ff2f479f464b953b4171217b758b280c5d8acda32cced7bb0c92cd9b405afb3a8405602da914e1831fec5b6a291f90635afe82b9389a8b41d957f81be125de2f943b7cda9e873fcd74b446bacc00bdfcbe643053f6cc8162c0a98343242b489f59f7ebac016a7fbf620dafc15c8ecfe20b954153dba19eb81087673a1e847238864036e9a300239a00a5a03d8b39aae2bc201c04c477b1f2a37552670c06ea65551c5c88a42476d0d797af494b077737cb48050bd35f4980964b8b9b98bde84615e8fdca407230f5d15e97ae65d63a96f3d88518fde12d6a82881db5c8d4cd79e724312e88b394129de3569c5c99bf842a90f193c91fa55a82116e237c877dec2da6dc652cb33e33df47420c5238fb6ba5fd96cb77f0cf6c8a12be1a95186680d16a064d9b1a7c2461fdf5e0a512a5a3ed2f8dc0eeadb6c95a658aa1c2713fea473de51f65b13a40a2fe64e5227bc9248f59c2bd60dd2fc14918e333faab6e792ce2f0597be47cee70f5a8b788a50c9cd153bf24786aa80f631ad21926e3285f41c5125a15c12cc889112df0b1857020160122c2595ab3359bcab184ecb32f7cf8f38eea23f4f9135104629d8f1e8273c44f8afa129d3a74cf58ce494214629cd53b99a8489ddc5d339e317ce75dd6c5dbd098d811c56ec5f19c00fa00b5465e39f8f2022c71ab3ed0d5a24058c197719551985ab30a851390ab5e11420c521b1398bff0038d904e5879db37d60c623a0a82e191cd0b6bd20a9e956d41d5daef703bdedd6bd0e20fb096423dd39706e939e796aa8bdf071e44791d2e1ed4a81ffd018cb79c5b6bdfd6297cc6cd379845fd7ddfdb0b83d7b26c21e3edb58185e71472a79cb65322579bd5e0e7b1fe081dcae5447834d70459f8a96b341a26d8922a2b1412f95f3533e04b5f65be112cca03ca45ee0eca10adc7593c78c041281c880d879125e585e68f5c7fbf8686f245cd736ab5aadc57c032c637b753b49575acf4bbff46883382f408417438d7817097accae3fc54afc6015b84b3b05627d7c83c4627c87727bd24c4b4d96a08c64164ab8d4abe3fff5c3b09e8fd12498e3cc3627e799e4ef72a870cd89598d51ba396655b4de66e48997faa51d05d581c52f52852cffc9f89252f26d314d2fb8fcbce197f3a8f330339c2ec3c710710b74f0915da3bbb638b1f1a0cb0c176adc151da0ab52796d466b23e8a269c5b22b76fe7586cbc217621acc955a43571dc04f69deb50066cc587595cf0ca4e9a00a261ff2791ada8de04bcbbea249d2a7840bd8fd3ef98a248eacb7fea5318b2e207668e13ab4e5578c03315d44b478df5247d8afd0624d2a57adf85fd16d86ae54cca21f6c91d8cafb3b31e3f9c4e903c04f39d67c90560dd10b2d28c6ee937cae01e921c98ddd833a9b9247053110c0f29d2f35f8ea322a738636f17648b627db622a9cc891fc1d066d5fcabc168f1b492479b0578d0bd8de0298d4bb96a4351714a10a39de49d57ad66bd6b458ae0d799a19da54bf620c0e6979a95b61a83cd06e46d7d263d53d66f77557232983268f5fd01d10442af0c840ab09c6cc4ad77add6379eeaf98f7cdbd70fffcb035abae4efecdb7e6f63ed8acebd8449b3a910e5eb06b0ee6d80dd45026c9e6c2f978f813b2800386a4d7ad9d127d76c4286c1b2facccfd16e6a263ba3e2893ae5e42049d421e08a62ee9e9574a1f70f0add7b68344256592513cc15f4bc64c5a029f60d617c245c1c34d06c095b2d0a9647e65dadb33ea79e3e0ea62ce55347d24eaab7cf9fc33fd70c07363771f78a13d92941daf7970c97b43d2fbe3e789a52ae7bed64736e6ce59f95322d20f9d6dc00b5824a0ce9072dd051c66ac20d39bd953f567a831d75fa91fb4d49b200fc893489e60df95c2810f7fc57b7f6b7725ae600e1c2def6a943b8d111ff3e9a5ac80aa981fad8709e98ee1550005bb8f65dedffbfe3793abb407fc0470736574056302000359a33e8f3d0439eb7d60aa79255858269bc1011e4cd0d4aa753bc2793f9638fe70dda4a99191f08700047a8b66d9cf7a53bf70756013c8630419e3a0bf428158dd02ab6e16822f239df0a6f1b67b6e1335509a286b30c4b11a22dcea9f95d51307fc04707365740721027fa518c54bb326d5ce3da5c2eb8a6521ab99df86b511477d0f5ebcd616f063ac0007fc04707365740121081271c10f0caf52a40e015e7d35966dbad39525a6c0691d4beeb3bfb22af5304d07fc047073657403210b85bd6dc21b4919f6ebda7ab86ac8122c793be3fad19e44455945ddec8b59e9f6010422002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84507fc047073657404fd4e1060330000000000000001cb6f1101e2b960c9a2fe480eb88fc76c63e58b57445c78d88e04f740580a36d6956006ef12ba606aaca89796dad5ff7cb4c4c7f4e65a07fea8a2ce3b58b265d4b3220013a09ecf4e01023aabca5586d61ecd5d7f2bedceb8b18a8e41451c97a192098b196add06a8a6b619e1e731fd9ae2973741aff6358c1ad45cc873a2d497271e3a20873a6f701d4c44ef670c8c7a9793079d9bdfe956bdc02a52d1de8b2de58b0f7d309240999f13985fa8c98e57fe1bb75219ae6330e9495b523e891dba7885a5302817d68a9891ae0c2597d4d7833b91b073c4f9b27be1cf81ca1c2c1014c57a4affe7b402c0e0c1862bd17bc1d43428671a106c26cab61d5e4ffd1c01f6af1c6e97f7a25ae8aaa8d2c91c57881df52bd5f242b127ec7aed5880101caa01783884dfe943ec9764473323f59b27a204f34aa1fe7fd4433fa606608b0f253247d149e3e269ae5445e917390be83d5650c05859e3a817a6c7e561e2b12baf6d4ca4221df0b7f29fa134269139afd9cee5c7d60149dfa23031705c6a8b72d00d659d7a085de8330de2e5c168ee3eba2180a9319f5e8e0806dadaf0fffbc2df839571360b8cd32300504a527cf914da7a1e788261c9cca2872ebec5a17cad33b15a7a7427c200b8746761359194520f0da1d7ae03f26190d07cf92d515e04815f514c66a98997320a028ad24e83182f213d991accf19a8a59003a2ca666ca505c0d8349e2cb22887efb7db9e4a4e3e2d8da0d5f032603e03f48fb967fd018fc99c6eb72acee4178edeb48703903a89e9462a2d1f447234c3373fff8b205848c7a9d6e45ccc31eeeb0105ed3af1188fb847cf6f03a7f0a646fa325b672796168dbbd9d1d19b2f41685b18c3c96f1cfb7ecb1dea132e8815b62647820ac4b12597d8e737a01a970704b03ba5ae68f8d64a1810db10427fbff1d74cfac91561484cfc8d3b23f74ba0f37e7db2f942c58fb1dd30f6a50c57b5eae720c6ed69b0fb81a6e0260c53028c732a544391e319987a24548230378f8f1ddf65a2d654c7b26951d5c6546cc8fda6003228e8913c9e3c5adf7b7b72f4ff5c4aedba6096097f9a4b58ea1e060609e8d1f0fb0e5dd905b29fec72b118d40c5f599a63f9a37041742a7f1af3ef951c31833621842ec212f9fc5cd3e8c08278ea192f8032ade447d2f35ab59810aff371f598b7dd57b3cde2ad854ecad0c786150748ac241ecd67cb868663a6fcbe9d68c3dc221d4fcec9b0ad89c337c1e10b91a38ab1357f260ca3a084da536e56262973e6c6cca838601fb2f335811375aed78295c4b17d3798d39d4cbf6254ce57680a102907e5c08b5c7ec0a1e73bf3d7b8babdc6156c6ca3f09c0423d6716ff4e6ee0338cfd778158202b5ffb60b74558dc6d0be9b5aed6892c4e0ad3e20de5b604b2b010af09ceaba7c0fba5a7fed39d31cb2769909a251ba5b0668330f734728f5c6786a8f1a35df77f3d739eec71d9268fb2a494a14bf7ab91c075023e76856d1745f5813d83878822934d0b4cc0538048c3f96cad7aef2bbc49bab139915dd4998ed3c6701973eb7913530b14c688f0b344ca9cb990de2a9b12fa7ad8b292234a33428b4d16813693964365bd412fb936c1461fdf8dfb0bba31202685f29addf95fc65f841e97042bc5d82f103e41017c6ac91d3d266e12db2dc195ac4f6d4353924270c7144cd96dcd07b9612e2bf1e0f7fc46ef83690648395c575a13c2b2df0fa04f740340e6b116b0866a401de22f68fa3f621d75b9f5f625cd5d5d7e12a5b0ff795749d742eb2648ddf068a451059390da566b3de84f9d528b2663de7dcc562eb014071e8277a054783d322fa67b9e5261b87e9c354ff58fc52bf9df404139311d6bf9650658fc94835a6220ca02a4bfbf46b2af4f30b1ba681c0de7c134d98dd52eb1e937c191cc9557aa73a343b99ae0b8954a3e929174984b574da75e90a9b71af1215317b04e4090770ab596091fc05c82235a324f86280f7fa081360ac758c1980c6a6763453e6b344611e46b05760941f9517ceb298ed7a2d6f96b11f5719ed0dec803c511dadb8d056d4ca06ca0ad090558a4fbf3a886f3ea9c33e1bb4bb5ddef4798cdfb384bea75a3794c42a53af60f12c95fe9b38d7f6a5d914ef100508091fc84756b596b9ba08d1dc42a7e253435b5481d1470ef00a1172cb036b5bdfaccaee02b15d099da17f9753846226325232e71ed9b48f57697bb3d1db75ed214310e6e3608ded6f188e37b21b96eefaa396db0df05a86416fe64aa950eea87e7af4407c828a8822b17be661269c9f9e365cdc79d20503e2d5e575c5387fa961206118dd379834aade7727a1b2477a24f05f6c2ba3156fe7f5b5ba6d7487b1a124f38e3ed3cda92a8edf05f28e3d699f0c12de9cfeb30ec8d4cd253287a6d3f596db0c06006a531e80083f5b41ee26c05d529e0a59ec151b4a9260a7ea8c1a175ca41b59f464adc122f448fc43e90dfa7b88f81caa7a84e3d6d4dbb85e5828b6ae7455dc2c87c8d9c706af2e62763675851b4ca449c9c0f95d953ce53c5327ba8981321a1cbfb76bafac7fa17c99567725d8e0ac288f3ccd3bad666e515156517281c97a3dbfbd5f345f8eb80bb3c4230301a38b7c920d74eb910d380f884a683f7d3e2738fabf9646138e8a32c35e43786e67925508e4cc7b1e7a36abdf6a497077704e216f1e730c20ecfcddfbdf2484d8eb0ef9b7478f77063fa90b8afbcd019d1a584df58c537b40b193f246598ae4c53958a947dd3916b14a5a4227f01bf543a8c5d6ab8eaefdfb959c8715b756a9c797fe39229dc56a86364cb367fa37e16e96cf8dca1fdc8b6a46ce88e3d29c75b6cc718ca8c28e9e1ae991b28c286107c1dced150814d6369cc8003b2976018941df7fb8eeb68be57adcf8a0e813d2fcd16dc390ce17dd0a91dd674d766d21b5de7f4678a548d75cc3de7d099b418fbdb66b2a2b12a56b1dd8b3f84a7b45e36db9bb63b3ef9fdadebc21c6a75364173925ffc69d481024e49076dca105795e7a64a3c82011889aacf0114a1bd31414e288cbb63eb47d399d0e025a54f11670c8ad4a793d0e7ebd3b0d8eb30b87cf62b131c61a4c55d2e56e47ae99fc543c57a1877ce44dac4c6f9fd99552701ade43858e0b4020230cb4d42d1990bfb509471a5c1c5557c29c00072c5cbbc056de6d465ea2ba2f4a1a5dd604dbf998e834b9200c59fdf90bec38af9218e47ea5ed5512cf8b0146126a15d49bf915eb893ad1ef83d8faf6c93f944ebce3704f930b6f69a1afe767ac2c9fdf092c804c7372ae1a64bca3a3b5a31f2ad430ba9e61dab3daa3be90a538cf0fba00796de511cddb5a594f14aa6d215bd0be19c0ca5f043403b7dc56c87b092d9436eb79509c3dbe367c2fcbc2b09f9818cf5a55d5ee0e477888166bbfece661b62812ffed3e4167ecc81dba148f89a8f2e7c27424a2ee091ac487e68fbbf9798e8caf46b35de8dde66a7cad6dc98a426ea7b8b930cf2d7d71fe71066dbe51e8a1c7151e97fecbeedef3d6f8e01cd5576dd58097b46153f9c3bcecf30bc82b4cdfb1bbfa826c7c5b217a023e4da02a35d0947b2c4d24d50a292e4c70fe854a420c54490d4850ee8c372756671fe130532f89878a64977ead60bf604b73859ae64ed62536423bb51b30c6fedbc819fdae05cb64b87b153f4252b832d6b866100a7b307d1e705643f96f0724858e6211802b2ce706d5424b99315db90c7d74fac66951251f6cb739ea008f839c7f62318f795337ca4ff05886a2640819873ae00b933081b64da1101d1b17451357921a2f4d4dc86c92a5eb346fd6cd3a63315768b94b90a15162aec91cea706b9221330db154d1fd71acac90be47055c725bce38710f1b4b4144f331cfa9fe15ebf6535747669e4aa1f0d72092ef395f16a4ec9014029b5c9d1b4bed9ec81a7568f8f1c87e0ce0f4ef9cf49e3fe4960b0b7904614772c63147f3c5463fffed182919c4973a8256346116be40b10a38cdea5bad5878760daaeda57476e86ec65e58030bc8ff99ebf017e9bf6383f981edc83b538e2bf4bb573637e6f4717d74a3ac71f5e151259b29c1b7226e3a8ab176baa2f27e3e385cd48c6f072bb6e8e9c92e35d7ff51177f4e3553555d967c04befc1847003a8592738c82eef231ce3d372372a19a01b27dc7916f986ff3f3ea8872d4986bc1ca649a92924c8f582ae2b44028e711e955d2563c33db3b7734aa246de553dab2c5268538f7c2b6dbe9a70657e2a26e52f5d216dfa9aa8e197a227c86a7d3b468880a721b804a0c51af1592043eee7fe3657b40c1832a858cfb4e037d208ee69c4fd697b929383a971b2a0864544505af2267e334db5f3f3f4ed88e2f6f2b3d7b96016ff92a120556e4d1e50440943893b00508c6242bcc41b6d06dc29ba20564b42257b9fa1b5f4f453e94e72501d31e8947e09a38261020400db4b8cf675b1854639a962a57905cbbee14ea0daa9bd281fd635c8f900fcabdcbcfb140f4f24b47731782ca899284fadfc9d0d6eff77045792e139afad34c7672bacfa22d85fcc05652178cc169bcf52ee3cef281d99935abf9c9910caa7994cfe33b9319d9854aa6e2590a86297f23b0cada7251a6ee1b2f3d2cb5a193cae8768d92f556994e416d4bcf5bba3a295d9e2215291237df74e3c493189bc5a27b3fec3e1a1329c6c6c75e0802b40fc74776476dd2d9e3453ec1709a8a2d162a936d9fe7dd4b6f7abdadfa429aed4cbd5896cfb24a2d91f1cee781d0ed73cf7306d6f9545fd3346c2232b8799553357a5a531d6085d04af5f183019dfd3483baf23b0ba5a6b58bba4b7a1eb0a32626bebb5cc0c4dad45c55d135be8b0a4dee787ed48b90a2a3fc120a753b52290c27ad0eb32b668a9540986ca0256c1676debc4d19b1b80bedd81e505154264a199ef1a54e1fff1b3589fbb6b2d87a1e04e67066571b68fe04f030d473f8d135585f8b7be91f0ae1a4fa2f44008c0f727f6aba9c5c60c3a9ff22911e267ffa2a5d1c71ff25f96ad257be29a2ec641e2055d785765cadd0c2fe513c44154e74f4b8cc4b24d9ee2f6cfe245549713f9dada1935247a2ac7ccc13c4a5c00c6ffe7ca33c0cde4c75c4fe2ea041a965e4c7385ebfdbc348da8c4216a02fa829892c827adbcbb87745120667cdc5a4aef28b190a54b422df45b8547c447765838dbf9f05de338ab672706b59b2f0644d6735d9316e64a1a15d3dfad893bb1bbcbe1b574a0b8ef5265e195a929148cc5e97c8bfb032d4528b523b6a6b29209428f38115cd102e3b4e268333e490140964278238e7ea9638ac34559e05300dad0c3f18e9228474cd3a7186102967c33fc14f086b4f1ec3957d87f2609d140dbb9e7ff793101d1cb90d004565c6a32924715b1bcab483e6389e2e824054edef350f328870f16412aca0fee39edcbd02a6a667aaaeabb6654c4762c639a26286a3c1730ab75defcd9451b4377f6acdc3b905684658c0844d904c47d313d85eb54963fd71a9a76dc8e345e479004f00e446b886ec41cf7bbb9311463e877aa4e357a0dd0b185a5cf12244296f5f8568e84cf6ac3b6125db6897e4e7c183cafc04f61b3263456f61a7880b446e3cffe986c3bf027c7deba490ec8544d2627e6596ef8f8a5cb577796e7c36ffc4f4346263b5d86ae1d7b8d04709367349d590047a8bfb34fbf6481adce60eddfdd1e148ab83874d70b5303fa0ce60c0ba7a047a477dc4c513d2218b0bb2bdf9b60be9a39e928976464e333ce0cb19aa21fda1c6851c6db9d5bbc6552e080f8e448637af711fed92e72c8d8530187de94603377dc387041a9eb42ac70b3923b9828de33bb337d55409cb419bf4089cb2bec79ffc3afc6dcc3cb82bc903d956d28e307fc0470736574056302000318eb22887126df9062243038440ef3fca2aa024fff8739db4930b314822b00cab172e83c33b7e5b959b0c3f27c714e447120833ef69bd634d1e011fc3c2585beaa882a29c2dabddfd31a48c0255d1ab57c6796aa4625a546a02cef51a9ee2e8007fc047073657407210302e71fc2fff37aeb6d2e2a7b7f2308d4ab7d4bf0a4cf9be7c06e89a66442b48300010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104000007fc047073657401210970cb1dff96101101e24bed1a66fb0794d2fcb26aba11e7f2393edc1534df8a9607fc047073657403210b9991881df2ec384ff5616f6c03d45cf033ee64536297c3557f9fffec716c1fbe0104220020cd4ed5f0db8c450e8b0be595b6410c1759c19f1f6926279095c83dade9862b6d07fc047073657404fd4e10603300000000000000018b6d2d00790f618171a9e8eb6051fc14dc27c502a54f5ccecacb4bcb350581a8f4b1a887a1e58865a21f51ef5098400c115cca84f489637718d8c3ca4350ad677374d40d2b64fe949ca34bd4ba845a87c7693421b70aa8d852e021aee329762883b9820bc0a47ea2fc6a8411ef773703632849094e51c73997c67f3e922d2801b6abc445375cd963a62c2bb28d733bf9274fe503081b51a56023a94200743e7d38865c190331449d19bf3d4eb7bf0b2a9b90696484aab906b9470e10946744838fc428f88461864d6601e93f10909e049a315fcc0ea7f4d71507fe5ed19b9ac2f55b0d3902b153ee27da9c55ab66debfb5ca440dfbb1a600cd8875049c4c13bbf242d26b10035002c7859f9c3ea631d955914adfa0817e4801e85b3f250cd9e7523db62c4ecb17a49028a02a1b61eb96a410643f1fec0ac664d96f99a1db4ac335c2bfec2946707c3c779a56373db197039af9a903e833af6f51de5cf8fc667dbf5416845d415dc98641e0984ebdfab88bbcdf305f605d36f7a472a516206d7ec722251e269800a00e8adb8f2ce161395c1c6ad4b406e1fda77bc7f0af07ea075011cee6cc5e7fd1b6e96e321171ca7d28a35595ddf0b0c831d28a88d30c7391c5832d90f906539aa49185fc6c0864e2d10b21160991fc19a1d084006d03fe3fb6f571f1ffd9f06ffbc0c076689373f9c2f8655758f7f44618345a6d5f8edae46e73a09c38157d5c39dd51a47756ea761e6320d6a91a1bb22d8dd35e4e7806b0242bcc4cae8720a953c6f933c0ee3216513cce6742a2cb4bf44553d8eaf175471dbc0f71c7c245fe99ab4240ccac637a16c82f0c60586f00d83ff852af48a239289d8b70a2638b0aff02572d6d2d68e22b87ba93f3db51bb27825265607ba4b6e9a194c7351f220b9e715a23237c40024fb7cfedaf7c8e0a1c4c6aebef8841fcf2609a3dd7f44dfd8895077df41f10790372eac8adff5ea7eeb28e371b4700d5044b41fd358dc4ba29158213e0f93711026fac8abfbe7cd80a939477ce545bc91cd1d32e8f2268563b0fe3e80855777d51cdf4835050a557d3c7b7f6905ba744ae5450d22837d2c2fa0c0755934654a78601a1fe236f11b6d72f368880ed938ff4a2e8d82c118493a1bb9a9ee95cf329f2d175d467aacc2c6cd73ed59ce64d508604db77942f9b7f3b0f86d913d3e1b489d2190a6da1ed997ab1eee356c885270e4e0192acc9c2b8702107c96aed654318bbb7724b913808dd2cfbbf6ace8db9c4cbf26f2c90a76eb967e365c58855b83550819cb5b28ea5e6ec1ea153ad3ee5e6292a174f7cab1b39e852194a6926bdc4d42326e17998cc057f614e91f6acab5a5bbedd93d9a13dc61977aa2accaf35370a3f1d3819c43c9430d0e767e92de96bb225007a7b6576ed7c4f05c984ce2e437d3b7f7f50c270caf90f8e5dbecb992be2972ef8d79c7674e025ee06b1302bcbd57fe5be9d9b4e38f17d9dca898ef3d71918550fd77a15c7aa2b66ee1a2f38b81040f3d6ec6693f54cc3fe39515275849e9e24b0af3e81705dea95e8f1bb1b4665cfdeb0630a5542a2857f2b58c36761d743299d77872d6894302123f4347702572f04d9876191d771e87655c071fbd29338eef0f9acb0a8ca3f0327ead8e875bc2e7ba38f249e6eda1fb74162e972ff523d20c6638b93297d406e9b2264187c06d0a78203d771f2525227d029b27b23192f747492b9774b12b039729ef75d11ce8d701e56fbb202f3e4bd68686f096f13680456529e5f132915595e0e0b4061b3014219f1fbef4d7403dbfcac01c701b7727c2463cb838d427e07706400be4fdd9140a800e47e7ac15a7a8a897187a38a0080726349d8b7566252076b1ae1366496b50e9a6d236837ffa0c4c3e61bb409a7d9faf8662109ef7213007a76a6d94cb79ad07183a33a4cdedd78896278a3b5531ec0efda9d77076d85a63536b426a6b58c3d0e8a46faf0fdf678e4964272e8410b346cc753edb94a61a2f309f8e753ff332f5b15215e0a20ef32e6a6faa044a431764e008e66b4af820bb6afe4d8dc1679219fe7614482517fdc523d4d7ce2bad9d59f7b9aed89b813e5b36b58a7c668e53181c0e1da45e4ba3851b46de8e056d63e440c471fbe23fbffc31ece7cd20658784f2d2fca3f730a1f8a90ea6995ccb490fca475b1441e38468433d1423c1d83a20b04f1216aff13c8e035c2ed389695c2bb0bedadc38c8a6222d687f0235bda3566c0865774bb6098acd674ff9091db1a6c4f0c2955c1759730b361f310d956f892089f500eae0084022e610ca4e758ce2c680d213bd1b5e00a6c991976e93189159bb98a1e4eff14f681d47694060126c0852ad52489c15d7302d82c66aa830208a9fd13da87a2aac3e44dddae632f2e4d56dc768ee6b3622c61e59aee27fee5aa0bfa9c56402ae3525f00634b11381d0b9637ac699e4c4b225c32bef9dc563e87cfc33bf07450c2cdd015bbd94df63697cdd9b6cf4169cfe1f626c126dbb588c57542662d02eeed561946ce94b46571f72ca3cf7fe52a8a6ea24fa216f01655dadbeb0f74e383e522da69db64b368cb155c2ba4c4fc8aea8745b1081223317003f0cd7ae620fc7d9a6c9c4f39a237d5d9d7f3e756c77daeccbd5d06ed28ac2f089db5449340872bc444aa4aecf6552621b84e4fabfd6baf0e1b61cab00e5c2050bfa38899e9840e2dac55c7d5e7105f65dc3afe3c35dd3e8ebb1a013d65fb0b9d76665f3c4eff5b766fbb0c03cc10c411987ef516405296437a91a67d7398d788e30f55bc1e6236b317784504c53800cc07f4eaf78bac03a025a7943573edcc67db3d5d5281f85ee993238fee3580cb846efae33b45ee2ee1ad640b1d068302504521269a31a166435e8fd964d2e15048f299a95ec1cbeb0c8d5d119e24670112d61d56ea120d7bc30fcd924fc7b812404ac45798af3fb590570a4d7a3f41639b879d1bdf2c72c979105460892fb41570cffee716679eb7b4124be188e28ca4c68d206c1cc9d49cd7489d63372853dbe83f874579238ecdd28c0dc265871d6dccf782b571f1004702121e8b15c9d8af9e6812dbbe742812c7e7cd1dafbdbe3d189f618936e270855700be8f6a7b528f271a936a2cae204b44d909ae3f6a8bcbfcda44b430397b1c96187e5a8362afe92bb9afb0a0a482cb6c8cac39a0fb1fe0034f8a965a3be425b4b34f67ff38a8ab30f8219a8933539c1d06d9b2997b6de743c568caea8b269642b8503b546c9e136d0e47775c8fef45d4489e6b4747c6accd6fad3d34fdd6cbafe07264e7ae1e025306c97d77a130093cc8d5ab8e4abe095787183a9084c569168011766b47dade4e3e1353a78f9f3464d8237b7de02da10c7a7b8951bafbaa898003ad9de997c89d8507393c6fb782b8f41aa99d5c92d5ed93e02a2e7550d42f178739898406badb6da850e305c10063b1a687a2b321a1f867ddfc7949d9764493af4f9681137101f87ec3c3733c0ee23a758a69dd5dbfccd20e0e7cc8543c213688ef9cc85bf9c539d3b6758e24befb3c1b617b7d59a17e915bb985df8229429430dd3057a8225d22afc2775e352a2d7c2f2f46786d4e6e984fb35ac6d7e1b57da82a6d1470895e56521c88c166f8124a4f0c5ada7d5e43174e319c21b9416735858ab50958def63c9a38e853d28a0f47b8e601beb0cdfb30d87070003f957ae347d5b03e80890311ded8018de0227c430f29ff20f0d0d1331dd5f22cff547847c0a26c1fdc272cd234b668823635f68e0797bf68fb1e531a423b1fae9b056fb8c0589908cd2774a7bea8da465248a438a22919d35e0ed8c5020f06824aa856c1a75e0d50d8e9c2dca471d249a97e8e8055d0927432577ef07e6658aa6ab3e9f5f4f50848b12dcdcd9594dae732864f9c6253cccf39922b5f1f8e16458a0c11db397017821de73a331400a76c2a5a29c7661405e9f244a92862a8ca13bc86a78a36744e52019c067573574f75e01b21c36e19a714e9cc0860e9df8e659cefab57002dc2b3d1a2918dc20ff25bc0d87023813abcbbe29defa514bd71fedf314a140508c7e8dd4ace82d56cfd6307fc8299a65c8b3b0719881dc06070d670729902ebfa1dc0b88050e5824cc186454ec2727d0fb2f95eb677f949375a0a31661c7f2bc452426a052b160b0654bffae35766a5317b845582176f1ec52e5bb7d814651781e268cfaefcf6da560810d84343dab8a8b2f2f7976334043498f529d75f9dec893bafdde0ebf003ea7d43f22d8e4eb3afea7be8bd22a9adb9334db2d6b05b8bfe72a96ca2c5ecc925333e4076bf5b7d9ed519ac3eb87c73d0c8121b1034424991561eccb669807a722bcd43141915c9db90f7a8a8e732054970645da1845b988f21cd5d2a89abd8e14c0e6532a3db89e43571b795d6f475b11c16cd7253a4538f4e73d0e3791e0c8f3e51ce3d9645062f249549d9165185fe6920659fe72ae01f69c6d5cef5a01cbbce0fcfd671e1a0aac35d541210a723d2fde91f37c130657d8825662bc46ca7780e07422ce2e7e5cbc1b15ad29b8473ffb832f45c480e960d620267561b3e3112c54359459c3f0235eb6eb2720dd5cf65f88267e099ae87ec7e35b3a915f18a4ab67583ccb4d907637812d797dfa51acc7b5cb13ab58934217a562b00a4a3d030bd9d3565a47c95396034bd65d39d39a6e7795f13e5031d148db16eddba996e1e70730eee02c47bd8b5c42812a12a2db5490fc3ad50d7d03c72c0e933ed8b43f8e34124e272cb39e06e628f18acfe4488dcced67a2c47008801e8d2db5dc7f7556d38020d53512993f3efeb4b07fd1e7b631deeeda74983011ca401ec7b86eb2a7a4d341f97337d37ada0dbbe124fe481ecac3e9b8e8f3b8b90ccf81ec028f2ee4e62934abcfcc2647966f6eea6563a0fc8fc75348f5fb3d2390db24d49858bbca822217fa81d240cacb7b2f6c2e4bad8a7a112b83a5d35ad68ec1cd599afee41fd4e860097f33afbc2cd790b2933f1194549c5aa3fe5c651a456c8ba7c8fa5ee5492233c21a80bd9216fcfccc03ecb76af3849711a0f69d5a261ce94484c30f4b74ca6cb4d7d5c4dcc0be1f0390c208e1e7e863700c6dce7ea5ab3831c00e586094a6a1f3b32dfbbf99a7581f90001dd558738804d0663a59d77407b6ab1ef3a82c156bc58d5a694a365b300a90ebbcddc49bbe5ba63c88e7a6e0faf5364ea17cabc602ddbf87a4c2f55b068ef296be5bb66befc1e37ad77f8e97c08f02d17dcdeb47959b0f46c2ae2c3d99a948f2a52c5793d53fe57876c38336a74786042abafb63c2154096eaed98598aed76da5a17ae179e79f848b237bdd6db63e5fbe77ee28b2bdcae462905ce1827800407317c2a42fc0dc234b2183db9097c0fae23da91aca6b1b7894537b0dc8524536573a34ef68596021cba863ece0de4a068f806d888aa03ed88ad92f375860f8885c5533c637a7a330c24aa0357f007ac3678e59cb1f6aa7c6979e15fd107a98ab42a635a3c3e70b58a19ec73b4bdc482000c3dfb4af84012ea3957d3d30b80857d9e06a2e677c84e5d9041ad4bf22afbdf0351f6d5c7a7a2ada3dd5ab4e48e37d51e5fad56cf9963715438c5f04b9772773893a59e2e46c6b7e19e9001650b66b469f4b1c4d188b286d5ce8b21269179e772147c7cb09eaee9b9de684ffc33068e5d346e79b710d82fd1278aee64ddd4ed37a944e6c745217c6a626444aa95b565c1f68a12cd2b86a61927896884bd5a76a9df4f6fe548bc16444272ec1e856334d64e0f32ba90daa77085b0683e3e010abf571dc564fc703a12998c72b6712386cfa4ccc802c850a3604bb0b2d5cd2eb6e788d475ff198f94a220c925a32ab6d69b037f1b9f0f4ce1d1b89cc0d07fc047073657405630200033fb971149dc9881cf31b7bd90de445f0ada69611016c5fde4af5bffe2b40a1a27d651a1d2127b0a95539b18fbb835f5145c1c4c7492866c6bd08ba260abb300720d2d42b729b72c6166f9ae0e4ac09a0f6851ca65444bed00b72b7f12befbbd007fc047073657407210252a4b012198c2131d70498b5939c401c01eb1178dfd58123b55766b03f008f7b00").unwrap()).unwrap();
        let secp = Secp256k1::verification_only();

        let dummy_hash = elements::BlockHash::all_zeros();
        finalize(&mut psbt, &secp, dummy_hash).unwrap();
        let expected = "70736574ff01020402000000010401020105010401fb04020000000001017a0bab8c49f1fce77440be124c72ce22bb23b58c6f52baf4cdde1f656056cd6b96440980610bc88e4ab656c2e5ff6fe6c6a39967a1c0d386682240c5ff039148dc335d03b636cc4beba2967c418a9443e161cd0ac77bec5e44c4bf98e72fc28857abca331600142d2186719dc0c245e7b4a30f17834f371ca7377c01086b02473044022040d1802d6e10da4c27f05eff807550e614b3d2fa20c663dbf1ebf162d3952689022001f477c953b7c543bce877e3297fccb00ef5dba21d427e79c8bfb8522713309801210334c307ad8142e7c8a6bf1ad3552b12fbb860885ea7f2d76c1f49f93a7c4bbbe7010e20cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae010f04000000000001017a0b90df52169792d13db9b7d074d091aaa3e83aff261b1cc19d291441b62e7a03190899a91403ca5cd8bded09945bc99c2f980fd27601cada66833a5f4bc108baf63902e8bed2778bf381d17241be029f228664c7d1522ced55379e275b83fe805b370216001403bb7619d51d2af2c5538d3908ead081a7ef2b2b01086b02473044022017c696503f5e1539fe5cb8dd05f793bd3b6e39f193028a7299a80c94c817a02d022007889009088f46cd9d9f4d137815704170410f53d503b68c1e020292a85b93fa012103df8f51c053ba0dfb443cce9793b6dc3339ffb0ce97af4792dade3aae1eb890f6010e20cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae010f04010000000007fc0470736574012108a337e7e0ecf24c121a17193623254c277a306e9fd39cd5aaf8b7d374f4011c6507fc047073657403210b8e11e3b8904ac80caeb16af1c93053f8a11a963269bcefa96823d75b8640ae940104220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d9307fc047073657404fd4e1060330000000000000001efdfbc0022a6437ec10c672d76c513868f403f6b9706e09733d6624e3cda831c2c199dd4c5763054a1c219e079e8cf3ce0c00dc2f16516972e1e64d576adfd9f5d778675c8a3172450a4cc82d6e6c59f2b16dffddc902d0aaa647b750d6224cafca7239a4fa81219cf2ee89741ffc5b7dd7e47d332ca931cffb1d1d432935a6013207629118c965b7a5102e62c43ca9d06bca191307a476738548536809ff6b01c6b5b25d76ff2f67d99e20fdf7d2eff6fc248186d21d054196023c5e4f572ccf0f3aad8728c46f2ff6756ea39de46028610a3d26cd42978b09e0e29e0a8aa46e4fd39d28d028592560264cf1a794c27f6c95d382f486dfe900a81d9d92935c7e0e6306549b3e49b1f60182512ccb994338c3541a2956139b2ccb3dd156853105abf5fb394cb2c45915dfd4106c7472dc5d360ab5bca408203a3fef58b4dd33b0c11c367dde2f19c8af7682be067244bf49a2b8cd4685f5481cc31ba27fe2f3d7b7a353be9b41e4eee2342fd70b8408c91951c71c75dde8fbc03e3f28e6d3d3b41e0e963d3ba0c25b2eb50560c21221950b0699d2615f0128e6cb7fa1b04ac1a046e569a7e87df98c14360b8ffc43db5e17548c7ea5056f84ffd14f4cdfc68a4f10e9b391cfa63eef2c2d623e7cdcdfae2fc4d63496d81462174ff360809b7e3b4305979d9cb8e9ad5b0f012494d31ce51ee6489555b09dddb16641ed9e2534fc34db99d2a4fa736eeabacf2f8cdca97f9e84c964277c6f30f1af7fe2b51b39b487d56ebaf593a3f98e811cb09849c5b445d5b7c9ba37807bd0189c8bdb2709fa70c230f9aba41dd3c62384aea6e1ca098ffec26367aa65a09459fca074d1da0365cf7fc2d8310ae099b838ca78e62cee10f95ec549faac1ff0f8236fb8cf2c0f6654e471d3950ef45e0159c44f9e343d05b3af59b939cf76090d040376407c41661eeda7d2cb61cad0088a286948787dae0cc5abdcb97f7f42026c65a13e1df1357c25d376955942adc858e73876e1d8812969055d55decac9a689dcd11dffe5cf6e06088b93a11e153ffed104266bba472cebffb2b0cfc8ef132309bd7836071d3b6ed459a5950c64cccf230015c98f9210f2d57b7f3a07c382f3df09f055c88e1f312db0d60d471afdc0b780d319a6229babd8f45edecff8d1073fa850f755219a3ea14e7234cbc7590c60eba0ba0cc1afde6ce91c8e8835b1ca809926b3e7d8d7a0941425e5f08e884f12693eeea1b3651f53da90972aaa37d426f37db3edae4285db114cbad5964c269e03b15358ad2a7242e0af538a594fc779ec3c43c3d94fab2028310c6d0acf3efdf0acf028ee757c5c02bb5b8b691aa5eed1a62acbabd0d61faa478cdcd54c6db2cec6144d8d1185115097a7da79c16ad3118d12e36dbcb7a70b0ddb27bddfcb1c6e5426b7e411f607d22c3ac2b8d3e41f55faf5e2105bf3b943846cc4c33edc64f902c1eeda09c8110d4f3ed0a5e511156a3e368f02161b92126abf649341ddb8ed03d1d41b91fc34548c6d94dfb47c088ef27a3cbfe1c9cb05f2ab2f18b8746394c8080c4cd92e818e46f861614ab870cb7ae3446e376793f3a6568a2ccfc2ab0ed0365567671436fee6cf427b6410a046d80b9d88f094924ad370da363e8eb70355b711687e92d88a08ed811ff241c7a6dbbad9dcfc18e6a42493483b938e36c1edd2a1c6e078a17c5d145c9c058b4dd69afc44c345f1c88afb95c1deb5c4994161ba25783165d43b9e50a2d8333a8037cec2ae809a3dbe026d6ba40d60badd05bce73b0f9f36966c30b9c0cb5776544c1182024a96e746a3b01f9db10b45aaffd3b055b02b40bccd41e57c10719bedb0fba99a0f6b0868b186fca0397ab8c219f33190f81e4cce2fbcbc0975c394919c98fdfd7e25a33e5f31fefd06c8dc409cbd3e743f0f48dc90abe45b2e68948436caa37fe9932a77b7e0fe0819d8283964b0eee2249d9190f3eb0bb8178e10a287be1059f35cc1a153dda14def65f3c49cdc5186da86bd3e965446f914e3c9b4cbfcfd2c379f306c5ef8844c4fd398b3c6f96601e90d2dc8810875663939f63abe3ee2e1c8a9c2c2010a01d0dcaebb556a7c98421f8e6465cb0434c07dcea9db1a142f9684e50b06c545785f0dee4def1257e4bb22d87a2b37ca9eb53081eb8f1ea0439c4575abac435868a36552df569ccc63477594ccf7eadfed6adbb8e81800a2e2fdd7effdd1e2f09cf76c9e780f6f8eb8408a3fcc06cb8bcd28db7a37edb0232a6f0e509c684318f179d0c91a97718ce3956c266790361ea3a1bf70cdb8a2f2a59b06dee18075745c7302db9b13a452c188c5624964af2d5d4bbb1138dec59df5dfb077a0f62ac4db3de81f54365f2a4a6dee63a6092b4660d3f5dca3cc8de3bb5350f5dcebabd515c72c9114bc58d96e2e863106f0982c2632bbacf2fe5cf6a8df880c550f7008fd09227baff82d4eb031802fbe7d50f6174860c70fcd9f0356e34c0d45df66492dc309b260b7158adf678e2da66348ca84de3e721c6196e0c717f59cb802c6866defdd9032a4b7da82b816d9681e5eb9115fc2a572fbbe105f479ab339bfa5961aa1920346c9ae4185a74aa828da78a71e55876c657249e83f5812cfb055400da1db8bbb5ed3ce2ca4655b0c39b698ed7d235fb0ed4f29a7e8925cb873176efcd1c6981dd23865468c6e01ddf61fa3e40d6fed18d8e3dbd97a08c68bfb092e441e512d44089cf563509785dd58203949a1ca9b66a700db14060a760aa404e5e9f31eaac015f1527f6d760d8714c88040b87fc8a4d183230cfae35326947e28a7a37eefe1d77070f5232a0d67e278a45d649709a7398cbd43094c5001263671517f83e62e79fb75e6f9bc592fb3bbececa3f597dee71dda0fc909079ea49d81554d2fd79d1cf3cf25d1186efb83cf972b7426600d7d6eb6c48a5f0e26af640c733f3f771e0926e6b38b6f39d7882b0538dcf281d92a6bd361bb32e16f3988d6790fa0a45f549e983f4eb68ce5ff11647b37f8e4c444aae8bc0f7c49ce7215545a29215b55f37dc42aa6add6fd1fb45d9ae580434097e7a8686e23cdbdbf6f8b6b1e5579a7908bafd8878b004c7c94e045fdf2b94f8c1a75ccee7bfabd9bb6d0ea8a60dca61053636160c19f8f3fff3d0330fc95d20a1393629f33f281e5da80a5ff66aaa5eefcf495f8bf7e24744778841d7c633f01af2305a122ee093837998e87f060105ffbc083c0d71f68c2c63820d7a547d9af5618544efb9736af56736e73cb696f191c68970ea1deb587231c889672b3b5399b9b5e915e3c567474c3905ec5b6468da826f1a6438ec335da847db540a091ab311c6846f96a2f17befa2f29ea491a41d7630e42583ad1212e6c606dc258a49f756e2480f90775c04c5c533300e37f8bc7afe7b155fb95877252ce4a53f78491ebf9d8a4aa41da1848633816542901d56e66f126316c80efdaf4b457f9ce771edb012a0b3c27c717f5cb3cc99ffcc959a02289e30d5b1ff936320579c469bd55cba6e79a0c5f1bda59981b71840a8c1ca56863e91eb21fbaf84525d5f04e0f282d03bb56d6dc2352f163d8357b86bc6e4e621bb693db3565eb9ef5629af537874c1cb3459582463362dab3c6fed7e574ce9bffcc685b8eea61599292cc69860c4f9584818182f94d719dcc463e9a6f854405ca2deb3de29ffa1826f795b7e7ac2555c0ee576c75494cb832c59de8d9620927167bc136549b731ef79a39fbf8789831cc003a772fa00d4d699d089d47037e12e1c6eb8c20c5535225a33a1a787ba866ad481e9a4d689c83d75f1986405c82154e312ce8b3494ac5721b96193c025bb75b2cc974f9171297da058d2ed4f00d94e60737af29da660fc51fb9bb4d241e78c9d1815d7e3ea90aa541c4c512ab423ece93f9ff2f479f464b953b4171217b758b280c5d8acda32cced7bb0c92cd9b405afb3a8405602da914e1831fec5b6a291f90635afe82b9389a8b41d957f81be125de2f943b7cda9e873fcd74b446bacc00bdfcbe643053f6cc8162c0a98343242b489f59f7ebac016a7fbf620dafc15c8ecfe20b954153dba19eb81087673a1e847238864036e9a300239a00a5a03d8b39aae2bc201c04c477b1f2a37552670c06ea65551c5c88a42476d0d797af494b077737cb48050bd35f4980964b8b9b98bde84615e8fdca407230f5d15e97ae65d63a96f3d88518fde12d6a82881db5c8d4cd79e724312e88b394129de3569c5c99bf842a90f193c91fa55a82116e237c877dec2da6dc652cb33e33df47420c5238fb6ba5fd96cb77f0cf6c8a12be1a95186680d16a064d9b1a7c2461fdf5e0a512a5a3ed2f8dc0eeadb6c95a658aa1c2713fea473de51f65b13a40a2fe64e5227bc9248f59c2bd60dd2fc14918e333faab6e792ce2f0597be47cee70f5a8b788a50c9cd153bf24786aa80f631ad21926e3285f41c5125a15c12cc889112df0b1857020160122c2595ab3359bcab184ecb32f7cf8f38eea23f4f9135104629d8f1e8273c44f8afa129d3a74cf58ce494214629cd53b99a8489ddc5d339e317ce75dd6c5dbd098d811c56ec5f19c00fa00b5465e39f8f2022c71ab3ed0d5a24058c197719551985ab30a851390ab5e11420c521b1398bff0038d904e5879db37d60c623a0a82e191cd0b6bd20a9e956d41d5daef703bdedd6bd0e20fb096423dd39706e939e796aa8bdf071e44791d2e1ed4a81ffd018cb79c5b6bdfd6297cc6cd379845fd7ddfdb0b83d7b26c21e3edb58185e71472a79cb65322579bd5e0e7b1fe081dcae5447834d70459f8a96b341a26d8922a2b1412f95f3533e04b5f65be112cca03ca45ee0eca10adc7593c78c041281c880d879125e585e68f5c7fbf8686f245cd736ab5aadc57c032c637b753b49575acf4bbff46883382f408417438d7817097accae3fc54afc6015b84b3b05627d7c83c4627c87727bd24c4b4d96a08c64164ab8d4abe3fff5c3b09e8fd12498e3cc3627e799e4ef72a870cd89598d51ba396655b4de66e48997faa51d05d581c52f52852cffc9f89252f26d314d2fb8fcbce197f3a8f330339c2ec3c710710b74f0915da3bbb638b1f1a0cb0c176adc151da0ab52796d466b23e8a269c5b22b76fe7586cbc217621acc955a43571dc04f69deb50066cc587595cf0ca4e9a00a261ff2791ada8de04bcbbea249d2a7840bd8fd3ef98a248eacb7fea5318b2e207668e13ab4e5578c03315d44b478df5247d8afd0624d2a57adf85fd16d86ae54cca21f6c91d8cafb3b31e3f9c4e903c04f39d67c90560dd10b2d28c6ee937cae01e921c98ddd833a9b9247053110c0f29d2f35f8ea322a738636f17648b627db622a9cc891fc1d066d5fcabc168f1b492479b0578d0bd8de0298d4bb96a4351714a10a39de49d57ad66bd6b458ae0d799a19da54bf620c0e6979a95b61a83cd06e46d7d263d53d66f77557232983268f5fd01d10442af0c840ab09c6cc4ad77add6379eeaf98f7cdbd70fffcb035abae4efecdb7e6f63ed8acebd8449b3a910e5eb06b0ee6d80dd45026c9e6c2f978f813b2800386a4d7ad9d127d76c4286c1b2facccfd16e6a263ba3e2893ae5e42049d421e08a62ee9e9574a1f70f0add7b68344256592513cc15f4bc64c5a029f60d617c245c1c34d06c095b2d0a9647e65dadb33ea79e3e0ea62ce55347d24eaab7cf9fc33fd70c07363771f78a13d92941daf7970c97b43d2fbe3e789a52ae7bed64736e6ce59f95322d20f9d6dc00b5824a0ce9072dd051c66ac20d39bd953f567a831d75fa91fb4d49b200fc893489e60df95c2810f7fc57b7f6b7725ae600e1c2def6a943b8d111ff3e9a5ac80aa981fad8709e98ee1550005bb8f65dedffbfe3793abb407fc0470736574056302000359a33e8f3d0439eb7d60aa79255858269bc1011e4cd0d4aa753bc2793f9638fe70dda4a99191f08700047a8b66d9cf7a53bf70756013c8630419e3a0bf428158dd02ab6e16822f239df0a6f1b67b6e1335509a286b30c4b11a22dcea9f95d51307fc04707365740721027fa518c54bb326d5ce3da5c2eb8a6521ab99df86b511477d0f5ebcd616f063ac0007fc04707365740121081271c10f0caf52a40e015e7d35966dbad39525a6c0691d4beeb3bfb22af5304d07fc047073657403210b85bd6dc21b4919f6ebda7ab86ac8122c793be3fad19e44455945ddec8b59e9f6010422002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84507fc047073657404fd4e1060330000000000000001cb6f1101e2b960c9a2fe480eb88fc76c63e58b57445c78d88e04f740580a36d6956006ef12ba606aaca89796dad5ff7cb4c4c7f4e65a07fea8a2ce3b58b265d4b3220013a09ecf4e01023aabca5586d61ecd5d7f2bedceb8b18a8e41451c97a192098b196add06a8a6b619e1e731fd9ae2973741aff6358c1ad45cc873a2d497271e3a20873a6f701d4c44ef670c8c7a9793079d9bdfe956bdc02a52d1de8b2de58b0f7d309240999f13985fa8c98e57fe1bb75219ae6330e9495b523e891dba7885a5302817d68a9891ae0c2597d4d7833b91b073c4f9b27be1cf81ca1c2c1014c57a4affe7b402c0e0c1862bd17bc1d43428671a106c26cab61d5e4ffd1c01f6af1c6e97f7a25ae8aaa8d2c91c57881df52bd5f242b127ec7aed5880101caa01783884dfe943ec9764473323f59b27a204f34aa1fe7fd4433fa606608b0f253247d149e3e269ae5445e917390be83d5650c05859e3a817a6c7e561e2b12baf6d4ca4221df0b7f29fa134269139afd9cee5c7d60149dfa23031705c6a8b72d00d659d7a085de8330de2e5c168ee3eba2180a9319f5e8e0806dadaf0fffbc2df839571360b8cd32300504a527cf914da7a1e788261c9cca2872ebec5a17cad33b15a7a7427c200b8746761359194520f0da1d7ae03f26190d07cf92d515e04815f514c66a98997320a028ad24e83182f213d991accf19a8a59003a2ca666ca505c0d8349e2cb22887efb7db9e4a4e3e2d8da0d5f032603e03f48fb967fd018fc99c6eb72acee4178edeb48703903a89e9462a2d1f447234c3373fff8b205848c7a9d6e45ccc31eeeb0105ed3af1188fb847cf6f03a7f0a646fa325b672796168dbbd9d1d19b2f41685b18c3c96f1cfb7ecb1dea132e8815b62647820ac4b12597d8e737a01a970704b03ba5ae68f8d64a1810db10427fbff1d74cfac91561484cfc8d3b23f74ba0f37e7db2f942c58fb1dd30f6a50c57b5eae720c6ed69b0fb81a6e0260c53028c732a544391e319987a24548230378f8f1ddf65a2d654c7b26951d5c6546cc8fda6003228e8913c9e3c5adf7b7b72f4ff5c4aedba6096097f9a4b58ea1e060609e8d1f0fb0e5dd905b29fec72b118d40c5f599a63f9a37041742a7f1af3ef951c31833621842ec212f9fc5cd3e8c08278ea192f8032ade447d2f35ab59810aff371f598b7dd57b3cde2ad854ecad0c786150748ac241ecd67cb868663a6fcbe9d68c3dc221d4fcec9b0ad89c337c1e10b91a38ab1357f260ca3a084da536e56262973e6c6cca838601fb2f335811375aed78295c4b17d3798d39d4cbf6254ce57680a102907e5c08b5c7ec0a1e73bf3d7b8babdc6156c6ca3f09c0423d6716ff4e6ee0338cfd778158202b5ffb60b74558dc6d0be9b5aed6892c4e0ad3e20de5b604b2b010af09ceaba7c0fba5a7fed39d31cb2769909a251ba5b0668330f734728f5c6786a8f1a35df77f3d739eec71d9268fb2a494a14bf7ab91c075023e76856d1745f5813d83878822934d0b4cc0538048c3f96cad7aef2bbc49bab139915dd4998ed3c6701973eb7913530b14c688f0b344ca9cb990de2a9b12fa7ad8b292234a33428b4d16813693964365bd412fb936c1461fdf8dfb0bba31202685f29addf95fc65f841e97042bc5d82f103e41017c6ac91d3d266e12db2dc195ac4f6d4353924270c7144cd96dcd07b9612e2bf1e0f7fc46ef83690648395c575a13c2b2df0fa04f740340e6b116b0866a401de22f68fa3f621d75b9f5f625cd5d5d7e12a5b0ff795749d742eb2648ddf068a451059390da566b3de84f9d528b2663de7dcc562eb014071e8277a054783d322fa67b9e5261b87e9c354ff58fc52bf9df404139311d6bf9650658fc94835a6220ca02a4bfbf46b2af4f30b1ba681c0de7c134d98dd52eb1e937c191cc9557aa73a343b99ae0b8954a3e929174984b574da75e90a9b71af1215317b04e4090770ab596091fc05c82235a324f86280f7fa081360ac758c1980c6a6763453e6b344611e46b05760941f9517ceb298ed7a2d6f96b11f5719ed0dec803c511dadb8d056d4ca06ca0ad090558a4fbf3a886f3ea9c33e1bb4bb5ddef4798cdfb384bea75a3794c42a53af60f12c95fe9b38d7f6a5d914ef100508091fc84756b596b9ba08d1dc42a7e253435b5481d1470ef00a1172cb036b5bdfaccaee02b15d099da17f9753846226325232e71ed9b48f57697bb3d1db75ed214310e6e3608ded6f188e37b21b96eefaa396db0df05a86416fe64aa950eea87e7af4407c828a8822b17be661269c9f9e365cdc79d20503e2d5e575c5387fa961206118dd379834aade7727a1b2477a24f05f6c2ba3156fe7f5b5ba6d7487b1a124f38e3ed3cda92a8edf05f28e3d699f0c12de9cfeb30ec8d4cd253287a6d3f596db0c06006a531e80083f5b41ee26c05d529e0a59ec151b4a9260a7ea8c1a175ca41b59f464adc122f448fc43e90dfa7b88f81caa7a84e3d6d4dbb85e5828b6ae7455dc2c87c8d9c706af2e62763675851b4ca449c9c0f95d953ce53c5327ba8981321a1cbfb76bafac7fa17c99567725d8e0ac288f3ccd3bad666e515156517281c97a3dbfbd5f345f8eb80bb3c4230301a38b7c920d74eb910d380f884a683f7d3e2738fabf9646138e8a32c35e43786e67925508e4cc7b1e7a36abdf6a497077704e216f1e730c20ecfcddfbdf2484d8eb0ef9b7478f77063fa90b8afbcd019d1a584df58c537b40b193f246598ae4c53958a947dd3916b14a5a4227f01bf543a8c5d6ab8eaefdfb959c8715b756a9c797fe39229dc56a86364cb367fa37e16e96cf8dca1fdc8b6a46ce88e3d29c75b6cc718ca8c28e9e1ae991b28c286107c1dced150814d6369cc8003b2976018941df7fb8eeb68be57adcf8a0e813d2fcd16dc390ce17dd0a91dd674d766d21b5de7f4678a548d75cc3de7d099b418fbdb66b2a2b12a56b1dd8b3f84a7b45e36db9bb63b3ef9fdadebc21c6a75364173925ffc69d481024e49076dca105795e7a64a3c82011889aacf0114a1bd31414e288cbb63eb47d399d0e025a54f11670c8ad4a793d0e7ebd3b0d8eb30b87cf62b131c61a4c55d2e56e47ae99fc543c57a1877ce44dac4c6f9fd99552701ade43858e0b4020230cb4d42d1990bfb509471a5c1c5557c29c00072c5cbbc056de6d465ea2ba2f4a1a5dd604dbf998e834b9200c59fdf90bec38af9218e47ea5ed5512cf8b0146126a15d49bf915eb893ad1ef83d8faf6c93f944ebce3704f930b6f69a1afe767ac2c9fdf092c804c7372ae1a64bca3a3b5a31f2ad430ba9e61dab3daa3be90a538cf0fba00796de511cddb5a594f14aa6d215bd0be19c0ca5f043403b7dc56c87b092d9436eb79509c3dbe367c2fcbc2b09f9818cf5a55d5ee0e477888166bbfece661b62812ffed3e4167ecc81dba148f89a8f2e7c27424a2ee091ac487e68fbbf9798e8caf46b35de8dde66a7cad6dc98a426ea7b8b930cf2d7d71fe71066dbe51e8a1c7151e97fecbeedef3d6f8e01cd5576dd58097b46153f9c3bcecf30bc82b4cdfb1bbfa826c7c5b217a023e4da02a35d0947b2c4d24d50a292e4c70fe854a420c54490d4850ee8c372756671fe130532f89878a64977ead60bf604b73859ae64ed62536423bb51b30c6fedbc819fdae05cb64b87b153f4252b832d6b866100a7b307d1e705643f96f0724858e6211802b2ce706d5424b99315db90c7d74fac66951251f6cb739ea008f839c7f62318f795337ca4ff05886a2640819873ae00b933081b64da1101d1b17451357921a2f4d4dc86c92a5eb346fd6cd3a63315768b94b90a15162aec91cea706b9221330db154d1fd71acac90be47055c725bce38710f1b4b4144f331cfa9fe15ebf6535747669e4aa1f0d72092ef395f16a4ec9014029b5c9d1b4bed9ec81a7568f8f1c87e0ce0f4ef9cf49e3fe4960b0b7904614772c63147f3c5463fffed182919c4973a8256346116be40b10a38cdea5bad5878760daaeda57476e86ec65e58030bc8ff99ebf017e9bf6383f981edc83b538e2bf4bb573637e6f4717d74a3ac71f5e151259b29c1b7226e3a8ab176baa2f27e3e385cd48c6f072bb6e8e9c92e35d7ff51177f4e3553555d967c04befc1847003a8592738c82eef231ce3d372372a19a01b27dc7916f986ff3f3ea8872d4986bc1ca649a92924c8f582ae2b44028e711e955d2563c33db3b7734aa246de553dab2c5268538f7c2b6dbe9a70657e2a26e52f5d216dfa9aa8e197a227c86a7d3b468880a721b804a0c51af1592043eee7fe3657b40c1832a858cfb4e037d208ee69c4fd697b929383a971b2a0864544505af2267e334db5f3f3f4ed88e2f6f2b3d7b96016ff92a120556e4d1e50440943893b00508c6242bcc41b6d06dc29ba20564b42257b9fa1b5f4f453e94e72501d31e8947e09a38261020400db4b8cf675b1854639a962a57905cbbee14ea0daa9bd281fd635c8f900fcabdcbcfb140f4f24b47731782ca899284fadfc9d0d6eff77045792e139afad34c7672bacfa22d85fcc05652178cc169bcf52ee3cef281d99935abf9c9910caa7994cfe33b9319d9854aa6e2590a86297f23b0cada7251a6ee1b2f3d2cb5a193cae8768d92f556994e416d4bcf5bba3a295d9e2215291237df74e3c493189bc5a27b3fec3e1a1329c6c6c75e0802b40fc74776476dd2d9e3453ec1709a8a2d162a936d9fe7dd4b6f7abdadfa429aed4cbd5896cfb24a2d91f1cee781d0ed73cf7306d6f9545fd3346c2232b8799553357a5a531d6085d04af5f183019dfd3483baf23b0ba5a6b58bba4b7a1eb0a32626bebb5cc0c4dad45c55d135be8b0a4dee787ed48b90a2a3fc120a753b52290c27ad0eb32b668a9540986ca0256c1676debc4d19b1b80bedd81e505154264a199ef1a54e1fff1b3589fbb6b2d87a1e04e67066571b68fe04f030d473f8d135585f8b7be91f0ae1a4fa2f44008c0f727f6aba9c5c60c3a9ff22911e267ffa2a5d1c71ff25f96ad257be29a2ec641e2055d785765cadd0c2fe513c44154e74f4b8cc4b24d9ee2f6cfe245549713f9dada1935247a2ac7ccc13c4a5c00c6ffe7ca33c0cde4c75c4fe2ea041a965e4c7385ebfdbc348da8c4216a02fa829892c827adbcbb87745120667cdc5a4aef28b190a54b422df45b8547c447765838dbf9f05de338ab672706b59b2f0644d6735d9316e64a1a15d3dfad893bb1bbcbe1b574a0b8ef5265e195a929148cc5e97c8bfb032d4528b523b6a6b29209428f38115cd102e3b4e268333e490140964278238e7ea9638ac34559e05300dad0c3f18e9228474cd3a7186102967c33fc14f086b4f1ec3957d87f2609d140dbb9e7ff793101d1cb90d004565c6a32924715b1bcab483e6389e2e824054edef350f328870f16412aca0fee39edcbd02a6a667aaaeabb6654c4762c639a26286a3c1730ab75defcd9451b4377f6acdc3b905684658c0844d904c47d313d85eb54963fd71a9a76dc8e345e479004f00e446b886ec41cf7bbb9311463e877aa4e357a0dd0b185a5cf12244296f5f8568e84cf6ac3b6125db6897e4e7c183cafc04f61b3263456f61a7880b446e3cffe986c3bf027c7deba490ec8544d2627e6596ef8f8a5cb577796e7c36ffc4f4346263b5d86ae1d7b8d04709367349d590047a8bfb34fbf6481adce60eddfdd1e148ab83874d70b5303fa0ce60c0ba7a047a477dc4c513d2218b0bb2bdf9b60be9a39e928976464e333ce0cb19aa21fda1c6851c6db9d5bbc6552e080f8e448637af711fed92e72c8d8530187de94603377dc387041a9eb42ac70b3923b9828de33bb337d55409cb419bf4089cb2bec79ffc3afc6dcc3cb82bc903d956d28e307fc0470736574056302000318eb22887126df9062243038440ef3fca2aa024fff8739db4930b314822b00cab172e83c33b7e5b959b0c3f27c714e447120833ef69bd634d1e011fc3c2585beaa882a29c2dabddfd31a48c0255d1ab57c6796aa4625a546a02cef51a9ee2e8007fc047073657407210302e71fc2fff37aeb6d2e2a7b7f2308d4ab7d4bf0a4cf9be7c06e89a66442b48300010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104000007fc047073657401210970cb1dff96101101e24bed1a66fb0794d2fcb26aba11e7f2393edc1534df8a9607fc047073657403210b9991881df2ec384ff5616f6c03d45cf033ee64536297c3557f9fffec716c1fbe0104220020cd4ed5f0db8c450e8b0be595b6410c1759c19f1f6926279095c83dade9862b6d07fc047073657404fd4e10603300000000000000018b6d2d00790f618171a9e8eb6051fc14dc27c502a54f5ccecacb4bcb350581a8f4b1a887a1e58865a21f51ef5098400c115cca84f489637718d8c3ca4350ad677374d40d2b64fe949ca34bd4ba845a87c7693421b70aa8d852e021aee329762883b9820bc0a47ea2fc6a8411ef773703632849094e51c73997c67f3e922d2801b6abc445375cd963a62c2bb28d733bf9274fe503081b51a56023a94200743e7d38865c190331449d19bf3d4eb7bf0b2a9b90696484aab906b9470e10946744838fc428f88461864d6601e93f10909e049a315fcc0ea7f4d71507fe5ed19b9ac2f55b0d3902b153ee27da9c55ab66debfb5ca440dfbb1a600cd8875049c4c13bbf242d26b10035002c7859f9c3ea631d955914adfa0817e4801e85b3f250cd9e7523db62c4ecb17a49028a02a1b61eb96a410643f1fec0ac664d96f99a1db4ac335c2bfec2946707c3c779a56373db197039af9a903e833af6f51de5cf8fc667dbf5416845d415dc98641e0984ebdfab88bbcdf305f605d36f7a472a516206d7ec722251e269800a00e8adb8f2ce161395c1c6ad4b406e1fda77bc7f0af07ea075011cee6cc5e7fd1b6e96e321171ca7d28a35595ddf0b0c831d28a88d30c7391c5832d90f906539aa49185fc6c0864e2d10b21160991fc19a1d084006d03fe3fb6f571f1ffd9f06ffbc0c076689373f9c2f8655758f7f44618345a6d5f8edae46e73a09c38157d5c39dd51a47756ea761e6320d6a91a1bb22d8dd35e4e7806b0242bcc4cae8720a953c6f933c0ee3216513cce6742a2cb4bf44553d8eaf175471dbc0f71c7c245fe99ab4240ccac637a16c82f0c60586f00d83ff852af48a239289d8b70a2638b0aff02572d6d2d68e22b87ba93f3db51bb27825265607ba4b6e9a194c7351f220b9e715a23237c40024fb7cfedaf7c8e0a1c4c6aebef8841fcf2609a3dd7f44dfd8895077df41f10790372eac8adff5ea7eeb28e371b4700d5044b41fd358dc4ba29158213e0f93711026fac8abfbe7cd80a939477ce545bc91cd1d32e8f2268563b0fe3e80855777d51cdf4835050a557d3c7b7f6905ba744ae5450d22837d2c2fa0c0755934654a78601a1fe236f11b6d72f368880ed938ff4a2e8d82c118493a1bb9a9ee95cf329f2d175d467aacc2c6cd73ed59ce64d508604db77942f9b7f3b0f86d913d3e1b489d2190a6da1ed997ab1eee356c885270e4e0192acc9c2b8702107c96aed654318bbb7724b913808dd2cfbbf6ace8db9c4cbf26f2c90a76eb967e365c58855b83550819cb5b28ea5e6ec1ea153ad3ee5e6292a174f7cab1b39e852194a6926bdc4d42326e17998cc057f614e91f6acab5a5bbedd93d9a13dc61977aa2accaf35370a3f1d3819c43c9430d0e767e92de96bb225007a7b6576ed7c4f05c984ce2e437d3b7f7f50c270caf90f8e5dbecb992be2972ef8d79c7674e025ee06b1302bcbd57fe5be9d9b4e38f17d9dca898ef3d71918550fd77a15c7aa2b66ee1a2f38b81040f3d6ec6693f54cc3fe39515275849e9e24b0af3e81705dea95e8f1bb1b4665cfdeb0630a5542a2857f2b58c36761d743299d77872d6894302123f4347702572f04d9876191d771e87655c071fbd29338eef0f9acb0a8ca3f0327ead8e875bc2e7ba38f249e6eda1fb74162e972ff523d20c6638b93297d406e9b2264187c06d0a78203d771f2525227d029b27b23192f747492b9774b12b039729ef75d11ce8d701e56fbb202f3e4bd68686f096f13680456529e5f132915595e0e0b4061b3014219f1fbef4d7403dbfcac01c701b7727c2463cb838d427e07706400be4fdd9140a800e47e7ac15a7a8a897187a38a0080726349d8b7566252076b1ae1366496b50e9a6d236837ffa0c4c3e61bb409a7d9faf8662109ef7213007a76a6d94cb79ad07183a33a4cdedd78896278a3b5531ec0efda9d77076d85a63536b426a6b58c3d0e8a46faf0fdf678e4964272e8410b346cc753edb94a61a2f309f8e753ff332f5b15215e0a20ef32e6a6faa044a431764e008e66b4af820bb6afe4d8dc1679219fe7614482517fdc523d4d7ce2bad9d59f7b9aed89b813e5b36b58a7c668e53181c0e1da45e4ba3851b46de8e056d63e440c471fbe23fbffc31ece7cd20658784f2d2fca3f730a1f8a90ea6995ccb490fca475b1441e38468433d1423c1d83a20b04f1216aff13c8e035c2ed389695c2bb0bedadc38c8a6222d687f0235bda3566c0865774bb6098acd674ff9091db1a6c4f0c2955c1759730b361f310d956f892089f500eae0084022e610ca4e758ce2c680d213bd1b5e00a6c991976e93189159bb98a1e4eff14f681d47694060126c0852ad52489c15d7302d82c66aa830208a9fd13da87a2aac3e44dddae632f2e4d56dc768ee6b3622c61e59aee27fee5aa0bfa9c56402ae3525f00634b11381d0b9637ac699e4c4b225c32bef9dc563e87cfc33bf07450c2cdd015bbd94df63697cdd9b6cf4169cfe1f626c126dbb588c57542662d02eeed561946ce94b46571f72ca3cf7fe52a8a6ea24fa216f01655dadbeb0f74e383e522da69db64b368cb155c2ba4c4fc8aea8745b1081223317003f0cd7ae620fc7d9a6c9c4f39a237d5d9d7f3e756c77daeccbd5d06ed28ac2f089db5449340872bc444aa4aecf6552621b84e4fabfd6baf0e1b61cab00e5c2050bfa38899e9840e2dac55c7d5e7105f65dc3afe3c35dd3e8ebb1a013d65fb0b9d76665f3c4eff5b766fbb0c03cc10c411987ef516405296437a91a67d7398d788e30f55bc1e6236b317784504c53800cc07f4eaf78bac03a025a7943573edcc67db3d5d5281f85ee993238fee3580cb846efae33b45ee2ee1ad640b1d068302504521269a31a166435e8fd964d2e15048f299a95ec1cbeb0c8d5d119e24670112d61d56ea120d7bc30fcd924fc7b812404ac45798af3fb590570a4d7a3f41639b879d1bdf2c72c979105460892fb41570cffee716679eb7b4124be188e28ca4c68d206c1cc9d49cd7489d63372853dbe83f874579238ecdd28c0dc265871d6dccf782b571f1004702121e8b15c9d8af9e6812dbbe742812c7e7cd1dafbdbe3d189f618936e270855700be8f6a7b528f271a936a2cae204b44d909ae3f6a8bcbfcda44b430397b1c96187e5a8362afe92bb9afb0a0a482cb6c8cac39a0fb1fe0034f8a965a3be425b4b34f67ff38a8ab30f8219a8933539c1d06d9b2997b6de743c568caea8b269642b8503b546c9e136d0e47775c8fef45d4489e6b4747c6accd6fad3d34fdd6cbafe07264e7ae1e025306c97d77a130093cc8d5ab8e4abe095787183a9084c569168011766b47dade4e3e1353a78f9f3464d8237b7de02da10c7a7b8951bafbaa898003ad9de997c89d8507393c6fb782b8f41aa99d5c92d5ed93e02a2e7550d42f178739898406badb6da850e305c10063b1a687a2b321a1f867ddfc7949d9764493af4f9681137101f87ec3c3733c0ee23a758a69dd5dbfccd20e0e7cc8543c213688ef9cc85bf9c539d3b6758e24befb3c1b617b7d59a17e915bb985df8229429430dd3057a8225d22afc2775e352a2d7c2f2f46786d4e6e984fb35ac6d7e1b57da82a6d1470895e56521c88c166f8124a4f0c5ada7d5e43174e319c21b9416735858ab50958def63c9a38e853d28a0f47b8e601beb0cdfb30d87070003f957ae347d5b03e80890311ded8018de0227c430f29ff20f0d0d1331dd5f22cff547847c0a26c1fdc272cd234b668823635f68e0797bf68fb1e531a423b1fae9b056fb8c0589908cd2774a7bea8da465248a438a22919d35e0ed8c5020f06824aa856c1a75e0d50d8e9c2dca471d249a97e8e8055d0927432577ef07e6658aa6ab3e9f5f4f50848b12dcdcd9594dae732864f9c6253cccf39922b5f1f8e16458a0c11db397017821de73a331400a76c2a5a29c7661405e9f244a92862a8ca13bc86a78a36744e52019c067573574f75e01b21c36e19a714e9cc0860e9df8e659cefab57002dc2b3d1a2918dc20ff25bc0d87023813abcbbe29defa514bd71fedf314a140508c7e8dd4ace82d56cfd6307fc8299a65c8b3b0719881dc06070d670729902ebfa1dc0b88050e5824cc186454ec2727d0fb2f95eb677f949375a0a31661c7f2bc452426a052b160b0654bffae35766a5317b845582176f1ec52e5bb7d814651781e268cfaefcf6da560810d84343dab8a8b2f2f7976334043498f529d75f9dec893bafdde0ebf003ea7d43f22d8e4eb3afea7be8bd22a9adb9334db2d6b05b8bfe72a96ca2c5ecc925333e4076bf5b7d9ed519ac3eb87c73d0c8121b1034424991561eccb669807a722bcd43141915c9db90f7a8a8e732054970645da1845b988f21cd5d2a89abd8e14c0e6532a3db89e43571b795d6f475b11c16cd7253a4538f4e73d0e3791e0c8f3e51ce3d9645062f249549d9165185fe6920659fe72ae01f69c6d5cef5a01cbbce0fcfd671e1a0aac35d541210a723d2fde91f37c130657d8825662bc46ca7780e07422ce2e7e5cbc1b15ad29b8473ffb832f45c480e960d620267561b3e3112c54359459c3f0235eb6eb2720dd5cf65f88267e099ae87ec7e35b3a915f18a4ab67583ccb4d907637812d797dfa51acc7b5cb13ab58934217a562b00a4a3d030bd9d3565a47c95396034bd65d39d39a6e7795f13e5031d148db16eddba996e1e70730eee02c47bd8b5c42812a12a2db5490fc3ad50d7d03c72c0e933ed8b43f8e34124e272cb39e06e628f18acfe4488dcced67a2c47008801e8d2db5dc7f7556d38020d53512993f3efeb4b07fd1e7b631deeeda74983011ca401ec7b86eb2a7a4d341f97337d37ada0dbbe124fe481ecac3e9b8e8f3b8b90ccf81ec028f2ee4e62934abcfcc2647966f6eea6563a0fc8fc75348f5fb3d2390db24d49858bbca822217fa81d240cacb7b2f6c2e4bad8a7a112b83a5d35ad68ec1cd599afee41fd4e860097f33afbc2cd790b2933f1194549c5aa3fe5c651a456c8ba7c8fa5ee5492233c21a80bd9216fcfccc03ecb76af3849711a0f69d5a261ce94484c30f4b74ca6cb4d7d5c4dcc0be1f0390c208e1e7e863700c6dce7ea5ab3831c00e586094a6a1f3b32dfbbf99a7581f90001dd558738804d0663a59d77407b6ab1ef3a82c156bc58d5a694a365b300a90ebbcddc49bbe5ba63c88e7a6e0faf5364ea17cabc602ddbf87a4c2f55b068ef296be5bb66befc1e37ad77f8e97c08f02d17dcdeb47959b0f46c2ae2c3d99a948f2a52c5793d53fe57876c38336a74786042abafb63c2154096eaed98598aed76da5a17ae179e79f848b237bdd6db63e5fbe77ee28b2bdcae462905ce1827800407317c2a42fc0dc234b2183db9097c0fae23da91aca6b1b7894537b0dc8524536573a34ef68596021cba863ece0de4a068f806d888aa03ed88ad92f375860f8885c5533c637a7a330c24aa0357f007ac3678e59cb1f6aa7c6979e15fd107a98ab42a635a3c3e70b58a19ec73b4bdc482000c3dfb4af84012ea3957d3d30b80857d9e06a2e677c84e5d9041ad4bf22afbdf0351f6d5c7a7a2ada3dd5ab4e48e37d51e5fad56cf9963715438c5f04b9772773893a59e2e46c6b7e19e9001650b66b469f4b1c4d188b286d5ce8b21269179e772147c7cb09eaee9b9de684ffc33068e5d346e79b710d82fd1278aee64ddd4ed37a944e6c745217c6a626444aa95b565c1f68a12cd2b86a61927896884bd5a76a9df4f6fe548bc16444272ec1e856334d64e0f32ba90daa77085b0683e3e010abf571dc564fc703a12998c72b6712386cfa4ccc802c850a3604bb0b2d5cd2eb6e788d475ff198f94a220c925a32ab6d69b037f1b9f0f4ce1d1b89cc0d07fc047073657405630200033fb971149dc9881cf31b7bd90de445f0ada69611016c5fde4af5bffe2b40a1a27d651a1d2127b0a95539b18fbb835f5145c1c4c7492866c6bd08ba260abb300720d2d42b729b72c6166f9ae0e4ac09a0f6851ca65444bed00b72b7f12befbbd007fc047073657407210252a4b012198c2131d70498b5939c401c01eb1178dfd58123b55766b03f008f7b00";
        assert_eq!(elements::encode::serialize_hex(&psbt), expected);
    }

    #[test]
    fn test_update_item_tr_no_script() {
        // keys taken from: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#Specifications
        let root_xpub = Xpub::from_str("xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8").unwrap();
        let fingerprint = root_xpub.fingerprint();
        let desc = format!("eltr([{}/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/0)", fingerprint);
        let desc = Descriptor::from_str(&desc).unwrap();
        let mut psbt_input = psbt::Input::default();
        psbt_input.update_with_descriptor_unchecked(&desc).unwrap();
        let mut psbt_output = psbt::Output::default();
        psbt_output.update_with_descriptor_unchecked(&desc).unwrap();
        let internal_key = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        assert_eq!(psbt_input.tap_internal_key, Some(internal_key));
        assert_eq!(
            psbt_input.tap_key_origins.get(&internal_key),
            Some(&(
                vec![],
                (
                    fingerprint,
                    DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap()
                )
            ))
        );
        assert_eq!(psbt_input.tap_key_origins.len(), 1);
        assert_eq!(psbt_input.tap_scripts.len(), 0);
        assert_eq!(psbt_input.tap_merkle_root, None);

        assert_eq!(psbt_output.tap_internal_key, psbt_input.tap_internal_key);
        assert_eq!(psbt_output.tap_key_origins, psbt_input.tap_key_origins);
        assert_eq!(psbt_output.tap_tree, None);
    }

    #[test]
    fn test_update_item_tr_with_tapscript() {
        use crate::Tap;
        // keys taken from: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#Specifications
        let root_xpub = Xpub::from_str("xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8").unwrap();
        let fingerprint = root_xpub.fingerprint();
        let xpub = format!("[{}/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ", fingerprint);
        let desc = format!(
            "eltr({}/0/0,{{pkh({}/0/1),multi_a(2,{}/0/1,{}/1/0)}})",
            xpub, xpub, xpub, xpub
        );

        let desc = Descriptor::from_str(&desc).unwrap();
        let internal_key = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        let mut psbt_input = psbt::Input::default();
        psbt_input.update_with_descriptor_unchecked(&desc).unwrap();
        let mut psbt_output = psbt::Output::default();
        psbt_output.update_with_descriptor_unchecked(&desc).unwrap();
        assert_eq!(psbt_input.tap_internal_key, Some(internal_key));
        assert_eq!(
            psbt_input.tap_key_origins.get(&internal_key),
            Some(&(
                vec![],
                (
                    fingerprint,
                    DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap()
                )
            ))
        );
        assert_eq!(psbt_input.tap_key_origins.len(), 3);
        assert_eq!(psbt_input.tap_scripts.len(), 2);
        assert!(psbt_input.tap_merkle_root.is_some());

        assert_eq!(psbt_output.tap_internal_key, psbt_input.tap_internal_key);
        assert_eq!(psbt_output.tap_key_origins, psbt_input.tap_key_origins);
        assert!(psbt_output.tap_tree.is_some());

        let key_0_1 = XOnlyPublicKey::from_str(
            "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
        )
        .unwrap();
        let first_leaf_hash = {
            let ms =
                Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!("pkh({})", &key_0_1)).unwrap();
            let first_script = ms.encode();
            assert!(psbt_input
                .tap_scripts
                .values()
                .any(|value| *value == (first_script.clone(), LeafVersion::default())));
            TapLeafHash::from_script(&first_script, LeafVersion::default())
        };

        {
            // check 0/1
            let (leaf_hashes, (key_fingerprint, deriv_path)) =
                psbt_input.tap_key_origins.get(&key_0_1).unwrap();
            assert_eq!(key_fingerprint, &fingerprint);
            assert_eq!(&deriv_path.to_string(), "86'/0'/0'/0/1");
            assert_eq!(leaf_hashes.len(), 2);
            assert!(leaf_hashes.contains(&first_leaf_hash));
        }

        {
            // check 1/0
            let key_1_0 = XOnlyPublicKey::from_str(
                "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
            )
            .unwrap();
            let (leaf_hashes, (key_fingerprint, deriv_path)) =
                psbt_input.tap_key_origins.get(&key_1_0).unwrap();
            assert_eq!(key_fingerprint, &fingerprint);
            assert_eq!(&deriv_path.to_string(), "86'/0'/0'/1/0");
            assert_eq!(leaf_hashes.len(), 1);
            assert!(!leaf_hashes.contains(&first_leaf_hash));
        }
    }

    #[test]
    fn test_update_item_non_tr_multi() {
        // values taken from https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki (after removing zpub thingy)
        let root_xpub = Xpub::from_str("xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8").unwrap();
        let fingerprint = root_xpub.fingerprint();
        let xpub = format!("[{}/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V", fingerprint);
        let pubkeys = [
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
            "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
            "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6",
        ];

        let expected_bip32 = pubkeys
            .iter()
            .zip(["0/0", "0/1", "1/0"].iter())
            .map(|(pubkey, path)| {
                (
                    bitcoin::PublicKey::from_str(pubkey).unwrap(),
                    (
                        fingerprint,
                        DerivationPath::from_str(&format!("m/84'/0'/0'/{}", path)).unwrap(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();

        {
            // test segwit
            let desc = format!("elwsh(multi(2,{}/0/0,{}/0/1,{}/1/0))", xpub, xpub, xpub);
            let desc = Descriptor::from_str(&desc).unwrap();
            let derived = format!("elwsh(multi(2,{}))", pubkeys.join(","));
            let derived = Descriptor::<bitcoin::PublicKey>::from_str(&derived).unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input.update_with_descriptor_unchecked(&desc).unwrap();

            let mut psbt_output = psbt::Output::default();
            psbt_output.update_with_descriptor_unchecked(&desc).unwrap();

            assert_eq!(expected_bip32, psbt_input.bip32_derivation);
            assert_eq!(
                psbt_input.witness_script,
                Some(derived.explicit_script().unwrap())
            );

            assert_eq!(psbt_output.bip32_derivation, psbt_input.bip32_derivation);
            assert_eq!(psbt_output.witness_script, psbt_input.witness_script);
        }

        {
            // test non-segwit
            let desc = format!("elsh(multi(2,{}/0/0,{}/0/1,{}/1/0))", xpub, xpub, xpub);
            let desc = Descriptor::from_str(&desc).unwrap();
            let derived = format!("elsh(multi(2,{}))", pubkeys.join(","));
            let derived = Descriptor::<bitcoin::PublicKey>::from_str(&derived).unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input.update_with_descriptor_unchecked(&desc).unwrap();

            let mut psbt_output = psbt::Output::default();
            psbt_output.update_with_descriptor_unchecked(&desc).unwrap();

            assert_eq!(psbt_input.bip32_derivation, expected_bip32);
            assert_eq!(psbt_input.witness_script, None);
            assert_eq!(
                psbt_input.redeem_script,
                Some(derived.explicit_script().unwrap())
            );

            assert_eq!(psbt_output.bip32_derivation, psbt_input.bip32_derivation);
            assert_eq!(psbt_output.witness_script, psbt_input.witness_script);
            assert_eq!(psbt_output.redeem_script, psbt_input.redeem_script);
        }
    }

    #[test]
    fn test_update_input_checks() {
        let desc = "eltr([73c5da0a/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/0)";
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(desc).unwrap();

        let asset = elements::AssetId::from_str(
            "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
        )
        .unwrap();
        let mut non_witness_utxo = elements::Transaction {
            version: 1,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: elements::confidential::Value::Explicit(1_000),
                script_pubkey: Script::from_str(
                    "5120f370a017453c8a22123a43f83f7efced972ba1ef8320ae58e3997a94a64bb7ff",
                )
                .unwrap(),
                asset: elements::confidential::Asset::Explicit(asset),
                nonce: elements::confidential::Nonce::Null,
                witness: elements::TxOutWitness::default(),
            }],
        };

        let tx = elements::Transaction {
            version: 1,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: non_witness_utxo.txid(),
                    vout: 0,
                },
                is_pegin: false,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                asset_issuance: AssetIssuance::default(),
                witness: TxInWitness::default(),
            }],
            output: vec![],
        };

        let mut psbt = Psbt::from_tx(tx);
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Err(UtxoUpdateError::UtxoCheck),
            "neither *_utxo are not set"
        );
        psbt.inputs_mut()[0].witness_utxo = Some(non_witness_utxo.output[0].clone());
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Ok(()),
            "witness_utxo is set which is ok"
        );
        psbt.inputs_mut()[0].non_witness_utxo = Some(non_witness_utxo.clone());
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Ok(()),
            "matching non_witness_utxo"
        );
        non_witness_utxo.version = 0;
        psbt.inputs_mut()[0].non_witness_utxo = Some(non_witness_utxo);
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Err(UtxoUpdateError::UtxoCheck),
            "non_witness_utxo no longer matches"
        );
        psbt.inputs_mut()[0].non_witness_utxo = None;
        psbt.inputs_mut()[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = Script::default();
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Err(UtxoUpdateError::MismatchedScriptPubkey),
            "non_witness_utxo no longer matches"
        );
    }

    #[test]
    fn test_update_output_checks() {
        let desc = "eltr([73c5da0a/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/0)";
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(desc).unwrap();

        let tx = elements::Transaction {
            version: 1,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: confidential::Value::Explicit(1_000),
                script_pubkey: Script::from_str(
                    "5120f370a017453c8a22123a43f83f7efced972ba1ef8320ae58e3997a94a64bb7ff", // spk calculatations are differnet in elements because of different tagged hashes
                )
                .unwrap(),
                asset: confidential::Asset::Explicit(AssetId::default()),
                nonce: confidential::Nonce::Null,
                witness: Default::default(),
            }],
        };

        let mut psbt = Psbt::from_tx(tx);
        assert_eq!(
            psbt.update_output_with_descriptor(1, &desc),
            Err(OutputUpdateError::IndexOutOfBounds(1, 1)),
            "output index doesn't exist"
        );
        assert_eq!(
            psbt.update_output_with_descriptor(0, &desc),
            Ok(()),
            "script_pubkey should match"
        );
        psbt.outputs_mut()[0].script_pubkey = Script::default();
        assert_eq!(
            psbt.update_output_with_descriptor(0, &desc),
            Err(OutputUpdateError::MismatchedScriptPubkey),
            "output script_pubkey no longer matches"
        );
    }
}
