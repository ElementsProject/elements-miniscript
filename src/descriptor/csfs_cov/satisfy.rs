// Miniscript
// Written in 2021 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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
//! Covenant Descriptor Satisfaction

use elements::encode::Encodable;
use elements::hashes::{sha256d, Hash};
use elements::sighash::SighashCache;
use elements::{self, confidential, EcdsaSighashType, OutPoint, Script, Sighash, Transaction};

use super::CovError;
use crate::{MiniscriptKey, Satisfier, ToPublicKey};

/// A satisfier for Covenant descriptors
/// that can do transaction introspection
/// 'tx denotes the lifetime of the transaction
/// being satisfied and 'ptx denotes the lifetime
/// of the previous transaction inputs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyCovSatisfier<'tx, 'ptx> {
    // Common fields in Segwit and Taphash
    /// The transaction being spent
    tx: &'tx Transaction,
    /// The script code required for
    /// The input index being spent
    idx: u32,
    /// The sighash type
    hash_type: EcdsaSighashType,

    // Segwitv0
    /// The script code required for segwit sighash
    script_code: Option<&'ptx Script>,
    /// The value of the output being spent
    value: Option<confidential::Value>,
}

impl<'tx, 'ptx> LegacyCovSatisfier<'tx, 'ptx> {
    /// Create  a new Covsatisfier for v0 spends
    /// Panics if idx is out of bounds
    pub fn new_segwitv0(
        tx: &'tx Transaction,
        idx: u32,
        value: confidential::Value,
        script_code: &'ptx Script,
        hash_type: EcdsaSighashType,
    ) -> Self {
        assert!((idx as usize) < tx.input.len());
        Self {
            tx,
            idx,
            hash_type,
            script_code: Some(script_code),
            value: Some(value),
        }
    }

    /// Easy way to get sighash since we already have
    /// all the required information.
    /// Note that this does not do any caching, so it
    /// will be slightly inefficient as compared to
    /// using sighash
    pub fn segwit_sighash(&self) -> Result<Sighash, CovError> {
        let mut cache = SighashCache::new(self.tx);
        // TODO: error types
        let script_code = self.script_code.ok_or(CovError::MissingScriptCode)?;
        let value = self.value.ok_or(CovError::MissingValue)?;
        Ok(cache.segwitv0_sighash(self.idx as usize, script_code, value, self.hash_type))
    }
}

impl<'tx, 'ptx, Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for LegacyCovSatisfier<'tx, 'ptx> {
    fn lookup_nversion(&self) -> Option<u32> {
        Some(self.tx.version)
    }

    fn lookup_hashprevouts(&self) -> Option<sha256d::Hash> {
        let mut enc = sha256d::Hash::engine();
        for txin in &self.tx.input {
            txin.previous_output.consensus_encode(&mut enc).unwrap();
        }
        Some(sha256d::Hash::from_engine(enc))
    }

    fn lookup_hashsequence(&self) -> Option<sha256d::Hash> {
        let mut enc = sha256d::Hash::engine();
        for txin in &self.tx.input {
            txin.sequence.consensus_encode(&mut enc).unwrap();
        }
        Some(sha256d::Hash::from_engine(enc))
    }

    fn lookup_hashissuances(&self) -> Option<sha256d::Hash> {
        let mut enc = sha256d::Hash::engine();
        for txin in &self.tx.input {
            if txin.has_issuance() {
                txin.asset_issuance.consensus_encode(&mut enc).unwrap();
            } else {
                0u8.consensus_encode(&mut enc).unwrap();
            }
        }
        Some(sha256d::Hash::from_engine(enc))
    }

    fn lookup_outpoint(&self) -> Option<OutPoint> {
        Some(self.tx.input[self.idx as usize].previous_output)
    }

    fn lookup_scriptcode(&self) -> Option<&Script> {
        self.script_code
    }

    fn lookup_value(&self) -> Option<confidential::Value> {
        self.value
    }

    fn lookup_nsequence(&self) -> Option<u32> {
        Some(self.tx.input[self.idx as usize].sequence.to_consensus_u32())
    }

    fn lookup_outputs(&self) -> Option<&[elements::TxOut]> {
        Some(&self.tx.output)
    }

    fn lookup_nlocktime(&self) -> Option<u32> {
        Some(self.tx.lock_time.to_consensus_u32())
    }

    fn lookup_sighashu32(&self) -> Option<u32> {
        Some(self.hash_type.as_u32())
    }
}
