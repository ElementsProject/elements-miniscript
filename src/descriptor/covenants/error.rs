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
//! Covenant Descriptor Errors

use crate::Error;
use std::{error, fmt};
/// Covenant related Errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CovError {
    /// Missing script code (segwit sighash)
    MissingScriptCode,
    /// Missing value (segwit sighash)
    MissingValue,
    /// Missing a sighash Item in satisfier,
    MissingSighashItem(u8),
    /// Missing Sighash Signature
    /// This must be a secp signature serialized
    /// in DER format *with* the sighash byte
    MissingCovSignature,
    /// Bad(Malformed) Covenant Descriptor
    BadCovDescriptor,
    /// Cannot lift a Covenant Descriptor
    /// This is because the different components of the covenants
    /// might interact across branches and thus is
    /// not composable and could not be analyzed individually.
    CovenantLift,
    /// The Covenant Sighash type and the satisfier sighash
    /// type must be the same
    CovenantSighashTypeMismatch,
}

impl fmt::Display for CovError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CovError::MissingScriptCode => write!(f, "Missing Script code"),
            CovError::MissingValue => write!(f, "Missing value"),
            CovError::BadCovDescriptor => write!(f, "Bad or Malformed covenant descriptor"),
            CovError::CovenantLift => write!(f, "Cannot lift a covenant descriptor"),
            CovError::MissingSighashItem(i) => {
                write!(f, "Missing sighash item # : {} in satisfier", i)
            }
            CovError::MissingCovSignature => write!(f, "Missing signature over the covenant pk"),
            CovError::CovenantSighashTypeMismatch => write!(
                f,
                "The sighash type provided in the witness must the same \
                as the one used in signature"
            ),
        }
    }
}

impl error::Error for CovError {}

#[doc(hidden)]
impl From<CovError> for Error {
    fn from(e: CovError) -> Error {
        Error::CovError(e)
    }
}
