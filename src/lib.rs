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

//! Miniscript and Output Descriptors
//!
//! # Introduction
//! ## Bitcoin Script
//!
//! In Bitcoin, spending policies are defined and enforced by means of a
//! stack-based programming language known as Bitcoin Script. While this
//! language appears to be designed with tractable analysis in mind (e.g.
//! there are no looping or jumping constructions), in practice this is
//! extremely difficult. As a result, typical wallet software supports only
//! a small set of script templates, cannot interoperate with other similar
//! software, and each wallet contains independently written ad-hoc manually
//! verified code to handle these templates. Users who require more complex
//! spending policies, or who want to combine signing infrastructure which
//! was not explicitly designed to work together, are simply out of luck.
//!
//! ## Miniscript
//!
//! Miniscript is an alternative to Bitcoin Script which eliminates these
//! problems. It can be efficiently and simply encoded as Script to ensure
//! that it works on the Bitcoin blockchain, but its design is very different.
//! Essentially, a Miniscript is a monotone function (tree of ANDs, ORs and
//! thresholds) of signature requirements, hash preimage requirements, and
//! timelocks.
//!
//! A [full description of Miniscript is available here](http://bitcoin.sipa.be/miniscript/miniscript.html).
//!
//! Miniscript also admits a more human-readable encoding.
//!
//! ## Elements Miniscript
//!
//! Elements Miniscript is a fork of miniscript for [elements](https://github.com/ElementsProject/elements) sidechain.
//!
//! ## Output Descriptors
//!
//! While spending policies in Bitcoin are entirely defined by Script; there
//! are multiple ways of embedding these Scripts in transaction outputs; for
//! example, P2SH or Segwit v0. These different embeddings are expressed by
//! *Output Descriptors*, [which are described here](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
//! Elements descriptors are extension of bitcoin Output descriptors with support
//! for blinded descriptors(WIP)
//! # Examples
//!
//! ## Deriving an address from a descriptor
//!
//! ```rust
//! extern crate bitcoin;
//! extern crate elements;
//! extern crate elements_miniscript as miniscript;
//!
//! use std::str::FromStr;
//!
//! fn main() {
//!     // Elements descriptors are prefixed by string el
//!     let desc = miniscript::Descriptor::<
//!         bitcoin::PublicKey,
//!     >::from_str("\
//!         elsh(wsh(or_d(\
//!             c:pk_k(020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261),\
//!             c:pk_k(0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352)\
//!         )))\
//!     ").unwrap();
//!
//!     // Derive the P2SH address
//!     assert_eq!(
//!         desc.address(&elements::AddressParams::ELEMENTS).unwrap().to_string(),
//!         "XMyBX13qCo5Lp65mymgYVdmsYR5bcznWUa"
//!     );
//!
//!     // Check whether the descriptor is safe
//!     // This checks whether all spend paths are accessible in bitcoin network.
//!     // It maybe possible that some of the spend require more than 100 elements in Wsh scripts
//!     // Or they contain a combination of timelock and heightlock.
//!     assert!(desc.sanity_check().is_ok());
//!
//!     // Estimate the satisfaction cost
//!     assert_eq!(desc.max_satisfaction_weight().unwrap(), 293);
//! }
//! ```
//!
//!
#![allow(bare_trait_objects)]
#![cfg_attr(all(test, feature = "unstable"), feature(test))]
// Coding conventions
#![deny(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

pub use {bitcoin, elements};
#[cfg(feature = "serde")]
pub extern crate serde;
#[cfg(all(test, feature = "unstable"))]
extern crate test;

// Miniscript imports
// It can be confusing to code when we have two miniscript libraries
// As a rule, only import the library here and pub use all the required
// items. Should help in faster code development in the long run
extern crate miniscript as bitcoin_miniscript;
pub(crate) use crate::bitcoin_miniscript::expression::{FromTree as BtcFromTree, Tree as BtcTree};
pub(crate) use crate::bitcoin_miniscript::policy::semantic::Policy as BtcPolicy;
pub(crate) use crate::bitcoin_miniscript::policy::Liftable as BtcLiftable;
pub(crate) use crate::bitcoin_miniscript::{
    Descriptor as BtcDescriptor, DescriptorTrait as BtcDescriptorTrait, Error as BtcError,
    Miniscript as BtcMiniscript, Satisfier as BtcSatisfier, Segwitv0 as BtcSegwitv0,
    Terminal as BtcTerminal,
};
// re-export imports
pub use crate::bitcoin_miniscript::{
    DummyKey, DummyKeyHash, ForEach, ForEachKey, MiniscriptKey, ToPublicKey, TranslatePk,
    TranslatePk1, TranslatePk2, TranslatePk3,
};
// End imports

#[macro_use]
mod macros;

pub mod descriptor;
pub mod expression;
pub mod extensions;
pub mod interpreter;
pub mod miniscript;
pub mod policy;
pub mod psbt;
pub mod timelock;

mod util;

use std::{error, fmt, str};

use elements::hashes::sha256;
use elements::secp256k1_zkp::Secp256k1;
use elements::{opcodes, script, secp256k1_zkp};

pub use crate::descriptor::{Descriptor, DescriptorPublicKey};
use crate::extensions::{CovenantExt, Extension, NoExt};
pub use crate::interpreter::Interpreter;
pub use crate::miniscript::context::{BareCtx, Legacy, ScriptContext, Segwitv0, Tap};
pub use crate::miniscript::decode::Terminal;
pub use crate::miniscript::satisfy::{
    elementssig_from_rawsig, elementssig_to_rawsig, ElementsSig, Preimage32, Satisfier,
};
pub use crate::miniscript::Miniscript;

// minimal implementation of contract hash module
mod contracthash {
    use bitcoin::PublicKey;
    use elements::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
    use elements::secp256k1_zkp::{self, Secp256k1};

    /// Tweak a single key using some arbitrary data
    pub(super) fn tweak_key<C: secp256k1_zkp::Verification>(
        secp: &Secp256k1<C>,
        mut key: PublicKey,
        contract: &[u8],
    ) -> PublicKey {
        let hmac_result = compute_tweak(&key, contract);
        key.inner
            .add_exp_assign(secp, &hmac_result[..])
            .expect("HMAC cannot produce invalid tweak");
        key
    }

    /// Compute a tweak from some given data for the given public key
    fn compute_tweak(pk: &PublicKey, contract: &[u8]) -> Hmac<sha256::Hash> {
        let mut hmac_engine: HmacEngine<sha256::Hash> = if pk.compressed {
            HmacEngine::new(&pk.inner.serialize())
        } else {
            HmacEngine::new(&pk.inner.serialize_uncompressed())
        };
        hmac_engine.input(contract);
        Hmac::from_engine(hmac_engine)
    }
}

/// Same as upstream [`TranslatePk`] but with support for extensions
pub trait TranslatePkExt<P: MiniscriptKey, Q: MiniscriptKey, QExt: Extension<Q>> {
    /// The associated output type. This must be Self<Q>
    type Output;

    /// Translate a struct from one Generic to another where the
    /// translation for Pk is provided by translatefpk, and translation for
    /// PkH is provided by translatefpkh
    fn translate_pk<Fpk, Fpkh, E>(
        &self,
        translatefpk: Fpk,
        translatefpkh: Fpkh,
    ) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>;

    /// Calls `translate_pk` with conversion functions that cannot fail
    fn translate_pk_infallible<Fpk, Fpkh>(
        &self,
        mut translatefpk: Fpk,
        mut translatefpkh: Fpkh,
    ) -> Self::Output
    where
        Fpk: FnMut(&P) -> Q,
        Fpkh: FnMut(&P::Hash) -> Q::Hash,
    {
        self.translate_pk::<_, _, ()>(|pk| Ok(translatefpk(pk)), |pkh| Ok(translatefpkh(pkh)))
            .expect("infallible translation function")
    }
}

/// Tweak a MiniscriptKey to obtain the tweaked key
// Ideally, we want this in a trait, but doing so we cannot
// use it in the implementation of DescriptorTrait from
// rust-miniscript because it would require stricter bounds.
pub fn tweak_key<Pk, C: secp256k1_zkp::Verification>(
    pk: &Pk,
    secp: &Secp256k1<C>,
    contract: &[u8],
) -> bitcoin::PublicKey
where
    Pk: MiniscriptKey + ToPublicKey,
{
    let pk = pk.to_public_key();
    contracthash::tweak_key(secp, pk, contract)
}
/// Miniscript

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Opcode appeared which is not part of the script subset
    InvalidOpcode(opcodes::All),
    /// Some opcode occurred followed by `OP_VERIFY` when it had
    /// a `VERIFY` version that should have been used instead
    NonMinimalVerify(String),
    /// Push was illegal in some context
    InvalidPush(Vec<u8>),
    /// rust-bitcoin script error
    Script(script::Error),
    /// rust-bitcoin address error
    AddrError(bitcoin::util::address::Error),
    /// A `CHECKMULTISIG` opcode was preceded by a number > 20
    CmsTooManyKeys(u32),
    /// A tapscript multi_a cannot support more than MAX_BLOCK_WEIGHT/32 keys
    MultiATooManyKeys(u32),
    /// Encountered unprintable character in descriptor
    Unprintable(u8),
    /// expected character while parsing descriptor; didn't find one
    ExpectedChar(char),
    /// While parsing backward, hit beginning of script
    UnexpectedStart,
    /// Got something we were not expecting
    Unexpected(String),
    /// Name of a fragment contained `:` multiple times
    MultiColon(String),
    /// Name of a fragment contained `@` multiple times
    MultiAt(String),
    /// Name of a fragment contained `@` but we were not parsing an OR
    AtOutsideOr(String),
    /// Encountered a `l:0` which is syntactically equal to `u:0` except stupid
    LikelyFalse,
    /// Encountered a wrapping character that we don't recognize
    UnknownWrapper(char),
    /// Parsed a miniscript and the result was not of type T
    NonTopLevel(String),
    /// Parsed a miniscript but there were more script opcodes after it
    Trailing(String),
    /// Failed to parse a push as a public key
    BadPubkey(bitcoin::util::key::Error),
    /// Could not satisfy a script (fragment) because of a missing hash preimage
    MissingHash(sha256::Hash),
    /// Could not satisfy a script (fragment) because of a missing signature
    MissingSig(bitcoin::PublicKey),
    /// Could not satisfy, relative locktime not met
    RelativeLocktimeNotMet(u32),
    /// Could not satisfy, absolute locktime not met
    AbsoluteLocktimeNotMet(u32),
    /// General failure to satisfy
    CouldNotSatisfy,
    /// Typechecking failed
    TypeCheck(String),
    /// General error in creating descriptor
    BadDescriptor(String),
    /// Forward-secp related errors
    Secp(elements::secp256k1_zkp::Error),
    #[cfg(feature = "compiler")]
    /// Compiler related errors
    CompilerError(policy::compiler::CompilerError),
    /// Errors related to policy
    PolicyError(policy::concrete::PolicyError),
    /// Errors related to lifting
    LiftError(policy::LiftError),
    /// Forward script context related errors
    ContextError(miniscript::context::ScriptContextError),
    /// Recursion depth exceeded when parsing policy/miniscript from string
    MaxRecursiveDepthExceeded,
    /// Script size too large
    ScriptSizeTooLarge,
    /// Anything but c:pk(key) (P2PK), c:pk_h(key) (P2PKH), and thresh_m(k,...)
    /// up to n=3 is invalid by standardness (bare)
    NonStandardBareScript,
    /// Analysis Error
    AnalysisError(miniscript::analyzable::AnalysisError),
    /// Miniscript is equivalent to false. No possible satisfaction
    ImpossibleSatisfaction,
    /// Bare descriptors don't have any addresses
    BareDescriptorAddr,
    /// Upstream Miniscript Errors
    BtcError(bitcoin_miniscript::Error),
    /// Covenant Error
    CovError(descriptor::CovError),
    /// PubKey invalid under current context
    PubKeyCtxError(miniscript::decode::KeyParseError, &'static str),
    /// Attempted to call function that requires PreComputed taproot info
    TaprootSpendInfoUnavialable,
    /// No script code for Tr descriptors
    TrNoScriptCode,
    /// No explicit script for Tr descriptors
    TrNoExplicitScript,
}

#[doc(hidden)]
impl<Pk, Ctx, Ext> From<miniscript::types::Error<Pk, Ctx, Ext>> for Error
where
    Pk: MiniscriptKey,
    Ctx: ScriptContext,
    Ext: Extension<Pk>,
{
    fn from(e: miniscript::types::Error<Pk, Ctx, Ext>) -> Error {
        Error::TypeCheck(e.to_string())
    }
}

#[doc(hidden)]
impl From<bitcoin_miniscript::Error> for Error {
    fn from(e: bitcoin_miniscript::Error) -> Error {
        Error::BtcError(e)
    }
}

#[doc(hidden)]
impl From<policy::LiftError> for Error {
    fn from(e: policy::LiftError) -> Error {
        Error::LiftError(e)
    }
}

#[doc(hidden)]
impl From<miniscript::context::ScriptContextError> for Error {
    fn from(e: miniscript::context::ScriptContextError) -> Error {
        Error::ContextError(e)
    }
}

#[doc(hidden)]
impl From<miniscript::analyzable::AnalysisError> for Error {
    fn from(e: miniscript::analyzable::AnalysisError) -> Error {
        Error::AnalysisError(e)
    }
}

#[doc(hidden)]
impl From<elements::secp256k1_zkp::Error> for Error {
    fn from(e: elements::secp256k1_zkp::Error) -> Error {
        Error::Secp(e)
    }
}

#[doc(hidden)]
impl From<elements::secp256k1_zkp::UpstreamError> for Error {
    fn from(e: elements::secp256k1_zkp::UpstreamError) -> Error {
        Error::Secp(elements::secp256k1_zkp::Error::Upstream(e))
    }
}

#[doc(hidden)]
impl From<bitcoin::util::key::Error> for Error {
    fn from(e: bitcoin::util::key::Error) -> Error {
        Error::BadPubkey(e)
    }
}

impl From<bitcoin::util::address::Error> for Error {
    fn from(e: bitcoin::util::address::Error) -> Error {
        Error::AddrError(e)
    }
}

fn errstr(s: &str) -> Error {
    Error::Unexpected(s.to_owned())
}

// https://github.com/sipa/miniscript/pull/5 for discussion on this number
const MAX_RECURSION_DEPTH: u32 = 402;
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
const MAX_SCRIPT_SIZE: u32 = 10000;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::InvalidOpcode(op) => write!(f, "invalid opcode {}", op),
            Error::NonMinimalVerify(ref tok) => write!(f, "{} VERIFY", tok),
            Error::InvalidPush(ref push) => write!(f, "invalid push {:?}", push), // TODO hexify this
            Error::Script(ref e) => fmt::Display::fmt(e, f),
            Error::AddrError(ref e) => fmt::Display::fmt(e, f),
            Error::CmsTooManyKeys(n) => write!(f, "checkmultisig with {} keys", n),
            Error::Unprintable(x) => write!(f, "unprintable character 0x{:02x}", x),
            Error::ExpectedChar(c) => write!(f, "expected {}", c),
            Error::UnexpectedStart => f.write_str("unexpected start of script"),
            Error::Unexpected(ref s) => write!(f, "unexpected «{}»", s),
            Error::MultiColon(ref s) => write!(f, "«{}» has multiple instances of «:»", s),
            Error::MultiAt(ref s) => write!(f, "«{}» has multiple instances of «@»", s),
            Error::AtOutsideOr(ref s) => write!(f, "«{}» contains «@» in non-or() context", s),
            Error::LikelyFalse => write!(f, "0 is not very likely (use «u:0»)"),
            Error::UnknownWrapper(ch) => write!(f, "unknown wrapper «{}:»", ch),
            Error::NonTopLevel(ref s) => write!(f, "non-T miniscript: {}", s),
            Error::Trailing(ref s) => write!(f, "trailing tokens: {}", s),
            Error::MissingHash(ref h) => write!(f, "missing preimage of hash {}", h),
            Error::MissingSig(ref pk) => write!(f, "missing signature for key {:?}", pk),
            Error::RelativeLocktimeNotMet(n) => {
                write!(f, "required relative locktime CSV of {} blocks, not met", n)
            }
            Error::AbsoluteLocktimeNotMet(n) => write!(
                f,
                "required absolute locktime CLTV of {} blocks, not met",
                n
            ),
            Error::CouldNotSatisfy => f.write_str("could not satisfy"),
            Error::BadPubkey(ref e) => fmt::Display::fmt(e, f),
            Error::TypeCheck(ref e) => write!(f, "typecheck: {}", e),
            Error::BadDescriptor(ref e) => write!(f, "Invalid descriptor: {}", e),
            Error::Secp(ref e) => fmt::Display::fmt(e, f),
            Error::ContextError(ref e) => fmt::Display::fmt(e, f),
            #[cfg(feature = "compiler")]
            Error::CompilerError(ref e) => fmt::Display::fmt(e, f),
            Error::PolicyError(ref e) => fmt::Display::fmt(e, f),
            Error::LiftError(ref e) => fmt::Display::fmt(e, f),
            Error::MaxRecursiveDepthExceeded => write!(
                f,
                "Recursive depth over {} not permitted",
                MAX_RECURSION_DEPTH
            ),
            Error::ScriptSizeTooLarge => write!(
                f,
                "Standardness rules imply bitcoin than {} bytes",
                MAX_SCRIPT_SIZE
            ),
            Error::NonStandardBareScript => write!(
                f,
                "Anything but c:pk(key) (P2PK), c:pk_h(key) (P2PKH), and thresh_m(k,...) \
                up to n=3 is invalid by standardness (bare).
                "
            ),
            Error::AnalysisError(ref e) => e.fmt(f),
            Error::ImpossibleSatisfaction => write!(f, "Impossible to satisfy Miniscript"),
            Error::BareDescriptorAddr => write!(f, "Bare descriptors don't have address"),
            Error::BtcError(ref e) => write!(f, " Bitcoin Miniscript Error {}", e),
            Error::CovError(ref e) => write!(f, "Covenant Error: {}", e),
            Error::PubKeyCtxError(ref pk, ref ctx) => {
                write!(f, "Pubkey error: {} under {} scriptcontext", pk, ctx)
            }
            Error::MultiATooManyKeys(k) => {
                write!(f, "MultiA too many keys {}", k)
            }
            Error::TaprootSpendInfoUnavialable => {
                write!(f, "Taproot Spend Info not computed.")
            }
            Error::TrNoScriptCode => {
                write!(f, "No script code for Tr descriptors")
            }
            Error::TrNoExplicitScript => {
                write!(f, "No script code for Tr descriptors")
            }
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::Error::*;

        match self {
            InvalidOpcode(_)
            | NonMinimalVerify(_)
            | InvalidPush(_)
            | CmsTooManyKeys(_)
            | MultiATooManyKeys(_)
            | Unprintable(_)
            | ExpectedChar(_)
            | UnexpectedStart
            | Unexpected(_)
            | MultiColon(_)
            | MultiAt(_)
            | AtOutsideOr(_)
            | LikelyFalse
            | UnknownWrapper(_)
            | NonTopLevel(_)
            | Trailing(_)
            | MissingHash(_)
            | MissingSig(_)
            | RelativeLocktimeNotMet(_)
            | AbsoluteLocktimeNotMet(_)
            | CouldNotSatisfy
            | TypeCheck(_)
            | BadDescriptor(_)
            | MaxRecursiveDepthExceeded
            | ScriptSizeTooLarge
            | NonStandardBareScript
            | ImpossibleSatisfaction
            | BareDescriptorAddr
            | TaprootSpendInfoUnavialable
            | TrNoScriptCode
            | TrNoExplicitScript => None,
            BtcError(e) => Some(e),
            CovError(e) => Some(e),
            Script(_e) => None, // should be Some(e), but requires changes upstream
            AddrError(e) => Some(e),
            BadPubkey(e) => Some(e),
            Secp(e) => Some(e),
            #[cfg(feature = "compiler")]
            CompilerError(e) => Some(e),
            PolicyError(e) => Some(e),
            LiftError(e) => Some(e),
            ContextError(e) => Some(e),
            AnalysisError(e) => Some(e),
            PubKeyCtxError(e, _) => Some(e),
        }
    }
}

#[doc(hidden)]
#[cfg(feature = "compiler")]
impl From<policy::compiler::CompilerError> for Error {
    fn from(e: policy::compiler::CompilerError) -> Error {
        Error::CompilerError(e)
    }
}

#[doc(hidden)]
impl From<policy::concrete::PolicyError> for Error {
    fn from(e: policy::concrete::PolicyError) -> Error {
        Error::PolicyError(e)
    }
}

/// The size of an encoding of a number in Script
pub fn script_num_size(n: usize) -> usize {
    match n {
        n if n <= 0x10 => 1,      // OP_n
        n if n < 0x80 => 2,       // OP_PUSH1 <n>
        n if n < 0x8000 => 3,     // OP_PUSH2 <n>
        n if n < 0x800000 => 4,   // OP_PUSH3 <n>
        n if n < 0x80000000 => 5, // OP_PUSH4 <n>
        _ => 6,                   // OP_PUSH5 <n>
    }
}

/// Returns the size of the smallest push opcode used to push a given number of bytes onto the stack
///
/// For sizes ≤ 75, there are dedicated single-byte opcodes, so the push size is one. Otherwise,
/// if the size can fit into 1, 2 or 4 bytes, we use the `PUSHDATA{1,2,4}` opcode respectively,
/// followed by the actual size encoded in that many bytes.
fn push_opcode_size(script_size: usize) -> usize {
    if script_size < 76 {
        1
    } else if script_size < 0x100 {
        2
    } else if script_size < 0x10000 {
        3
    } else {
        5
    }
}

/// Helper function used by tests
#[cfg(test)]
fn hex_script(s: &str) -> elements::Script {
    let v: Vec<u8> = elements::hashes::hex::FromHex::from_hex(s).unwrap();
    elements::Script::from(v)
}
