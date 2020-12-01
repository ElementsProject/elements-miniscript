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
//! ## Output Descriptors
//!
//! While spending policies in Bitcoin are entirely defined by Script; there
//! are multiple ways of embedding these Scripts in transaction outputs; for
//! example, P2SH or Segwit v0. These different embeddings are expressed by
//! *Output Descriptors*, [which are described here](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
//!
//! # Examples
//!
//! ## Deriving an address from a descriptor
//!
//! ```rust
//! extern crate bitcoin;
//! extern crate elements;
//! extern crate miniscript;
//!
//! use std::str::FromStr;
//! use miniscript::{NullCtx, DescriptorTrait};
//!
//! fn main() {
//!     let desc = miniscript::Descriptor::<
//!         bitcoin::PublicKey,
//!     >::from_str("\
//!         sh(wsh(or_d(\
//!             c:pk_k(020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261),\
//!             c:pk_k(0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352)\
//!         )))\
//!     ").unwrap();
//!
//!     // Sometimes it is necessary to have additional information to get the bitcoin::PublicKey
//!     // from the MiniscriptKey which can supplied by `to_pk_ctx` parameter. For example,
//!     // when calculating the script pubkey of a descriptor with xpubs, the secp context and
//!     // child information maybe required.
//!
//!     // Derive the P2SH address
//!     assert_eq!(
//!         desc.address(NullCtx, &elements::AddressParams::ELEMENTS).unwrap().to_string(),
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
// #![deny(unsafe_code)]
// #![deny(non_upper_case_globals)]
// #![deny(non_camel_case_types)]
// #![deny(non_snake_case)]
// #![deny(unused_mut)]
// #![deny(dead_code)]
// #![deny(unused_imports)]
// #![deny(missing_docs)]

pub extern crate bitcoin;
pub extern crate elements;
#[cfg(feature = "serde")]
pub extern crate serde;
#[cfg(all(test, feature = "unstable"))]
extern crate test;

#[macro_use]
mod macros;

pub mod descriptor;
pub mod expression;
// pub mod interpreter;
pub mod miniscript;
pub mod policy;

mod util;

use std::str::FromStr;
use std::{error, fmt, hash, str};

use elements::hashes::{hash160, sha256, Hash};
use elements::{opcodes, script};

pub use descriptor::{Descriptor, DescriptorPublicKey, DescriptorPublicKeyCtx, DescriptorTrait};
// pub use interpreter::Interpreter;
pub use miniscript::context::{BareCtx, Legacy, ScriptContext, Segwitv0};
pub use miniscript::decode::Terminal;
pub use miniscript::satisfy::{BitcoinSig, Satisfier};
pub use miniscript::Miniscript;

///Public key trait which can be converted to Hash type
pub trait MiniscriptKey:
    Clone + Eq + Ord + str::FromStr + fmt::Debug + fmt::Display + hash::Hash
{
    /// Check if the publicKey is uncompressed. The default
    /// implementation returns false
    fn is_uncompressed(&self) -> bool {
        false
    }
    /// The associated Hash type with the publicKey
    type Hash: Clone + Eq + Ord + str::FromStr + fmt::Display + fmt::Debug + hash::Hash;

    /// Converts an object to PublicHash
    fn to_pubkeyhash(&self) -> Self::Hash;

    /// Computes the size of a public key when serialized in a script,
    /// including the length bytes
    fn serialized_len(&self) -> usize {
        if self.is_uncompressed() {
            66
        } else {
            34
        }
    }
}

impl MiniscriptKey for bitcoin::PublicKey {
    /// `is_uncompressed` returns true only for
    /// bitcoin::Publickey type if the underlying key is uncompressed.
    fn is_uncompressed(&self) -> bool {
        !self.compressed
    }

    type Hash = hash160::Hash;

    fn to_pubkeyhash(&self) -> Self::Hash {
        let mut engine = hash160::Hash::engine();
        self.write_into(&mut engine);
        hash160::Hash::from_engine(engine)
    }
}

impl MiniscriptKey for String {
    type Hash = String;

    fn to_pubkeyhash(&self) -> Self::Hash {
        format!("{}", &self)
    }
}

/// Trait describing public key types which can be converted to bitcoin pubkeys
/// The trait relies on Copy trait because in all practical usecases `ToPkCtx`
/// should contain references to objects which should be cheap to `Copy`.
// Why is this a generic instead of associated type?
// We would like to support implementation of `ToPublicKey` for both
// secp verification_only and secp_all. But as of rust 1.29(MSRV), the
// feature for associated traits is unstable.
pub trait ToPublicKey<ToPkCtx: Copy>: MiniscriptKey {
    /// Converts an object to a public key
    /// C represents additional context information that maybe
    /// required for deriving a bitcoin::PublicKey from MiniscriptKey
    /// You may require secp context for crypto operations
    /// or additional information for substituting the wildcard in
    /// extended pubkeys
    fn to_public_key(&self, to_pk_ctx: ToPkCtx) -> bitcoin::PublicKey;

    /// Converts a hashed version of the public key to a `hash160` hash.
    ///
    /// This method must be consistent with `to_public_key`, in the sense
    /// that calling `MiniscriptKey::to_pubkeyhash` followed by this function
    /// should give the same result as calling `to_public_key` and hashing
    /// the result directly.
    fn hash_to_hash160(hash: &<Self as MiniscriptKey>::Hash, to_pk_ctx: ToPkCtx) -> hash160::Hash;
}

/// Dummy Context for impl for ToPublicKey for bitcoin::PublicKey
#[derive(Debug, Clone, Copy)]
pub struct NullCtx;

impl ToPublicKey<NullCtx> for bitcoin::PublicKey {
    fn to_public_key(&self, _ctx: NullCtx) -> bitcoin::PublicKey {
        *self
    }

    fn hash_to_hash160(hash: &hash160::Hash, _ctx: NullCtx) -> hash160::Hash {
        *hash
    }
}

/// Dummy key which de/serializes to the empty string; useful sometimes for testing
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct DummyKey;

impl str::FromStr for DummyKey {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<DummyKey, &'static str> {
        if x.is_empty() {
            Ok(DummyKey)
        } else {
            Err("non empty dummy key")
        }
    }
}

impl MiniscriptKey for DummyKey {
    type Hash = DummyKeyHash;

    fn to_pubkeyhash(&self) -> Self::Hash {
        DummyKeyHash
    }
}

impl hash::Hash for DummyKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "DummyKey".hash(state);
    }
}

impl fmt::Display for DummyKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl ToPublicKey<NullCtx> for DummyKey {
    fn to_public_key(&self, _ctx: NullCtx) -> bitcoin::PublicKey {
        bitcoin::PublicKey::from_str(
            "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352",
        )
        .unwrap()
    }

    fn hash_to_hash160(_: &DummyKeyHash, _ctx: NullCtx) -> hash160::Hash {
        hash160::Hash::from_str("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31").unwrap()
    }
}

/// Dummy keyhash which de/serializes to the empty string; useful sometimes for testing
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct DummyKeyHash;

impl str::FromStr for DummyKeyHash {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<DummyKeyHash, &'static str> {
        if x.is_empty() {
            Ok(DummyKeyHash)
        } else {
            Err("non empty dummy key")
        }
    }
}

impl fmt::Display for DummyKeyHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl hash::Hash for DummyKeyHash {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "DummyKeyHash".hash(state);
    }
}

/// Miniscript

#[derive(Debug)]
pub enum Error {
    /// Opcode appeared which is not part of the script subset
    InvalidOpcode(opcodes::All),
    /// Some opcode occurred followed by `OP_VERIFY` when it had
    /// a `VERIFY` version that should have been used instead
    NonMinimalVerify(miniscript::lex::Token),
    /// Push was illegal in some context
    InvalidPush(Vec<u8>),
    /// rust-bitcoin script error
    Script(script::Error),
    /// A `CHECKMULTISIG` opcode was preceded by a number > 20
    CmsTooManyKeys(u32),
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
    /// Fragment was an `and_v(_, true)` which should be written as `t:`
    NonCanonicalTrue,
    /// Fragment was an `or_i(_, false)` or `or_i(false,_)` which should be written as `u:` or `l:`
    NonCanonicalFalse,
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
    Secp(bitcoin::secp256k1::Error),
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
}

#[doc(hidden)]
impl<Pk, Ctx> From<miniscript::types::Error<Pk, Ctx>> for Error
where
    Pk: MiniscriptKey,
    Ctx: ScriptContext,
{
    fn from(e: miniscript::types::Error<Pk, Ctx>) -> Error {
        Error::TypeCheck(e.to_string())
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
impl From<elements::secp256k1::Error> for Error {
    fn from(e: elements::secp256k1::Error) -> Error {
        Error::Secp(e)
    }
}

fn errstr(s: &str) -> Error {
    Error::Unexpected(s.to_owned())
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::BadPubkey(ref e) => Some(e),
            _ => None,
        }
    }
}

// https://github.com/sipa/miniscript/pull/5 for discussion on this number
const MAX_RECURSION_DEPTH: u32 = 402;
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
const MAX_SCRIPT_SIZE: u32 = 10000;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidOpcode(op) => write!(f, "invalid opcode {}", op),
            Error::NonMinimalVerify(tok) => write!(f, "{} VERIFY", tok),
            Error::InvalidPush(ref push) => write!(f, "invalid push {:?}", push), // TODO hexify this
            Error::Script(ref e) => fmt::Display::fmt(e, f),
            Error::CmsTooManyKeys(n) => write!(f, "checkmultisig with {} keys", n),
            Error::Unprintable(x) => write!(f, "unprintable character 0x{:02x}", x),
            Error::ExpectedChar(c) => write!(f, "expected {}", c),
            Error::UnexpectedStart => f.write_str("unexpected start of script"),
            Error::Unexpected(ref s) => write!(f, "unexpected «{}»", s),
            Error::MultiColon(ref s) => write!(f, "«{}» has multiple instances of «:»", s),
            Error::MultiAt(ref s) => write!(f, "«{}» has multiple instances of «@»", s),
            Error::AtOutsideOr(ref s) => write!(f, "«{}» contains «@» in non-or() context", s),
            Error::NonCanonicalTrue => f.write_str("Use «t:X» rather than «and_v(X,true())»"),
            Error::NonCanonicalFalse => {
                f.write_str("Use «u:X» «l:X» rather than «or_i(X,false)» «or_i(false,X)»")
            }
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
