//! Parameters to certain covenants

use std::{fmt, hash};

use bitcoin::hashes::hex::ToHex;
use elements::confidential;
use elements::encode::serialize;

use super::csfs::{CsfsKey, CsfsMsg};
use super::introspect_ops::Spk;
use super::CovenantExt;
use crate::{Error, ExtTranslator};

/// Trait for parsing extension arg from String
/// Parse an argument from `s` given context of parent and argument position
///
/// When parsing all allowed parameters from string, we need to restrict where
/// the parameters can be allowed. For example, csfs() should not have a txout
/// parameter.
///
/// All parameters that should be parsed from extensions need to implement this
pub trait ArgFromStr: Sized {
    /// Parse an argument from `s` given context of parent and argument position
    fn arg_from_str(s: &str, parent: &str, pos: usize) -> Result<Self, Error>;
}

/// Abstract parameter to Miniscript Extension
pub trait ExtParam: Clone + Eq + Ord + fmt::Debug + fmt::Display + hash::Hash + ArgFromStr {}

impl<T> ExtParam for T where
    T: Clone + Eq + Ord + fmt::Debug + fmt::Display + hash::Hash + ArgFromStr
{
}

impl ArgFromStr for String {
    fn arg_from_str(s: &str, _parent: &str, _pos: usize) -> Result<Self, Error> {
        // Abstract strings are parsed without context as they don't contain any concrete
        // information
        Ok(String::from(s))
    }
}

/// No Extensions for elements-miniscript
/// All the implementations for the this function are unreachable
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub enum NoExtParam {}

impl fmt::Display for NoExtParam {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}

impl ArgFromStr for NoExtParam {
    fn arg_from_str(_s: &str, _parent: &str, _pos: usize) -> Result<Self, Error> {
        // This will be removed in a followup commit
        unreachable!("Called ArgFromStr for NoExt")
    }
}

/// All known Extension parameters/arguments
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum CovExtArgs {
    /// XOnlyPublicKey (in CSFS)
    XOnlyKey(CsfsKey),
    /// Message
    CsfsMsg(CsfsMsg),
    /// Asset
    Asset(confidential::Asset),
    /// Value
    Value(confidential::Value),
    /// Script
    Script(Spk),
}

impl From<CsfsMsg> for CovExtArgs {
    fn from(v: CsfsMsg) -> Self {
        Self::CsfsMsg(v)
    }
}

impl From<Spk> for CovExtArgs {
    fn from(v: Spk) -> Self {
        Self::Script(v)
    }
}

impl From<confidential::Value> for CovExtArgs {
    fn from(v: confidential::Value) -> Self {
        Self::Value(v)
    }
}

impl From<confidential::Asset> for CovExtArgs {
    fn from(v: confidential::Asset) -> Self {
        Self::Asset(v)
    }
}

impl From<CsfsKey> for CovExtArgs {
    fn from(v: CsfsKey) -> Self {
        Self::XOnlyKey(v)
    }
}

impl CovExtArgs {
    /// Creates a new csfs key variant of [`CovExtArgs`]
    pub fn csfs_key(key: bitcoin::XOnlyPublicKey) -> Self {
        CovExtArgs::XOnlyKey(CsfsKey(key))
    }

    /// Creates a csfs message variant of [`CovExtArgs`]
    pub fn csfs_msg(msg: elements::secp256k1_zkp::Message) -> Self {
        CovExtArgs::CsfsMsg(CsfsMsg::new(msg.as_ref().to_vec()).expect("32 byte size message"))
    }

    /// Creates a new asset variant of [`CovExtArgs`]
    pub fn asset(asset: confidential::Asset) -> Self {
        Self::from(asset)
    }

    /// Creates a new value variant of [`CovExtArgs`]
    pub fn value(value: confidential::Value) -> Self {
        Self::from(value)
    }

    /// Creates a new script pubkey of [`CovExtArgs`]
    pub fn spk(spk: elements::Script) -> Self {
        Self::from(Spk::new(spk))
    }
}

impl PartialOrd for CovExtArgs {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // HACKY implementation, need Ord/PartialOrd to make it work with other components
        // in the library
        self.to_string().partial_cmp(&other.to_string())
    }
}

impl Ord for CovExtArgs {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // HACKY implementation, need Ord/PartialOrd to make it work with other components
        // in the library
        self.to_string().cmp(&other.to_string())
    }
}

impl fmt::Display for CovExtArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CovExtArgs::XOnlyKey(x) => write!(f, "{}", x),
            CovExtArgs::CsfsMsg(m) => write!(f, "{}", m),
            CovExtArgs::Asset(a) => write!(f, "{}", serialize(a).to_hex()),
            CovExtArgs::Value(v) => write!(f, "{}", serialize(v).to_hex()),
            CovExtArgs::Script(s) => write!(f, "{}", s),
        }
    }
}

impl ArgFromStr for CovExtArgs {
    fn arg_from_str(s: &str, parent: &str, pos: usize) -> Result<Self, Error> {
        let arg = match (parent, pos) {
            ("csfs", 0) => CovExtArgs::XOnlyKey(CsfsKey::arg_from_str(s, parent, pos)?),
            ("csfs", 1) => CovExtArgs::CsfsMsg(CsfsMsg::arg_from_str(s, parent, pos)?),
            ("asset_eq", 0) | ("asset_eq", 1) | ("is_exp_asset", 0) => {
                CovExtArgs::Asset(confidential::Asset::arg_from_str(s, parent, pos)?)
            }
            ("value_eq", 0) | ("value_eq", 1) | ("is_exp_value", 0) => {
                CovExtArgs::Value(confidential::Value::arg_from_str(s, parent, pos)?)
            }
            ("spk_eq", 0) | ("spk_eq", 1) => CovExtArgs::Script(Spk::arg_from_str(s, parent, pos)?),
            _ => return Err(Error::Unexpected(s.to_string())),
        };
        Ok(arg)
    }
}

/// Trait for translating different parameter types for covenant extensions
pub trait ExtParamTranslator<PArg, QArg, E>
where
    PArg: ExtParam,
    QArg: ExtParam,
{
    /// Translates one extension to another
    fn ext(&mut self, e: &PArg) -> Result<QArg, E>;
}

// Use ExtParamTranslator as a ExTTranslator
impl<T, PArg, QArg, E> ExtTranslator<CovenantExt<PArg>, CovenantExt<QArg>, E> for T
where
    T: ExtParamTranslator<PArg, QArg, E>,
    PArg: ExtParam,
    QArg: ExtParam,
{
    /// Translates one extension to another
    fn ext(&mut self, cov: &CovenantExt<PArg>) -> Result<CovenantExt<QArg>, E> {
        match *cov {
            CovenantExt::LegacyVerEq(ref v) => Ok(CovenantExt::LegacyVerEq(v.clone())),
            CovenantExt::LegacyOutputsPref(ref p) => Ok(CovenantExt::LegacyOutputsPref(p.clone())),
            CovenantExt::Csfs(ref c) => Ok(CovenantExt::Csfs(TranslateExtParam::translate_ext(
                c, self,
            )?)),
            CovenantExt::Arith(ref e) => Ok(CovenantExt::Arith(e.clone())),
            CovenantExt::Introspect(ref c) => Ok(CovenantExt::Introspect(
                TranslateExtParam::translate_ext(c, self)?,
            )),
        }
    }
}

/// Converts a descriptor using abstract extension parameters to one using concrete ones,
/// or vice-versa
pub trait TranslateExtParam<PArg, QArg>
where
    PArg: ExtParam,
    QArg: ExtParam,
{
    /// The associated output type.
    type Output;

    /// Translates a struct from one generic to another where the translations
    /// for Pk are provided by the given [`Translator`].
    fn translate_ext<T, E>(&self, translator: &mut T) -> Result<Self::Output, E>
    where
        T: ExtParamTranslator<PArg, QArg, E>;
}
