//! Miniscript Arithmetic expressions:
//! Note that this fragment is only supported for Tapscript context
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use elements::address::Payload;
use elements::confidential::Asset;
use elements::hex::{FromHex, ToHex};
use elements::opcodes::all::*;
use elements::{confidential, encode, script, Address, AddressParams};

use super::index_ops::IdxExpr;
use super::param::{ExtParamTranslator, TranslateExtParam};
use super::{ArgFromStr, CovExtArgs, EvalError, ExtParam, FromTokenIterError, ParseableExt, TxEnv};
use crate::expression::{FromTree, Tree};
use crate::miniscript::context::ScriptContextError;
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::satisfy::{Satisfaction, Witness};
use crate::miniscript::types::extra_props::{OpLimits, TimelockInfo};
use crate::miniscript::types::{Base, Correctness, Dissat, ExtData, Input, Malleability};
use crate::{
    expression, interpreter, script_num_size, Error, ExtTranslator, Extension, Satisfier,
    ToPublicKey, TranslateExt,
};

/// Enum representing operations with transaction assets.
/// Every variant of this enum pushes a 32 byte asset + 1 byte prefix on stack top..
/// These operations also support confidential assets.
/// This will abort when
///     - Supplied index is out of bounds.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum AssetExpr<T: ExtParam> {
    /* leaf fragments/terminals */
    /// A constant asset id
    /// Minimal push of this `<asset_id>`
    Const(T),
    /// Asset under the current executing input
    /// `INSPECTCURRENTINPUTINDEX INPSECTINPUTASSET`
    CurrInputAsset,
    /// Explicit asset at the given input index
    /// `i INPSECTINPUTASSET`
    Input(IdxExpr),
    /// Explicit asset at the given output index
    /// `i INPSECTOUTPUTASSET`
    Output(IdxExpr),
}

/// Enum representing operations with transaction values.
/// Every variant of this enum pushes a 32 byte value + 1 byte prefix on stack top..
/// These operations also support confidential values.
/// This will abort when
///     - Supplied index is out of bounds.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum ValueExpr<T: ExtParam> {
    /* leaf fragments/terminals */
    /// A constant Value
    Const(T),
    /// Value under the current executing input
    /// `INSPECTCURRENTINPUTINDEX INPSECTINPUTVALUE`
    CurrInputValue,
    ///  Value(possibly confidential) at the given input index
    /// `i INPSECTINPUTVALUE`
    Input(IdxExpr),
    /// Value(possibly confidential) at the given output index
    /// `i INPSECTOUTPUTVALUE`
    Output(IdxExpr),
}

/// Enum representing operations with transaction script pubkeys.
/// Every variant of this enum pushes a witness program + 1 byte witness version on stack top.
/// If the script pubkey is not a witness program. Push a sha256 hash of the
/// script pubkey followed by -1 witness version
/// This will abort when
///     - Supplied index is out of bounds.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum SpkExpr<T: ExtParam> {
    /* leaf fragments/terminals */
    /// A constant fixed script pubkey
    /// Pushes the witness program followed by witness version
    /// Pushes -1 if the legacy script pubkeys followed by sha256 hash of script pubkey
    Const(T),
    /// Script pubkey under the current executing input
    /// `INSPECTCURRENTINPUTINDEX INPSECTINPUTSCRIPTPUBKEY`
    CurrInputSpk,
    /// Explicit asset at the given input index
    /// `i INPSECTINPUTSCRIPTPUBKEY`
    Input(IdxExpr),
    /// Explicit asset at the given output index
    /// `i INPSECTOUTPUTSCRIPTPUBKEY`
    Output(IdxExpr),
}

/// Miniscript Fragment containing arith expressions
/// Expr cannot be directly used a miniscript fragment because it pushes a 64 bit
/// value on stack. Two expressions can be combined with Arith to something is
/// of Base type B to be used in miniscript expressions
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum CovOps<T: ExtParam> {
    /// Checks that asset is explicit
    /// `[X] <1> EQUAL NIP`
    IsExpAsset(AssetExpr<T>),
    /// Checks if the value is explicit
    /// `[X] <1> EQUAL NIP`
    /// The script translation is same as that of IsExpAsset, but the data structure
    /// distinguishes them for clarity.
    IsExpValue(ValueExpr<T>),
    /// Checks that both assets are equal (maybe confidential)
    /// `[X] TOALTSTACK [Y] FROMALTSTACK EQUAL TOALTSTACK EQUAL FROMALTSTACK BOOLAND`
    AssetEq(AssetExpr<T>, AssetExpr<T>),
    /// Checks that both values are equal (maybe confidential)
    /// `[X] TOALTSTACK [Y] FROMALTSTACK EQUAL TOALTSTACK EQUAL FROMALTSTACK BOOLAND`
    ValueEq(ValueExpr<T>, ValueExpr<T>),
    /// Script pubkey equal. Checks the witness version and program. Also works for
    /// legacy programs.
    /// `[X] TOALTSTACK [Y] FROMALTSTACK EQUAL TOALTSTACK EQUAL FROMALTSTACK BOOLAND`
    SpkEq(SpkExpr<T>, SpkExpr<T>),
    /// Current input index equality
    /// `<i> PUSHCURRENTINPUTINDEX EQUAL`
    CurrIndEq(usize),
    /// Index equality
    /// `[X] [Y] EQUAL`
    IdxEq(IdxExpr, IdxExpr),
}

impl<T: ExtParam> AssetExpr<T> {
    /// Returns the script size of this [`AssetExpr<T>`].
    fn script_size(&self) -> usize {
        match self {
            AssetExpr::Const(_) => 33 + 1,
            AssetExpr::CurrInputAsset => 2,
            AssetExpr::Input(i) => i.script_size() + 1,
            AssetExpr::Output(i) => i.script_size() + 1,
        }
    }

    /// Returns the extention translation from AssetExpr<T> to AssetExpr<Q>
    fn _translate_ext<Q, E, Ext>(&self, t: &mut Ext) -> Result<AssetExpr<Q>, E>
    where
        Ext: ExtParamTranslator<T, Q, E>,
        Q: ExtParam,
    {
        let res = match self {
            AssetExpr::Const(c) => AssetExpr::Const(t.ext(c)?),
            AssetExpr::CurrInputAsset => AssetExpr::CurrInputAsset,
            AssetExpr::Input(i) => AssetExpr::Input(i.clone()),
            AssetExpr::Output(i) => AssetExpr::Output(i.clone()),
        };
        Ok(res)
    }
}

impl<T: ExtParam> fmt::Display for AssetExpr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetExpr::Const(asset) => write!(f, "{}", asset),
            AssetExpr::CurrInputAsset => write!(f, "curr_inp_asset"),
            AssetExpr::Input(i) => write!(f, "inp_asset({})", i),
            AssetExpr::Output(i) => write!(f, "out_asset({})", i),
        }
    }
}

impl<T: ExtParam> fmt::Debug for AssetExpr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetExpr::Const(asset) => write!(f, "{:?}", asset),
            AssetExpr::CurrInputAsset => write!(f, "curr_inp_asset"),
            AssetExpr::Input(i) => write!(f, "inp_asset({:?})", i),
            AssetExpr::Output(i) => write!(f, "out_asset({:?})", i),
        }
    }
}

impl<T: ExtParam> ArgFromStr for AssetExpr<T> {
    fn arg_from_str(s: &str, parent: &str, pos: usize) -> Result<Self, Error> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree_parent(&top, parent, pos)
    }
}

impl<T: ExtParam> AssetExpr<T> {
    fn from_tree_parent(top: &Tree<'_>, parent: &str, pos: usize) -> Result<Self, Error> {
        match (top.name, top.args.len()) {
            ("curr_inp_asset", 0) => Ok(AssetExpr::CurrInputAsset),
            ("inp_asset", 1) => expression::unary(top, AssetExpr::Input),
            ("out_asset", 1) => expression::unary(top, AssetExpr::Output),
            (asset, 0) => Ok(AssetExpr::Const(T::arg_from_str(asset, parent, pos)?)),
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Extension",
                top.name,
                top.args.len(),
            ))),
        }
    }
}

impl<T: ExtParam> ValueExpr<T> {
    /// Returns the script size of this [`ValueExpr<T>`].
    fn script_size(&self) -> usize {
        match self {
            ValueExpr::Const(_c) => 33 + 1, // Worst case size for fee estimation
            ValueExpr::CurrInputValue => 2,
            ValueExpr::Input(i) => i.script_size() + 1,
            ValueExpr::Output(i) => i.script_size() + 1,
        }
    }

    /// Returns the extention translation from ValueExpr<T> to ValueExpr<Q>
    fn _translate_ext<Q, E, Ext>(&self, t: &mut Ext) -> Result<ValueExpr<Q>, E>
    where
        Ext: ExtParamTranslator<T, Q, E>,
        Q: ExtParam,
    {
        let res = match self {
            ValueExpr::Const(c) => ValueExpr::Const(t.ext(c)?),
            ValueExpr::CurrInputValue => ValueExpr::CurrInputValue,
            ValueExpr::Input(i) => ValueExpr::Input(i.clone()),
            ValueExpr::Output(i) => ValueExpr::Output(i.clone()),
        };
        Ok(res)
    }
}

impl<T: ExtParam> fmt::Display for ValueExpr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueExpr::Const(asset) => write!(f, "{}", asset),
            ValueExpr::CurrInputValue => write!(f, "curr_inp_value"),
            ValueExpr::Input(i) => write!(f, "inp_value({})", i),
            ValueExpr::Output(i) => write!(f, "out_value({})", i),
        }
    }
}

impl<T: ExtParam> fmt::Debug for ValueExpr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueExpr::Const(asset) => write!(f, "{:?}", asset),
            ValueExpr::CurrInputValue => write!(f, "curr_inp_value"),
            ValueExpr::Input(i) => write!(f, "inp_value({:?})", i),
            ValueExpr::Output(i) => write!(f, "out_value({:?})", i),
        }
    }
}

impl<T: ExtParam> ArgFromStr for ValueExpr<T> {
    fn arg_from_str(s: &str, parent: &str, pos: usize) -> Result<Self, Error> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree_parent(&top, parent, pos)
    }
}

impl<T: ExtParam> ValueExpr<T> {
    fn from_tree_parent(top: &Tree<'_>, parent: &str, pos: usize) -> Result<Self, Error> {
        match (top.name, top.args.len()) {
            ("curr_inp_value", 0) => Ok(ValueExpr::CurrInputValue),
            ("inp_value", 1) => expression::unary(top, ValueExpr::Input),
            ("out_value", 1) => expression::unary(top, ValueExpr::Output),
            (value, 0) => Ok(ValueExpr::Const(T::arg_from_str(value, parent, pos)?)),
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Extension",
                top.name,
                top.args.len(),
            ))),
        }
    }
}

impl<T: ExtParam> SpkExpr<T> {
    /// Returns the script size of this [`SpkExpr<T>`].
    fn script_size(&self) -> usize {
        match self {
            SpkExpr::Const(_c) => 32 + 1 + 1,
            SpkExpr::CurrInputSpk => 2,
            SpkExpr::Input(i) => i.script_size() + 1,
            SpkExpr::Output(i) => i.script_size() + 1,
        }
    }

    /// Returns the extention translation from SpkExpr<T> to SpkExpr<Q>
    fn _translate_ext<Q, E, Ext>(&self, t: &mut Ext) -> Result<SpkExpr<Q>, E>
    where
        Ext: ExtParamTranslator<T, Q, E>,
        Q: ExtParam,
    {
        let res = match self {
            SpkExpr::Const(c) => SpkExpr::Const(t.ext(c)?),
            SpkExpr::CurrInputSpk => SpkExpr::CurrInputSpk,
            SpkExpr::Input(i) => SpkExpr::Input(i.clone()),
            SpkExpr::Output(i) => SpkExpr::Output(i.clone()),
        };
        Ok(res)
    }
}

impl<T: ExtParam> fmt::Display for SpkExpr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpkExpr::Const(asset) => write!(f, "{}", asset),
            SpkExpr::CurrInputSpk => write!(f, "curr_inp_spk"),
            SpkExpr::Input(i) => write!(f, "inp_spk({})", i),
            SpkExpr::Output(i) => write!(f, "out_spk({})", i),
        }
    }
}

impl<T: ExtParam> fmt::Debug for SpkExpr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpkExpr::Const(asset) => write!(f, "{:?}", asset),
            SpkExpr::CurrInputSpk => write!(f, "curr_inp_spk"),
            SpkExpr::Input(i) => write!(f, "inp_spk({:?})", i),
            SpkExpr::Output(i) => write!(f, "out_spk({:?})", i),
        }
    }
}

impl<T: ExtParam> ArgFromStr for SpkExpr<T> {
    fn arg_from_str(s: &str, parent: &str, pos: usize) -> Result<Self, Error> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree_parent(&top, parent, pos)
    }
}

impl<T: ExtParam> SpkExpr<T> {
    fn from_tree_parent(top: &Tree<'_>, parent: &str, pos: usize) -> Result<Self, Error> {
        match (top.name, top.args.len()) {
            ("curr_inp_spk", 0) => Ok(SpkExpr::CurrInputSpk),
            ("inp_spk", 1) => expression::unary(top, SpkExpr::Input),
            ("out_spk", 1) => expression::unary(top, SpkExpr::Output),
            (asset, 0) => Ok(SpkExpr::Const(T::arg_from_str(asset, parent, pos)?)),
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Extension",
                top.name,
                top.args.len(),
            ))),
        }
    }
}

impl<T: ExtParam> fmt::Display for CovOps<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CovOps::IsExpAsset(a) => write!(f, "is_exp_asset({})", a),
            CovOps::IsExpValue(v) => write!(f, "is_exp_value({})", v),
            CovOps::AssetEq(a, b) => write!(f, "asset_eq({},{})", a, b),
            CovOps::ValueEq(a, b) => write!(f, "value_eq({},{})", a, b),
            CovOps::SpkEq(a, b) => write!(f, "spk_eq({},{})", a, b),
            CovOps::CurrIndEq(i) => write!(f, "curr_idx_eq({})", i),
            CovOps::IdxEq(a, b) => write!(f, "idx_eq({},{})", a, b),
        }
    }
}

impl<T: ExtParam> fmt::Debug for CovOps<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CovOps::IsExpAsset(a) => write!(f, "is_exp_asset({:?})", a),
            CovOps::IsExpValue(v) => write!(f, "is_exp_value({:?})", v),
            CovOps::AssetEq(a, b) => write!(f, "asset_eq({:?},{:?})", a, b),
            CovOps::ValueEq(a, b) => write!(f, "value_eq({:?},{:?})", a, b),
            CovOps::SpkEq(a, b) => write!(f, "spk_eq({:?},{:?})", a, b),
            CovOps::CurrIndEq(i) => write!(f, "curr_idx_eq({:?})", i),
            CovOps::IdxEq(a, b) => write!(f, "idx_eq({},{})", a, b),
        }
    }
}

impl<T: ExtParam> FromStr for CovOps<T> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree(&top)
    }
}

impl<T: ExtParam> FromTree for CovOps<T> {
    fn from_tree(top: &Tree<'_>) -> Result<Self, Error> {
        match (top.name, top.args.len()) {
            ("is_exp_asset", 1) => {
                AssetExpr::from_tree_parent(&top.args[0], top.name, 0).map(CovOps::IsExpAsset)
            }
            ("is_exp_value", 1) => {
                ValueExpr::from_tree_parent(&top.args[0], top.name, 0).map(CovOps::IsExpValue)
            }
            ("asset_eq", 2) => {
                let l = AssetExpr::from_tree_parent(&top.args[0], top.name, 0)?;
                let r = AssetExpr::from_tree_parent(&top.args[1], top.name, 1)?;
                Ok(CovOps::AssetEq(l, r))
            }
            ("value_eq", 2) => {
                let l = ValueExpr::from_tree_parent(&top.args[0], top.name, 0)?;
                let r = ValueExpr::from_tree_parent(&top.args[1], top.name, 1)?;
                Ok(CovOps::ValueEq(l, r))
            }
            ("spk_eq", 2) => {
                let l = SpkExpr::from_tree_parent(&top.args[0], top.name, 0)?;
                let r = SpkExpr::from_tree_parent(&top.args[1], top.name, 1)?;
                Ok(CovOps::SpkEq(l, r))
            }
            ("curr_idx_eq", 1) => {
                expression::terminal(&top.args[0], expression::parse_num::<usize>)
                    .map(CovOps::CurrIndEq)
            }
            ("idx_eq", 2) => {
                let l = IdxExpr::from_tree(&top.args[0])?;
                let r = IdxExpr::from_tree(&top.args[1])?;
                Ok(CovOps::IdxEq(l, r))
            }
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Extension",
                top.name,
                top.args.len(),
            ))),
        }
    }
}

impl<T: ExtParam> Extension for CovOps<T> {
    fn corr_prop(&self) -> Correctness {
        Correctness {
            base: Base::B,
            input: Input::Zero,    // No input from stack
            dissatisfiable: false, // No dissatisfactions possible from stack inputs
            unit: true,
        }
    }

    fn mall_prop(&self) -> Malleability {
        Malleability {
            dissat: Dissat::None, // No dissatisfactions from stack inputs
            safe: false,          // Unsafe as a top fragment
            non_malleable: true, // Script satisfaction is non-malleable, whole fragment tx could be malleable
        }
    }

    fn extra_prop(&self) -> ExtData {
        ExtData {
            pk_cost: self.script_size(), // 1 opcodes, 1 key push, msg, 1 msg push
            has_free_verify: matches!(self, CovOps::CurrIndEq(..)),
            stack_elem_count_sat: Some(0),
            stack_elem_count_dissat: Some(0),
            max_sat_size: Some((0, 0)),
            max_dissat_size: Some((0, 0)),
            timelock_info: TimelockInfo::default(),
            exec_stack_elem_count_sat: Some(4), // There is composition in asset/value/spk expressions. Only max 4 depth with asset expressions
            exec_stack_elem_count_dissat: Some(4),
            ops: OpLimits {
                // Opcodes are really not relevant in tapscript as BIP342 removes all rules on them
                // So, don't make any effort in trying to compute and cache them.
                count: 0,
                sat: Some(0),
                nsat: Some(0),
            },
        }
    }

    fn script_size(&self) -> usize {
        match self {
            CovOps::IsExpAsset(a) => a.script_size() + 3,
            CovOps::IsExpValue(v) => v.script_size() + 3,
            CovOps::AssetEq(a, b) => a.script_size() + b.script_size() + 7,
            CovOps::ValueEq(a, b) => a.script_size() + b.script_size() + 7,
            CovOps::SpkEq(a, b) => a.script_size() + b.script_size() + 7,
            CovOps::CurrIndEq(i) => script_num_size(*i) + 2,
            CovOps::IdxEq(a, b) => a.script_size() + b.script_size() + 1,
        }
    }

    fn from_name_tree(name: &str, children: &[Tree<'_>]) -> Result<Self, FromTokenIterError> {
        let tree = Tree {
            name,
            args: children.to_vec(), // Cloning references here, it is possible to avoid the to_vec() here,
                                     // but it requires lot of refactor.
        };
        Self::from_tree(&tree).map_err(|_| FromTokenIterError)
    }

    fn segwit_ctx_checks(&self) -> Result<(), ScriptContextError> {
        // New opcodes only supported in taproot context
        Err(ScriptContextError::ExtensionError(
            "Introspection opcodes only available in Taproot".to_string(),
        ))
    }
}

impl<PArg, QArg> TranslateExt<CovOps<PArg>, CovOps<QArg>> for CovOps<PArg>
where
    CovOps<PArg>: Extension,
    CovOps<QArg>: Extension,
    PArg: ExtParam,
    QArg: ExtParam,
{
    type Output = CovOps<QArg>;

    fn translate_ext<T, E>(&self, t: &mut T) -> Result<Self::Output, E>
    where
        T: ExtTranslator<CovOps<PArg>, CovOps<QArg>, E>,
    {
        t.ext(self)
    }
}

// Use ExtParamTranslator as a ExtTranslator
impl<T, PArg, QArg, E> ExtTranslator<CovOps<PArg>, CovOps<QArg>, E> for T
where
    T: ExtParamTranslator<PArg, QArg, E>,
    PArg: ExtParam,
    QArg: ExtParam,
{
    /// Translates one extension to another
    fn ext(&mut self, cov_ops: &CovOps<PArg>) -> Result<CovOps<QArg>, E> {
        TranslateExtParam::translate_ext(cov_ops, self)
    }
}

/// Wrapper around [`elements::Script`] for representing script pubkeys
// Required because the fmt::Display of elements::Script does not print hex
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Spk(SpkInner);

impl Spk {
    /// Creates a new [`Spk`].
    pub fn new(s: elements::Script) -> Self {
        Spk(SpkInner::Script(s))
    }
}

/// Script pubkey representing either a known script or a hash of legacy script
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum SpkInner {
    /// A complete known script
    Script(elements::Script),
    /// An hashed legacy script pubkey
    Hashed(sha256::Hash),
}

impl fmt::Display for Spk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            SpkInner::Script(s) => write!(f, "{}", s.to_hex()),
            SpkInner::Hashed(_h) => write!(f, "hashed_spk"), // This should never be used
        }
    }
}

impl ArgFromStr for Spk {
    fn arg_from_str(s: &str, parent: &str, _pos: usize) -> Result<Self, Error> {
        if parent != "spk_eq" {
            return Err(Error::Unexpected(
                "spk expressions can only used in spk_eq".to_string(),
            ));
        }
        let inner = elements::Script::from_hex(s).map_err(|e| Error::Unexpected(e.to_string()))?;
        Ok(Spk::new(inner))
    }
}

impl ArgFromStr for confidential::Asset {
    fn arg_from_str(s: &str, parent: &str, _pos: usize) -> Result<Self, Error> {
        if parent != "asset_eq" && parent != "is_exp_asset" {
            return Err(Error::Unexpected(
                "asset expressions only allowed inside asset_eq and is_exp_asset".to_string(),
            ));
        }
        let asset_hex = Vec::<u8>::from_hex(s).map_err(|e| Error::Unexpected(e.to_string()))?;
        elements::encode::deserialize(&asset_hex).map_err(|e| Error::Unexpected(e.to_string()))
    }
}

impl ArgFromStr for confidential::Value {
    fn arg_from_str(s: &str, parent: &str, _pos: usize) -> Result<Self, Error> {
        if parent != "value_eq" && parent != "is_exp_value" {
            return Err(Error::Unexpected(
                "value expressions only allowed inside value_eq and is_exp_value".to_string(),
            ));
        }
        let asset_hex = Vec::<u8>::from_hex(s).map_err(|e| Error::Unexpected(e.to_string()))?;
        elements::encode::deserialize(&asset_hex).map_err(|e| Error::Unexpected(e.to_string()))
    }
}

// Internal helper function to construct asset from prefix and commitments
fn asset(pref: u8, comm: &[u8]) -> Option<confidential::Asset> {
    let mut bytes = [0u8; 33];
    bytes[0] = pref;
    if comm.len() != 32 {
        return None;
    }
    bytes[1..].copy_from_slice(comm);
    encode::deserialize(&bytes).ok()
}

// Internal helper function to construct asset from prefix and components
fn value(pref: u8, comm: &[u8]) -> Option<confidential::Value> {
    if comm.len() == 32 {
        let mut bytes = [0u8; 33];
        bytes[0] = pref;
        bytes[1..].copy_from_slice(comm);
        encode::deserialize(&bytes).ok()
    } else if comm.len() == 8 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(comm);
        if pref == 1 {
            Some(confidential::Value::Explicit(u64::from_le_bytes(bytes)))
        } else {
            None
        }
    } else {
        None
    }
}

// Internal helper function to construct script pubkey from prefix and components
fn spk(pref: i8, prog: &[u8]) -> Option<elements::Script> {
    if pref == -1 {
        // Cannot infer script pubkey from sha256::Hash
        // In future, we can add fragments to check against certain hard-coded spks like fee spk.
        None
    } else if pref <= 16 && pref >= 0 {
        Some(
            script::Builder::new()
                .push_int(i64::from(pref))
                .push_slice(prog)
                .into_script(),
        )
    } else {
        None
    }
}

// Internal function to convert a script pubkey into (witness version, program)
// This converts legacy programs to (-1, sha256::Hash(spk))
fn spk_to_components(s: &elements::Script) -> (i8, Vec<u8>) {
    if !s.is_witness_program() {
        (
            -1,
            sha256::Hash::hash(s.as_bytes()).to_byte_array().to_vec(),
        )
    } else {
        // indirect way to get payload.
        // The address parameters don't really matter here
        let addr = Address::from_script(s, None, &AddressParams::ELEMENTS).unwrap();
        if let Payload::WitnessProgram { version, program } = addr.payload {
            (version.to_u8() as i8, program)
        } else {
            unreachable!("All witness programs have well defined payload")
        }
    }
}

impl AssetExpr<CovExtArgs> {
    /// Push this script to builder
    /// Panics when trying to push a Null asset. This never occur in honest use-cases
    /// as there is no such thing as Null asset
    pub fn push_to_builder(&self, builder: script::Builder) -> script::Builder {
        match self {
            AssetExpr::Const(CovExtArgs::Asset(a)) => {
                match a {
                    Asset::Null => unreachable!("Attempt to push Null asset"),
                    Asset::Explicit(a) => builder.push_slice(a.into_inner().as_ref()).push_int(1), // explicit prefix
                    Asset::Confidential(c) => {
                        let ser = c.serialize();
                        builder.push_slice(&ser[1..]).push_int(i64::from(ser[0]))
                    }
                }
            }
            AssetExpr::Const(_) => unreachable!(
                "Both constructors from_str and from_token_iter
            check that the correct variant is used in asset"
            ),
            AssetExpr::CurrInputAsset => builder
                .push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(OP_INSPECTINPUTASSET),
            AssetExpr::Input(i) => i.push_to_builder(builder).push_opcode(OP_INSPECTINPUTASSET),
            AssetExpr::Output(i) => i
                .push_to_builder(builder)
                .push_opcode(OP_INSPECTOUTPUTASSET),
        }
    }

    /// Evaluate this expression
    pub fn eval(&self, env: &TxEnv) -> Result<confidential::Asset, EvalError> {
        match self {
            AssetExpr::Const(CovExtArgs::Asset(a)) => Ok(*a),
            AssetExpr::Const(_) => unreachable!(
                "Both constructors from_str and from_token_iter
            check that the correct variant is used in asset"
            ),
            AssetExpr::CurrInputAsset => {
                if env.idx() >= env.spent_utxos().len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(
                        env.idx(),
                        env.spent_utxos().len(),
                    ));
                }
                Ok(env.spent_utxos()[env.idx()].asset)
            }
            AssetExpr::Input(i) => {
                let i = i.eval(env)?;
                if i >= env.spent_utxos().len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(i, env.spent_utxos().len()));
                }
                Ok(env.spent_utxos()[i].asset)
            }
            AssetExpr::Output(i) => {
                let i = i.eval(env)?;
                if i >= env.tx().output.len() {
                    return Err(EvalError::OutputIndexOutOfBounds(i, env.tx().output.len()));
                }
                Ok(env.tx().output[i].asset)
            }
        }
    }

    /// Returns (self, start_pos) parsed reversed form tokens starting with index end_pos
    /// Expression is parsed from tokens`[start:end_pos]`
    pub fn from_tokens(tokens: &[Tk], end_pos: usize) -> Option<(Self, usize)> {
        let tks = tokens;
        let e = end_pos; // short abbreviations for succinct readable code
        if let Some(&[Tk::Bytes32(asset_comm), Tk::Num(i)]) = tks.get(e.checked_sub(2)?..e) {
            let asset = asset(u8::try_from(i).ok()?, asset_comm)?;
            Some((AssetExpr::Const(CovExtArgs::Asset(asset)), e - 2))
        } else if let Some(&[Tk::CurrInp, Tk::InpAsset]) = tks.get(e.checked_sub(2)?..e) {
            Some((AssetExpr::CurrInputAsset, e - 2))
        } else if let Some(&[Tk::InpAsset]) = tks.get(e.checked_sub(1)?..e) {
            let (idx_expr, e) = IdxExpr::from_tokens(tks, e - 1)?;
            Some((AssetExpr::Input(idx_expr), e))
        } else if let Some(&[Tk::OutAsset]) = tks.get(e.checked_sub(1)?..e) {
            let (idx_expr, e) = IdxExpr::from_tokens(tks, e - 1)?;
            Some((AssetExpr::Output(idx_expr), e))
        } else {
            None
        }
    }
}

impl ValueExpr<CovExtArgs> {
    /// Push this script to builder
    pub fn push_to_builder(&self, builder: script::Builder) -> script::Builder {
        match self {
            ValueExpr::Const(CovExtArgs::Value(a)) => {
                match a {
                    confidential::Value::Null => {
                        builder.push_slice(&0i64.to_le_bytes()).push_int(1)
                    } // null amounts are 0 values
                    confidential::Value::Explicit(a) => {
                        builder.push_slice(&a.to_le_bytes()).push_int(1)
                    } // explicit prefix
                    confidential::Value::Confidential(c) => {
                        let ser = c.serialize();
                        builder.push_slice(&ser[1..]).push_int(i64::from(ser[0]))
                    }
                }
            }
            ValueExpr::Const(_) => unreachable!(
                "Both constructors from_str and from_token_iter
            check that the correct variant is used in Value"
            ),
            ValueExpr::CurrInputValue => builder
                .push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(OP_INSPECTINPUTVALUE),
            ValueExpr::Input(i) => i.push_to_builder(builder).push_opcode(OP_INSPECTINPUTVALUE),
            ValueExpr::Output(i) => i
                .push_to_builder(builder)
                .push_opcode(OP_INSPECTOUTPUTVALUE),
        }
    }

    /// Evaluate this expression
    pub fn eval(&self, env: &TxEnv) -> Result<confidential::Value, EvalError> {
        match self {
            ValueExpr::Const(CovExtArgs::Value(a)) => Ok(*a),
            ValueExpr::Const(_) => unreachable!(
                "Both constructors from_str and from_token_iter
            check that the correct variant is used in Value"
            ),
            ValueExpr::CurrInputValue => {
                if env.idx() >= env.spent_utxos().len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(
                        env.idx(),
                        env.spent_utxos().len(),
                    ));
                }
                Ok(env.spent_utxos()[env.idx()].value)
            }
            ValueExpr::Input(i) => {
                let i = i.eval(env)?;
                if i >= env.spent_utxos().len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(i, env.spent_utxos().len()));
                }
                Ok(env.spent_utxos()[i].value)
            }
            ValueExpr::Output(i) => {
                let i = i.eval(env)?;
                if i >= env.tx().output.len() {
                    return Err(EvalError::OutputIndexOutOfBounds(i, env.tx().output.len()));
                }
                Ok(env.tx().output[i].value)
            }
        }
    }

    /// Returns (self, start_pos) parsed reversed form tokens starting with index end_pos
    /// Expression is parsed from tokens`[start:end_pos]`
    pub fn from_tokens(tokens: &[Tk], end_pos: usize) -> Option<(Self, usize)> {
        let tks = tokens;
        let e = end_pos; // short abbreviations for succinct readable code
        if let Some(&[Tk::Bytes32(value_comm), Tk::Num(i)]) = tks.get(e.checked_sub(2)?..e) {
            let value = value(u8::try_from(i).ok()?, value_comm)?;
            Some((ValueExpr::Const(CovExtArgs::Value(value)), e - 2))
        } else if let Some(&[Tk::Bytes8(exp_val), Tk::Num(i)]) = tks.get(e.checked_sub(2)?..e) {
            let value = value(u8::try_from(i).ok()?, exp_val)?;
            Some((ValueExpr::Const(CovExtArgs::Value(value)), e - 2))
        } else if let Some(&[Tk::CurrInp, Tk::InpValue]) = tks.get(e.checked_sub(2)?..e) {
            Some((ValueExpr::CurrInputValue, e - 2))
        } else if let Some(&[Tk::InpValue]) = tks.get(e.checked_sub(1)?..e) {
            let (idx_expr, e) = IdxExpr::from_tokens(tks, e - 1)?;
            Some((ValueExpr::Input(idx_expr), e))
        } else if let Some(&[Tk::OutValue]) = tks.get(e.checked_sub(1)?..e) {
            let (idx_expr, e) = IdxExpr::from_tokens(tks, e - 1)?;
            Some((ValueExpr::Output(idx_expr), e))
        } else {
            None
        }
    }
}

impl SpkExpr<CovExtArgs> {
    /// Push this script to builder
    pub fn push_to_builder(&self, builder: script::Builder) -> script::Builder {
        match self {
            SpkExpr::Const(CovExtArgs::Script(s)) => {
                let (ver, prog) = match &s.0 {
                    SpkInner::Script(s) => spk_to_components(s),
                    SpkInner::Hashed(h) => (-1, h.to_byte_array().to_vec()),
                };
                builder.push_slice(&prog).push_int(i64::from(ver))
            }
            SpkExpr::Const(_) => unreachable!(
                "Both constructors from_str and from_token_iter
            check that the correct variant is used in Script"
            ),
            SpkExpr::CurrInputSpk => builder
                .push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(OP_INSPECTINPUTSCRIPTPUBKEY),
            SpkExpr::Input(i) => i
                .push_to_builder(builder)
                .push_opcode(OP_INSPECTINPUTSCRIPTPUBKEY),
            SpkExpr::Output(i) => i
                .push_to_builder(builder)
                .push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        }
    }

    /// Evaluate this expression
    pub fn eval(&self, env: &TxEnv) -> Result<(i8, Vec<u8>), EvalError> {
        let res = match self {
            SpkExpr::Const(CovExtArgs::Script(s)) => match &s.0 {
                SpkInner::Script(s) => spk_to_components(s),
                SpkInner::Hashed(h) => (-1, h.to_byte_array().to_vec()),
            },
            SpkExpr::Const(_) => unreachable!(
                "Both constructors from_str and from_token_iter
            check that the correct variant is used in Script pubkey"
            ),
            SpkExpr::CurrInputSpk => {
                if env.idx() >= env.spent_utxos().len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(
                        env.idx(),
                        env.spent_utxos().len(),
                    ));
                }
                spk_to_components(&env.spent_utxos()[env.idx()].script_pubkey)
            }
            SpkExpr::Input(i) => {
                let i = i.eval(env)?;
                if i >= env.spent_utxos().len() {
                    return Err(EvalError::UtxoIndexOutOfBounds(i, env.spent_utxos().len()));
                }
                spk_to_components(&(env.spent_utxos()[i].script_pubkey))
            }
            SpkExpr::Output(i) => {
                let i = i.eval(env)?;
                if i >= env.tx().output.len() {
                    return Err(EvalError::OutputIndexOutOfBounds(i, env.tx().output.len()));
                }
                spk_to_components(&(env.tx().output[i].script_pubkey))
            }
        };
        Ok(res)
    }

    /// Returns (self, start_pos) parsed reversed form tokens starting with index end_pos
    /// Expression is parsed from tokens`[start:end_pos]`
    pub fn from_tokens(tokens: &[Tk], end_pos: usize) -> Option<(Self, usize)> {
        let tks = tokens;
        let e = end_pos; // short abbreviations for succinct readable code
        if let Some(&[Tk::Bytes32(spk_vec), Tk::Num(i)]) = tks.get(e.checked_sub(2)?..e) {
            let script = spk(i8::try_from(i).ok()?, spk_vec)?;
            Some((SpkExpr::Const(CovExtArgs::Script(Spk::new(script))), e - 2))
        } else if let Some(&[Tk::Bytes32(spk_vec), Tk::NumNeg1]) = tks.get(e.checked_sub(2)?..e) {
            let mut inner = [0u8; 32];
            inner.copy_from_slice(spk_vec);
            let hashed_spk = Spk(SpkInner::Hashed(sha256::Hash::from_byte_array(inner)));
            Some((SpkExpr::Const(CovExtArgs::Script(hashed_spk)), e - 2))
        } else if let Some(&[Tk::Push(ref spk_vec), Tk::Num(i)]) = tks.get(e.checked_sub(2)?..e) {
            let script = spk(i8::try_from(i).ok()?, spk_vec)?;
            Some((SpkExpr::Const(CovExtArgs::Script(Spk::new(script))), e - 2))
        } else if let Some(&[Tk::CurrInp, Tk::InpSpk]) = tks.get(e.checked_sub(2)?..e) {
            Some((SpkExpr::CurrInputSpk, e - 2))
        } else if let Some(&[Tk::InpSpk]) = tks.get(e.checked_sub(1)?..e) {
            let (idx_expr, e) = IdxExpr::from_tokens(tks, e - 1)?;
            Some((SpkExpr::Input(idx_expr), e))
        } else if let Some(&[Tk::OutSpk]) = tks.get(e.checked_sub(1)?..e) {
            let (idx_expr, e) = IdxExpr::from_tokens(tks, e - 1)?;
            Some((SpkExpr::Output(idx_expr), e))
        } else {
            None
        }
    }
}

impl CovOps<CovExtArgs> {
    /// Push this script to builder
    pub fn push_to_builder(&self, builder: script::Builder) -> script::Builder {
        match self {
            CovOps::IsExpAsset(x) => x
                .push_to_builder(builder)
                .push_int(1)
                .push_opcode(OP_EQUAL)
                .push_opcode(OP_NIP),
            CovOps::IsExpValue(x) => x
                .push_to_builder(builder)
                .push_int(1)
                .push_opcode(OP_EQUAL)
                .push_opcode(OP_NIP),
            CovOps::AssetEq(x, y) => {
                // pushes [asset_x] [pref_x] [asset_y] [pref_y] on top. Check that both prefixes and values match.
                let builder = x.push_to_builder(builder).push_opcode(OP_TOALTSTACK);
                let builder = y
                    .push_to_builder(builder)
                    .push_opcode(OP_FROMALTSTACK)
                    .push_opcode(OP_EQUAL);
                builder
                    .push_opcode(OP_TOALTSTACK)
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_FROMALTSTACK)
                    .push_opcode(OP_BOOLAND)
            }
            CovOps::ValueEq(x, y) => {
                // pushes [value_x] [pref_x] [value_y] [pref_y] on top. Check that both prefixes and values match.
                let builder = x.push_to_builder(builder).push_opcode(OP_TOALTSTACK);
                let builder = y
                    .push_to_builder(builder)
                    .push_opcode(OP_FROMALTSTACK)
                    .push_opcode(OP_EQUAL);
                builder
                    .push_opcode(OP_TOALTSTACK)
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_FROMALTSTACK)
                    .push_opcode(OP_BOOLAND)
            }
            CovOps::SpkEq(x, y) => {
                // pushes [spk_x] [wit_ver_x] [spk_y] [wit_ver_y] on top. Check that both prefixes and values match.
                let builder = x.push_to_builder(builder).push_opcode(OP_TOALTSTACK);
                let builder = y
                    .push_to_builder(builder)
                    .push_opcode(OP_FROMALTSTACK)
                    .push_opcode(OP_EQUAL);
                builder
                    .push_opcode(OP_TOALTSTACK)
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_FROMALTSTACK)
                    .push_opcode(OP_BOOLAND)
            }
            CovOps::CurrIndEq(i) => builder
                .push_int(*i as i64)
                .push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(OP_EQUAL),
            CovOps::IdxEq(x, y) => {
                // pushes [idx_x] [idx_y] on top. Check that both prefixes and values match.
                let builder = x.push_to_builder(builder);
                let builder = y.push_to_builder(builder);
                builder.push_opcode(OP_EQUAL)
            }
        }
    }

    /// Evaluate this expression
    pub fn eval(&self, env: &TxEnv) -> Result<bool, EvalError> {
        match self {
            CovOps::IsExpAsset(x) => x.eval(env).map(|x| x.is_explicit()),
            CovOps::IsExpValue(y) => y.eval(env).map(|y| y.is_explicit()),
            CovOps::AssetEq(x, y) => Ok(x.eval(env)? == y.eval(env)?),
            CovOps::ValueEq(x, y) => Ok(x.eval(env)? == y.eval(env)?),
            CovOps::SpkEq(x, y) => Ok(x.eval(env)? == y.eval(env)?),
            CovOps::CurrIndEq(i) => Ok(*i == env.idx()),
            CovOps::IdxEq(x, y) => Ok(x.eval(env)? == y.eval(env)?),
        }
    }

    /// Returns (self, start_pos) parsed reversed form tokens starting with index end_pos
    /// Expression is parsed from tokens`[start:end_pos]`
    pub fn from_tokens(tks: &[Tk]) -> Option<(Self, usize)> {
        let e = tks.len();
        if let Some(&[Tk::Num(i), Tk::CurrInp, Tk::Equal]) = tks.get(e.checked_sub(3)?..e) {
            Some((CovOps::CurrIndEq(i as usize), e - 3))
        } else if let Some(&[Tk::Equal]) = tks.get(e.checked_sub(1)?..e) {
            let (y, e) = IdxExpr::from_tokens(tks, e - 1)?;
            let (x, e) = IdxExpr::from_tokens(tks, e)?;
            Some((CovOps::IdxEq(x, y), e))
        } else if let Some(&[Tk::Num(1), Tk::Equal, Tk::Nip]) = tks.get(e.checked_sub(3)?..e) {
            if let Some((asset, e)) = AssetExpr::from_tokens(tks, e - 3) {
                Some((CovOps::IsExpAsset(asset), e))
            } else if let Some((value, e)) = ValueExpr::from_tokens(tks, e - 3) {
                Some((CovOps::IsExpValue(value), e))
            } else {
                None
            }
        } else if let Some(
            &[Tk::FromAltStack, Tk::Equal, Tk::ToAltStack, Tk::Equal, Tk::FromAltStack, Tk::BoolAnd],
        ) = tks.get(e.checked_sub(6)?..e)
        {
            let res = if let Some((y, e)) = AssetExpr::from_tokens(tks, e - 6) {
                if tks.get(e - 1) != Some(&Tk::ToAltStack) {
                    return None;
                }
                if let Some((x, e)) = AssetExpr::from_tokens(tks, e - 1) {
                    Some((CovOps::AssetEq(x, y), e))
                } else {
                    None
                }
            } else {
                None
            };
            if res.is_some() {
                return res;
            }
            let res = if let Some((y, e)) = ValueExpr::from_tokens(tks, e - 6) {
                if tks.get(e - 1) != Some(&Tk::ToAltStack) {
                    return None;
                }
                if let Some((x, e)) = ValueExpr::from_tokens(tks, e - 1) {
                    Some((CovOps::ValueEq(x, y), e))
                } else {
                    None
                }
            } else {
                None
            };
            if res.is_some() {
                return res;
            }
            if let Some((y, e)) = SpkExpr::from_tokens(tks, e - 6) {
                if tks.get(e - 1) != Some(&Tk::ToAltStack) {
                    return None;
                }
                if let Some((x, e)) = SpkExpr::from_tokens(tks, e - 1) {
                    Some((CovOps::SpkEq(x, y), e))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl ParseableExt for CovOps<CovExtArgs> {
    fn satisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let env = match (
            sat.lookup_tx(),
            sat.lookup_spent_utxos(),
            sat.lookup_curr_inp(),
        ) {
            (Some(tx), Some(utxos), Some(idx)) => match TxEnv::new(tx, utxos, idx) {
                Some(x) => x,
                None => {
                    return Satisfaction {
                        stack: Witness::Impossible,
                        has_sig: false,
                    }
                }
            },
            _ => {
                return Satisfaction {
                    stack: Witness::Impossible,
                    has_sig: false,
                }
            }
        };
        let wit = match self.eval(&env) {
            Ok(false) => Witness::Unavailable,
            Ok(true) => Witness::empty(),
            Err(_e) => Witness::Impossible,
        };
        Satisfaction {
            stack: wit,
            has_sig: false,
        }
    }

    fn dissatisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let env = match (
            sat.lookup_tx(),
            sat.lookup_spent_utxos(),
            sat.lookup_curr_inp(),
        ) {
            (Some(tx), Some(utxos), Some(idx)) => match TxEnv::new(tx, utxos, idx) {
                Some(x) => x,
                None => {
                    return Satisfaction {
                        stack: Witness::Impossible,
                        has_sig: false,
                    }
                }
            },
            _ => {
                return Satisfaction {
                    stack: Witness::Impossible,
                    has_sig: false,
                }
            }
        };
        let wit = match self.eval(&env) {
            Ok(false) => Witness::empty(),
            Ok(true) => Witness::Unavailable,
            Err(_e) => Witness::Impossible,
        };
        Satisfaction {
            stack: wit,
            has_sig: false,
        }
    }

    fn push_to_builder(&self, builder: elements::script::Builder) -> elements::script::Builder {
        self.push_to_builder(builder)
    }

    fn from_token_iter(tokens: &mut TokenIter<'_>) -> Result<Self, FromTokenIterError> {
        let len = tokens.len();
        match Self::from_tokens(tokens.as_inner_mut()) {
            Some((res, last_pos)) => {
                tokens.advance(len - last_pos).ok_or(FromTokenIterError)?;
                Ok(res)
            }
            None => Err(FromTokenIterError),
        }
    }

    fn evaluate(
        &self,
        stack: &mut interpreter::Stack,
        txenv: Option<&TxEnv>,
    ) -> Result<bool, interpreter::Error> {
        let txenv = txenv
            .as_ref()
            .ok_or(interpreter::Error::ArithError(EvalError::TxEnvNotPresent))?;

        match self.eval(txenv) {
            Ok(true) => {
                stack.push(interpreter::Element::Satisfied);
                Ok(true)
            }
            Ok(false) => {
                stack.push(interpreter::Element::Dissatisfied);
                Ok(false)
            }
            Err(e) => Err(interpreter::Error::ArithError(e)),
        }
    }
}

impl<PArg, QArg> TranslateExtParam<PArg, QArg> for CovOps<PArg>
where
    PArg: ExtParam,
    QArg: ExtParam,
{
    type Output = CovOps<QArg>;

    fn translate_ext<T, E>(&self, t: &mut T) -> Result<Self::Output, E>
    where
        T: ExtParamTranslator<PArg, QArg, E>,
    {
        match self {
            CovOps::IsExpAsset(a) => Ok(CovOps::IsExpAsset(a._translate_ext(t)?)),
            CovOps::IsExpValue(v) => Ok(CovOps::IsExpValue(v._translate_ext(t)?)),
            CovOps::AssetEq(x, y) => {
                Ok(CovOps::AssetEq(x._translate_ext(t)?, y._translate_ext(t)?))
            }
            CovOps::ValueEq(x, y) => {
                Ok(CovOps::ValueEq(x._translate_ext(t)?, y._translate_ext(t)?))
            }
            CovOps::SpkEq(x, y) => Ok(CovOps::SpkEq(x._translate_ext(t)?, y._translate_ext(t)?)),
            CovOps::CurrIndEq(i) => Ok(CovOps::CurrIndEq(*i)),
            CovOps::IdxEq(x, y) => Ok(CovOps::IdxEq(x.clone(), y.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::key::XOnlyPublicKey;

    use super::*;
    use crate::test_utils::{StrExtTranslator, StrXOnlyKeyTranslator};
    use crate::{Miniscript, Segwitv0, Tap, TranslatePk};

    #[test]
    fn test_index_ops() {
        // index ops tests with different index types
        _test_parse("is_exp_asset(inp_asset(curr_idx))");
        _test_parse("is_exp_asset(inp_asset(idx_add(9,curr_idx)))");
        _test_parse("is_exp_asset(inp_asset(idx_sub(9,curr_idx)))");
        _test_parse("is_exp_asset(inp_asset(idx_mul(9,curr_idx)))");
        _test_parse("is_exp_asset(inp_asset(idx_div(9,curr_idx)))");
        _test_parse("is_exp_asset(inp_asset(idx_mul(1,idx_add(9,curr_idx))))");
        _test_parse("is_exp_asset(inp_asset(idx_sub(idx_mul(1,idx_add(9,curr_idx)),1)))");

        // test type parent fragments
        _test_parse("is_exp_asset(out_asset(idx_add(9,curr_idx)))");
        _test_parse("is_exp_value(inp_value(idx_add(9,curr_idx)))");
        _test_parse("is_exp_value(out_value(idx_add(9,curr_idx)))");
        _test_parse("spk_eq(inp_spk(idx_add(9,curr_idx)),out_spk(idx_sub(9,curr_idx)))");

        _test_parse("idx_eq(10,idx_add(9,curr_idx))");
    }

    #[test]
    fn cov_parse() {
        // This does not test the evaluation
        _test_parse("is_exp_asset(ConfAst)");
        _test_parse("is_exp_asset(ExpAst)");
        _test_parse("is_exp_asset(curr_inp_asset)");
        _test_parse("is_exp_asset(inp_asset(9))");
        _test_parse("is_exp_asset(out_asset(9))");
        _test_parse("asset_eq(ConfAst,ExpAst)");
        _test_parse("asset_eq(curr_inp_asset,out_asset(1))");
        _test_parse("asset_eq(inp_asset(3),out_asset(1))");

        // same tests for values
        _test_parse("is_exp_value(ConfVal)");
        _test_parse("is_exp_value(ExpVal)");
        _test_parse("is_exp_value(curr_inp_value)");
        _test_parse("is_exp_value(inp_value(9))");
        _test_parse("is_exp_value(out_value(9))");
        _test_parse("value_eq(ConfVal,ExpVal)");
        _test_parse("value_eq(curr_inp_value,out_value(1))");
        _test_parse("value_eq(inp_value(3),out_value(1))");

        // same tests for spks
        _test_parse("spk_eq(V0Spk,out_spk(1))");
        _test_parse("spk_eq(V1Spk,inp_spk(1))");
        _test_parse("spk_eq(curr_inp_spk,out_spk(1))");
        _test_parse("spk_eq(inp_spk(3),out_spk(1))");
        _test_parse("spk_eq(out_spk(2),V1Spk)");

        // Testing the current input index
        _test_parse("curr_idx_eq(1)");
        _test_parse("curr_idx_eq(0)");

        // test some misc combinations with other miniscript fragments
        _test_parse(
            "and_v(v:pk(K),and_v(v:is_exp_value(out_value(1)),is_exp_asset(out_asset(1))))",
        );
        _test_parse("and_v(v:pk(K),and_v(v:value_eq(ConfVal,ConfVal),spk_eq(V1Spk,V1Spk)))");
        _test_parse("and_v(v:pk(K),and_v(v:value_eq(ConfVal,ConfVal),and_v(v:spk_eq(V1Spk,V1Spk),curr_idx_eq(1))))");
    }

    #[test]
    fn options_fail_test() {
        type MsExt = Miniscript<XOnlyPublicKey, Tap, CovOps<CovExtArgs>>;

        // 33 bytes explicit asset succeeds
        MsExt::from_str_insane("asset_eq(out_asset(0),0179d51a47e4ac8e32306486dd0926a88678c392f2ed5f213e3ff2ad461c7c25e1)").unwrap();
        // 32 bytes explicit asset without prefix fails
        MsExt::from_str_insane("asset_eq(out_asset(0),79d51a47e4ac8e32306486dd0926a88678c392f2ed5f213e3ff2ad461c7c25e1)").unwrap_err();
    }

    #[rustfmt::skip]
    fn _test_parse(s: &str) {
        type MsExtStr = Miniscript<String, Tap, CovOps<String>>;
        type MsExt = Miniscript<XOnlyPublicKey, Tap, CovOps<CovExtArgs>>;
        type MsExtSegwitv0 = Miniscript<String, Segwitv0, CovOps<CovExtArgs>>;

        // Make sure that parsing this errors in segwit context
        assert!(MsExtSegwitv0::from_str_insane(s).is_err());

        let ms = MsExtStr::from_str_insane(s).unwrap();
        // test string rtt
        assert_eq!(ms.to_string(), s);
        let mut t = StrXOnlyKeyTranslator::default();
        let mut ext_t = StrExtTranslator::default();
        {
            ext_t.ext_map.insert("V1Spk".to_string(),CovExtArgs::spk(elements::Script::from_str("5120c73ac1b7a518499b9642aed8cfa15d5401e5bd85ad760b937b69521c297722f0").unwrap()));
            ext_t.ext_map.insert("V0Spk".to_string(),CovExtArgs::spk(elements::Script::from_str("0020c73ac1b7a518499b9642aed8cfa15d5401e5bd85ad760b937b69521c297722f0").unwrap()));
            ext_t.ext_map.insert("ConfAst".to_string(),CovExtArgs::asset(encode::deserialize(&Vec::<u8>::from_hex("0adef814ab021498562ab4717287305d3f7abb5686832fe6183e1db495abef7cc7").unwrap()).unwrap()));
            ext_t.ext_map.insert("ExpAst".to_string(),CovExtArgs::asset(encode::deserialize(&Vec::<u8>::from_hex("01c73ac1b7a518499b9642aed8cfa15d5401e5bd85ad760b937b69521c297722f0").unwrap()).unwrap()));
            ext_t.ext_map.insert("ConfVal".to_string(),CovExtArgs::value(encode::deserialize(&Vec::<u8>::from_hex("09def814ab021498562ab4717287305d3f7abb5686832fe6183e1db495abef7cc7").unwrap()).unwrap()));
            ext_t.ext_map.insert("ExpVal".to_string(),CovExtArgs::value(encode::deserialize(&Vec::<u8>::from_hex("010000000011110000").unwrap()).unwrap()));
        }
        let ms: Miniscript<XOnlyPublicKey, Tap, CovOps<String>> = ms.translate_pk(&mut t).unwrap();
        let ms: Miniscript<XOnlyPublicKey, Tap, CovOps<CovExtArgs>> = ms.translate_ext(&mut ext_t).unwrap();
        // script rtt
        assert_eq!(ms.encode(), MsExt::parse_insane(&ms.encode()).unwrap().encode());
        // String rtt of the translated script
        assert_eq!(ms, MsExt::from_str_insane(&ms.to_string()).unwrap())
    }
}
