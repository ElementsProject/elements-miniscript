//! Miniscript extension: CheckSigFromStack
//! Note that this fragment is only supported for Tapscript context

use std::fmt;
use std::str::FromStr;

use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::XOnlyPublicKey;
use elements::hashes::hex;
use elements::{self, opcodes, secp256k1_zkp};

use super::{ArgFromStr, CovExtArgs, ExtParam, ParseableExt};
use crate::miniscript::context::ScriptContextError;
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::limits::MAX_STANDARD_P2WSH_STACK_ITEM_SIZE;
use crate::miniscript::satisfy::{Satisfaction, Witness};
use crate::miniscript::types::extra_props::{OpLimits, TimelockInfo};
use crate::miniscript::types::{Base, Correctness, Dissat, ExtData, Input, Malleability};
use crate::{
    expression, interpreter, miniscript, Error, ExtTranslator, Extension, Satisfier, ToPublicKey,
    TranslateExt,
};

/// CheckSigFromStack struct
/// `<msg> <pk> CHECKSIGFROMSTACK`
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct CheckSigFromStack<T: ExtParam> {
    /// The public Key to check the signature against
    pk: T,
    /// The message to verify the signature
    msg: T,
}

impl<T: ExtParam> CheckSigFromStack<T> {
    /// Obtains the pk
    pub fn pk(&self) -> &T {
        &self.pk
    }

    /// Obtains the pk
    pub fn msg(&self) -> &T {
        &self.msg
    }
}

impl<T: ExtParam> fmt::Display for CheckSigFromStack<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "csfs({},{})", self.pk, self.msg)
    }
}

impl<T: ExtParam> Extension for CheckSigFromStack<T> {
    fn corr_prop(&self) -> Correctness {
        Correctness {
            base: Base::B,
            input: Input::One, // one input: signature
            dissatisfiable: true,
            unit: true,
        }
    }

    fn mall_prop(&self) -> Malleability {
        Malleability {
            dissat: Dissat::Unique, // multi-dissat
            safe: true,
            non_malleable: true,
        }
    }

    fn extra_prop(&self) -> ExtData {
        ExtData {
            pk_cost: 32 + 1 + 1 + 32 + 1, // 1 opcodes, 1 key push, msg, 1 msg push
            has_free_verify: true,        // free verify form. Checksigfromstack verify
            stack_elem_count_sat: Some(1),
            stack_elem_count_dissat: Some(1), // supply empty signature for dissatisfaction
            max_sat_size: Some((64, 64)),
            max_dissat_size: Some((1, 1)), // empty sig
            timelock_info: TimelockInfo::default(),
            exec_stack_elem_count_sat: Some(1),
            exec_stack_elem_count_dissat: Some(1),
            ops: OpLimits {
                // Opcodes are really not relevant in tapscript as BIP342 removes all rules on them
                count: 1,
                sat: Some(0),
                nsat: Some(0),
            },
        }
    }

    fn script_size(&self) -> usize {
        1 + 32 + 1 // opcode + key+ push
    }

    fn segwit_ctx_checks(&self) -> Result<(), miniscript::context::ScriptContextError> {
        // New opcodes only supported in taproot context
        Err(ScriptContextError::ExtensionError(
            "CSFS only available in Taproot".to_string(),
        ))
    }

    fn from_name_tree(name: &str, children: &[expression::Tree<'_>]) -> Result<Self, ()> {
        if children.len() == 2 && name == "csfs" {
            if !children[0].args.is_empty() || !children[1].args.is_empty() {
                return Err(());
            }
            let pk = T::arg_from_str(children[0].name, name, 0).map_err(|_| ())?;
            let msg = T::arg_from_str(children[1].name, name, 1).map_err(|_| ())?;
            Ok(Self { pk, msg })
        } else {
            // Correct error handling while parsing fromtree
            Err(())
        }
    }
}

/// Wrapper around CheckSigFromStack signature messages
#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub struct CsfsMsg(Vec<u8>);

impl CsfsMsg {
    /// Creates a new Msg with witness len check
    /// The current rust-secp API only supports verification of 32 byte signature
    /// but this should work in elementsd
    pub fn new(msg: Vec<u8>) -> Option<Self> {
        // Same rule about initial witness stack item size for tapscript
        if msg.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE {
            None
        } else {
            Some(Self(msg))
        }
    }

    /// Creates Self from slice
    pub fn from_slice(sl: &[u8]) -> Option<Self> {
        if sl.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE {
            None
        } else {
            Some(Self(sl.to_vec()))
        }
    }

    /// Obtains the inner slice of this message
    pub fn as_inner(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for CsfsMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

impl ArgFromStr for CsfsMsg {
    fn arg_from_str(s: &str, parent: &str, pos: usize) -> Result<Self, Error> {
        if parent != "csfs" || pos != 1 {
            return Err(Error::Unexpected(
                "Msg must be the first arg of csfs".to_string(),
            ));
        }
        let inner = Vec::<u8>::from_hex(s).map_err(|e| Error::Unexpected(e.to_string()))?;
        let inner_len = inner.len();
        let x = Self::new(inner)
            .ok_or(hex::Error::InvalidLength(32, inner_len))
            .map_err(|e| Error::Unexpected(e.to_string()))?;
        Ok(x)
    }
}

/// Wrapper around XOnlyKeys used in CheckSigfromstack
#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub struct CsfsKey(pub bitcoin::XOnlyPublicKey);

impl fmt::Display for CsfsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ArgFromStr for CsfsKey {
    fn arg_from_str(s: &str, parent: &str, pos: usize) -> Result<Self, Error> {
        if parent != "csfs" || pos != 0 {
            return Err(Error::Unexpected(
                "Key must be at first position in csfs".to_string(),
            ));
        }
        let k = bitcoin::XOnlyPublicKey::from_str(s)?;
        Ok(Self(k))
    }
}

impl CheckSigFromStack<CovExtArgs> {
    /// Obtains the XOnlyPublicKey
    pub fn as_pk(&self) -> &XOnlyPublicKey {
        if let CovExtArgs::XOnlyKey(CsfsKey(xpk)) = &self.pk {
            xpk
        } else {
            unreachable!(
                "Both constructors from_str and from_token_iter
            check that the correct variant is used in xpk"
            )
        }
    }

    /// Obtains the message as Vec
    pub fn as_msg(&self) -> &CsfsMsg {
        if let CovExtArgs::CsfsMsg(msg) = &self.msg {
            &msg
        } else {
            unreachable!(
                "Both constructors from_str and from_token_iter
            check that the correct variant is used in msg"
            )
        }
    }
}

impl ParseableExt for CheckSigFromStack<CovExtArgs> {
    fn satisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let wit = match sat.lookup_csfs_sig(self.as_pk(), self.as_msg()) {
            Some(sig) => Witness::Stack(vec![sig.as_ref().to_vec()]),
            None => Witness::Impossible,
        };
        Satisfaction {
            stack: wit,
            has_sig: false,
        }
    }

    fn dissatisfy<Pk, S>(&self, _sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        Satisfaction {
            stack: Witness::Stack(vec![vec![]]), // empty sig
            has_sig: false,
        }
    }

    fn push_to_builder(&self, builder: elements::script::Builder) -> elements::script::Builder {
        builder
            .push_slice(&self.as_msg().0)
            .push_slice(&self.as_pk().serialize())
            .push_opcode(opcodes::all::OP_CHECKSIGFROMSTACK)
    }

    fn from_token_iter(tokens: &mut TokenIter<'_>) -> Result<Self, ()> {
        let frag = {
            let sl = tokens.peek_slice(3).ok_or(())?;
            if let (Tk::Bytes32(pk), Tk::Bytes32(msg)) = (&sl[1], &sl[0]) {
                if sl[2] == Tk::CheckSigFromStack {
                    let xpk = XOnlyPublicKey::from_slice(&pk).map_err(|_| ())?;
                    let msg = CsfsMsg::from_slice(msg).ok_or(())?;
                    Self {
                        pk: CovExtArgs::XOnlyKey(CsfsKey(xpk)),
                        msg: CovExtArgs::CsfsMsg(msg),
                    }
                } else {
                    return Err(());
                }
            } else {
                return Err(());
            }
        };
        tokens.advance(3).expect("Size checked previously");
        Ok(frag)
    }

    fn evaluate<'intp, 'txin>(
        &'intp self,
        stack: &mut interpreter::Stack<'txin>,
    ) -> Result<bool, interpreter::Error> {
        let sig = stack[0].try_push()?;

        if sig.is_empty() {
            return Ok(false);
        }

        let sig = secp256k1_zkp::schnorr::Signature::from_slice(&sig)?;
        // rust-secp-zkp API only signing/verification for 32 bytes messages. It is supported in upstream secp-zkp
        // but bindings are not exposed.
        // The interpreter will error on non 32 byte messages till it is fixed.
        let msg = secp256k1_zkp::Message::from_slice(&self.as_msg().0)?;

        let secp = secp256k1_zkp::Secp256k1::verification_only();

        secp.verify_schnorr(&sig, &msg, &self.as_pk())?;
        Ok(true)
    }
}

impl<PExt, QExt, PArg, QArg> TranslateExt<PExt, QExt, PArg, QArg> for CheckSigFromStack<PArg>
where
    PExt: Extension,
    QExt: Extension,
    PArg: ExtParam,
    QArg: ExtParam,
{
    type Output = CheckSigFromStack<QArg>;

    fn translate_ext<T, E>(&self, t: &mut T) -> Result<Self::Output, E>
    where
        T: ExtTranslator<PArg, QArg, E>,
        PArg: ExtParam,
        QArg: ExtParam,
    {
        Ok(CheckSigFromStack {
            pk: t.ext(&self.pk)?,
            msg: t.ext(&self.msg)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::XOnlyPublicKey;

    use super::*;
    use crate::{Miniscript, Segwitv0, Tap};

    #[test]
    fn test_csfs() {
        type MsExtCsfs = Miniscript<XOnlyPublicKey, Tap, CheckSigFromStack<CovExtArgs>>;
        type MsExtCsfsSegwitv0 =
            Miniscript<XOnlyPublicKey, Segwitv0, CheckSigFromStack<CovExtArgs>>;

        // Make sure that parsing this errors in segwit context
        assert!(MsExtCsfsSegwitv0::from_str_insane(
            "csfs(26d137d15e2ae24f2d5158663d190d1269ad6b1a6ce330aa825ba502e7519d44,f38b23e7d84506eb8eb477792ba607f908fe8a64ac9ae8dc0e760096e1550562)",
        )
        .is_err());

        let ms = MsExtCsfs::from_str_insane(
            "csfs(26d137d15e2ae24f2d5158663d190d1269ad6b1a6ce330aa825ba502e7519d44,f38b23e7d84506eb8eb477792ba607f908fe8a64ac9ae8dc0e760096e1550562)",
        )
        .unwrap();
        // test string rtt
        assert_eq!(
            ms.to_string(),
            "csfs(26d137d15e2ae24f2d5158663d190d1269ad6b1a6ce330aa825ba502e7519d44,f38b23e7d84506eb8eb477792ba607f908fe8a64ac9ae8dc0e760096e1550562)"
        );
        // script rtt
        assert_eq!(ms, MsExtCsfs::parse_insane(&ms.encode()).unwrap());

        // Test translate
        // Translation tests to be added in upcoming commits
    }
}
