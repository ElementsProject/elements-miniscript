//! Miniscript extension: ver_eq
//! Note that this fragment is only supported for Segwit context
//! You are most likely looking for taproot direct tx introspection

use std::fmt;

use elements::encode::serialize;
use elements::{self};

use super::{ExtParam, ParseableExt};
use crate::descriptor::CovError;
use crate::miniscript::astelem::StackCtxOperations;
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::satisfy::{Satisfaction, Witness};
use crate::miniscript::types::extra_props::{OpLimits, TimelockInfo};
use crate::miniscript::types::{Base, Correctness, Dissat, ExtData, Input, Malleability};
use crate::policy::{self, Liftable};
use crate::{
    expression, interpreter, miniscript, util, Error, ExtTranslator, Extension, MiniscriptKey,
    Satisfier, ToPublicKey, TranslateExt,
};

/// Version struct
/// `DEPTH <12> SUB PICK <num> EQUAL`
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy)]
pub struct LegacyVerEq {
    /// the version of transaction
    pub n: u32, // it's i32 in bitcoin core
}

impl fmt::Display for LegacyVerEq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ver_eq({})", self.n)
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for LegacyVerEq {
    fn lift(&self) -> Result<policy::Semantic<Pk>, Error> {
        Err(Error::CovError(CovError::CovenantLift))
    }
}

impl Extension for LegacyVerEq {
    fn segwit_ctx_checks(&self) -> Result<(), miniscript::context::ScriptContextError> {
        Ok(())
    }

    fn corr_prop(&self) -> Correctness {
        Correctness {
            base: Base::B,
            input: Input::Zero,
            dissatisfiable: true,
            unit: true,
        }
    }

    fn mall_prop(&self) -> Malleability {
        Malleability {
            dissat: Dissat::Unknown, // multi-dissat
            safe: false,
            non_malleable: true,
        }
    }

    fn extra_prop(&self) -> ExtData {
        ExtData {
            pk_cost: 4 + 1 + 1 + 4, // 4 opcodes, 1 push, (5) 4 byte push
            has_free_verify: true,
            stack_elem_count_sat: Some(0),
            stack_elem_count_dissat: Some(0),
            max_sat_size: Some((0, 0)),
            max_dissat_size: Some((0, 0)),
            timelock_info: TimelockInfo::default(),
            exec_stack_elem_count_sat: Some(2),
            exec_stack_elem_count_dissat: Some(2),
            ops: OpLimits {
                count: 4,
                sat: Some(0),
                nsat: Some(0),
            },
        }
    }

    fn script_size(&self) -> usize {
        4 + 1 + 1 + 4 // opcodes + push opcodes + target size
    }

    fn from_name_tree(name: &str, children: &[expression::Tree<'_>]) -> Result<Self, ()> {
        if children.len() == 1 && name == "ver_eq" {
            let n = expression::terminal(&children[0], expression::parse_num).map_err(|_| ())?;
            Ok(Self { n })
        } else {
            // Correct error handling while parsing fromtree
            Err(())
        }
    }
}

impl ParseableExt for LegacyVerEq {
    fn satisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let wit = match sat.lookup_nversion() {
            Some(k) => {
                if k == self.n {
                    Witness::empty()
                } else {
                    Witness::Impossible
                }
            }
            // Note the unavailable instead of impossible because we don't know
            // the version
            None => Witness::Unavailable,
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
        let wit = if let Some(k) = sat.lookup_nversion() {
            if k == self.n {
                Witness::Impossible
            } else {
                Witness::empty()
            }
        } else {
            Witness::empty()
        };
        Satisfaction {
            stack: wit,
            has_sig: false,
        }
    }

    fn push_to_builder(&self, builder: elements::script::Builder) -> elements::script::Builder {
        builder.check_item_eq(12, &serialize(&self.n))
    }

    fn from_token_iter(tokens: &mut TokenIter<'_>) -> Result<Self, ()> {
        let ver = {
            let sl = tokens.peek_slice(5).ok_or(())?;
            if let Tk::PickPush4(ver) = sl[3] {
                if sl[0] == Tk::Depth
                    && sl[1] == Tk::Num(12)
                    && sl[2] == Tk::Sub
                    && sl[4] == Tk::Equal
                {
                    Self { n: ver }
                } else {
                    return Err(());
                }
            } else {
                return Err(());
            }
        };
        tokens.advance(5).expect("Size checked previously");
        Ok(ver)
    }

    fn evaluate<'intp, 'txin>(
        &'intp self,
        stack: &mut interpreter::Stack<'txin>,
    ) -> Result<bool, interpreter::Error> {
        // Version is at index 11
        let ver = stack[11];
        let elem = ver.try_push()?;
        if elem.len() == 4 {
            let wit_ver = util::slice_to_u32_le(elem);
            if wit_ver == self.n {
                stack.push(interpreter::Element::Satisfied);
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(interpreter::Error::CovWitnessSizeErr {
                pos: 1,
                expected: 4,
                actual: elem.len(),
            })
        }
    }
}

impl<PExt, QExt, PArg, QArg> TranslateExt<PExt, QExt, PArg, QArg> for LegacyVerEq
where
    PExt: Extension,
    QExt: Extension,
    PArg: ExtParam,
    QArg: ExtParam,
{
    type Output = LegacyVerEq;

    fn translate_ext<T, E>(&self, _t: &mut T) -> Result<Self::Output, E>
    where
        T: ExtTranslator<PArg, QArg, E>,
    {
        Ok(Self { n: self.n })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::PublicKey;

    use super::*;
    use crate::{Miniscript, Segwitv0};

    #[test]
    fn test_ver_eq() {
        type MsExtVer = Miniscript<PublicKey, Segwitv0, LegacyVerEq>;

        let ms = MsExtVer::from_str_insane("ver_eq(8)").unwrap();
        // test string rtt
        assert_eq!(ms.to_string(), "ver_eq(8)");
        // script rtt
        assert_eq!(ms, MsExtVer::parse_insane(&ms.encode()).unwrap())
    }
}
