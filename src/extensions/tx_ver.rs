//! Miniscript extension: ver_eq
//! Note that this fragment is only supported for Segwit context
//! You are most likely looking for taproot direct tx introspection

use std::fmt;

use crate::MiniscriptKey;

use crate::miniscript;
use crate::Extension;
use crate::ForEach;
use crate::TranslatePk;
use elements::{self, encode::serialize};

use crate::ToPublicKey;

use crate::util;

use crate::{
    descriptor::CovError,
    expression, interpreter,
    miniscript::{
        astelem::StackCtxOperations,
        lex::{Token as Tk, TokenIter},
        satisfy::{Satisfaction, Witness},
        types::{
            extra_props::TimeLockInfo, Base, Correctness, Dissat, ExtData, Input, Malleability,
        },
    },
    policy::{self, Liftable},
    Error, Satisfier,
};

/// Version struct
/// `DEPTH <12> SUB PICK <num> EQUAL`
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy)]
pub struct VerEq {
    /// the version of transaction
    pub n: u32, // it's i32 in bitcoin core
}

impl fmt::Display for VerEq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ver_eq({})", self.n)
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for VerEq {
    fn lift(&self) -> Result<policy::Semantic<Pk>, Error> {
        Err(Error::CovError(CovError::CovenantLift))
    }
}

impl<Pk: MiniscriptKey> Extension<Pk> for VerEq {
    fn real_for_each_key<'a, F>(&'a self, _pred: &mut F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
        F: FnMut(ForEach<'a, Pk>) -> bool,
    {
        true
    }

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
            ops_count_static: 4,
            ops_count_sat: Some(4),
            ops_count_nsat: Some(4),
            stack_elem_count_sat: Some(0),
            stack_elem_count_dissat: Some(0),
            max_sat_size: Some((0, 0)),
            max_dissat_size: Some((0, 0)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(2),
            exec_stack_elem_count_dissat: Some(2),
        }
    }

    fn satisfy<S>(&self, sat: &S) -> Satisfaction
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

    fn dissatisfy<S>(&self, sat: &S) -> Satisfaction
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

    fn push_to_builder(&self, builder: elements::script::Builder) -> elements::script::Builder
    where
        Pk: ToPublicKey,
    {
        builder.check_item_eq(12, &serialize(&self.n))
    }

    fn script_size(&self) -> usize {
        4 + 1 + 1 + 4 // opcodes + push opcodes + target size
    }

    fn from_token_iter(tokens: &mut TokenIter) -> Result<Self, ()> {
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

    fn from_name_tree(name: &str, children: &[expression::Tree]) -> Result<Self, ()> {
        if children.len() == 1 && name == "ver_eq" {
            let n = expression::terminal(&children[0], expression::parse_num).map_err(|_| ())?;
            Ok(Self { n })
        } else {
            // Correct error handling while parsing fromtree
            Err(())
        }
    }

    fn evaluate<'intp, 'txin>(
        &'intp self,
        stack: &mut interpreter::Stack<'txin>,
    ) -> Option<Result<(), interpreter::Error>> {
        // Version is at index 11
        let ver = stack[11];
        if let Err(e) = ver.try_push() {
            return Some(Err(e));
        }
        let elem = ver.try_push().unwrap(); // TODO: refactor this later to avoid unwrap
        if elem.len() == 4 {
            let wit_ver = util::slice_to_u32_le(elem);
            if wit_ver == self.n {
                stack.push(interpreter::Element::Satisfied);
                Some(Ok(()))
            } else {
                None
            }
        } else {
            Some(Err(interpreter::Error::CovWitnessSizeErr {
                pos: 1,
                expected: 4,
                actual: elem.len(),
            }))
        }
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for VerEq {
    type Output = VerEq;

    fn translate_pk<Fpk, Fpkh, E>(
        &self,
        mut _translatefpk: Fpk,
        _translatefpkh: Fpkh,
    ) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        Ok(Self { n: self.n })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Miniscript, Segwitv0};
    use bitcoin::PublicKey;

    #[test]
    fn test_ver_eq() {
        type MsExtVer = Miniscript<PublicKey, Segwitv0, VerEq>;

        let ms = MsExtVer::from_str_insane("ver_eq(8)").unwrap();
        // test string rtt
        assert_eq!(ms.to_string(), "ver_eq(8)");
        // script rtt
        assert_eq!(ms, MsExtVer::parse_insane(&ms.encode()).unwrap())
    }
}
