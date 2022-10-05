//! Miniscript extension: outputs_pref
//! Note that this fragment is only supported for Segwit context
//! You are most likely looking for taproot direct tx introspection

use std::fmt;

use elements::encode::serialize;
use elements::hashes::hex::{FromHex, ToHex};
use elements::hashes::{sha256d, Hash};

use super::{ParseableExt, TxEnv};
use crate::descriptor::CovError;
use crate::miniscript::astelem::StackCtxOperations;
use crate::miniscript::context::ScriptContextError;
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::limits::{MAX_SCRIPT_ELEMENT_SIZE, MAX_STANDARD_P2WSH_STACK_ITEM_SIZE};
use crate::miniscript::satisfy::{Satisfaction, Witness};
use crate::miniscript::types::extra_props::{OpLimits, TimelockInfo};
use crate::miniscript::types::{Base, Correctness, Dissat, ExtData, Input, Malleability};
use crate::policy::{self, Liftable};
use crate::{
    expression, interpreter, Error, Extension, MiniscriptKey, Satisfier,
    ToPublicKey
};

/// Prefix is initally encoded in the script pubkey
/// User provides a suffix such that hash of (prefix || suffix)
/// is equal to hashOutputs
/// Since, there is a policy restriction that initial pushes must be
/// only 80 bytes, we need user to provide suffix in separate items
/// There can be atmost 7 cats, because the script element must be less
/// than 520 bytes total in order to compute an hash256 on it.
/// Even if the witness does not require 7 pushes, the user should push
/// 7 elements with possibly empty values.
///
/// CAT CAT CAT CAT CAT CAT <pref> SWAP CAT /*Now we hashoutputs on stack */
/// HASH256
/// DEPTH <10> SUB PICK EQUALVERIFY
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct LegacyOutputsPref {
    /// the version of transaction
    pub pref: Vec<u8>,
}

impl fmt::Display for LegacyOutputsPref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "outputs_pref({})", self.pref.to_hex())
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for LegacyOutputsPref {
    fn lift(&self) -> Result<policy::Semantic<Pk>, Error> {
        Err(Error::CovError(CovError::CovenantLift))
    }
}

impl Extension for LegacyOutputsPref {
    fn segwit_ctx_checks(&self) -> Result<(), ScriptContextError> {
        if self.pref.len() > MAX_SCRIPT_ELEMENT_SIZE {
            Err(ScriptContextError::CovElementSizeExceeded)
        } else {
            Ok(())
        }
    }

    fn corr_prop(&self) -> Correctness {
        Correctness {
            base: Base::B,
            input: Input::Any,    // 7 outputs
            dissatisfiable: true, // Any 7 elements that don't cat
            unit: true,
        }
    }

    fn mall_prop(&self) -> Malleability {
        Malleability {
            dissat: Dissat::Unknown,
            safe: false,
            non_malleable: true,
        }
    }

    fn extra_prop(&self) -> ExtData {
        // Assume txouts fill out all the 520 bytes
        let max_wit_sz = MAX_SCRIPT_ELEMENT_SIZE - self.pref.len();
        ExtData {
            pk_cost: 8 + self.pref.len() + 1 + 6, // See script_size() in astelem.rs
            has_free_verify: true,
            stack_elem_count_sat: Some(7),
            stack_elem_count_dissat: Some(7),
            max_sat_size: Some((max_wit_sz, max_wit_sz)),
            max_dissat_size: Some((0, 0)), // all empty should dissatisfy
            timelock_info: TimelockInfo::default(),
            exec_stack_elem_count_sat: Some(3), // sha2 context, byte slice, target hash
            exec_stack_elem_count_dissat: Some(3),
            ops: OpLimits {
                count: 13,
                sat: Some(0),
                nsat: Some(0),
            },
        }
    }

    fn script_size(&self) -> usize {
        // CAT CAT CAT CAT CAT CAT <pref> SWAP CAT /*Now we hashoutputs on stack */
        // HASH256 DEPTH <10> SUB PICK EQUAL
        8 + self.pref.len() + 1 /* line1 opcodes + pref.push */
                + 6 /* line 2 */
    }

    fn from_name_tree(name: &str, children: &[expression::Tree<'_>]) -> Result<Self, ()> {
        if children.len() == 1 && name == "outputs_pref" {
            let pref = expression::terminal(&children[0], Vec::<u8>::from_hex).map_err(|_| ())?;
            Ok(Self { pref })
        } else {
            // Correct error handling while parsing fromtree
            Err(())
        }
    }
}

impl ParseableExt for LegacyOutputsPref {
    fn satisfy<Pk, S>(&self, sat: &S) -> Satisfaction
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let wit = match sat.lookup_outputs() {
            Some(outs) => {
                let mut ser_out = Vec::new();
                let num_wit_elems =
                    MAX_SCRIPT_ELEMENT_SIZE / MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1;
                let mut witness = Vec::with_capacity(num_wit_elems);
                for out in outs {
                    ser_out.extend(serialize(out));
                }
                // We need less than 520 bytes of serialized hashoutputs
                // in order to compute hash256 inside script
                if ser_out.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    Witness::Impossible
                } else if ser_out.starts_with(&self.pref) {
                    let mut iter = ser_out.into_iter().skip(self.pref.len()).peekable();

                    while iter.peek().is_some() {
                        let chk_size = MAX_STANDARD_P2WSH_STACK_ITEM_SIZE;
                        let chunk: Vec<u8> = iter.by_ref().take(chk_size).collect();
                        witness.push(chunk);
                    }
                    // Append empty elems to make for extra cats
                    // in the spk
                    while witness.len() < num_wit_elems {
                        witness.push(vec![]);
                    }
                    Witness::Stack(witness)
                } else {
                    Witness::Impossible
                }
            }
            // Note the unavailable instead of impossible because we don't know
            // the hashoutputs yet
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
        let wit = match sat.lookup_outputs() {
            Some(outs) => {
                let mut ser_out = Vec::new();
                for out in outs {
                    ser_out.extend(serialize(out));
                }
                let num_wit_elems = MAX_SCRIPT_ELEMENT_SIZE / MAX_STANDARD_P2WSH_STACK_ITEM_SIZE;
                let mut witness = Vec::with_capacity(num_wit_elems);
                if self.pref != ser_out.as_slice() {
                    while witness.len() < num_wit_elems {
                        witness.push(vec![]);
                    }
                    Witness::Stack(witness)
                } else if self.pref.len() != MAX_SCRIPT_ELEMENT_SIZE {
                    // Case when prefix == ser_out and it is possible
                    // to add more witness
                    witness.push(vec![1]);
                    while witness.len() < num_wit_elems {
                        witness.push(vec![]);
                    }
                    Witness::Stack(witness)
                } else {
                    // case when pref == ser_out and len of both is 520
                    Witness::Impossible
                }
            }
            // Note the unavailable instead of impossible because we don't know
            // the hashoutputs yet
            None => Witness::Unavailable,
        };
        Satisfaction {
            stack: wit,
            has_sig: false,
        }
    }

    fn push_to_builder(&self, builder: elements::script::Builder) -> elements::script::Builder {
        builder.check_item_pref(4, &self.pref)
    }

    fn from_token_iter(tokens: &mut TokenIter<'_>) -> Result<Self, ()> {
        let outputs_pref = {
            let sl = tokens.peek_slice(15).ok_or(())?;
            if let Tk::Push(pref) = &sl[6] {
                if sl[0] == Tk::Cat
                    && sl[1] == Tk::Cat
                    && sl[2] == Tk::Cat
                    && sl[3] == Tk::Cat
                    && sl[4] == Tk::Cat
                    && sl[5] == Tk::Cat
                    && sl[7] == Tk::Swap
                    && sl[8] == Tk::Cat
                    && sl[9] == Tk::Hash256
                    && sl[11] == Tk::Num(4)
                    && sl[12] == Tk::Sub
                    && sl[13] == Tk::Pick
                    && sl[14] == Tk::Equal
                {
                    Self { pref: pref.clone() }
                } else {
                    return Err(());
                }
            } else {
                return Err(());
            }
        };
        tokens.advance(15).expect("Size checked previously");
        Ok(outputs_pref)
    }

    fn evaluate<'intp, 'txin>(
        &'intp self,
        stack: &mut interpreter::Stack<'txin>,
        _txenv: Option<&TxEnv>,
    ) -> Result<bool, interpreter::Error> {
        // Hash Outputs is at index 3
        let hash_outputs = stack[3];
        let hash_outputs = hash_outputs.try_push()?;
        // Maximum number of suffix elements
        let max_elems = MAX_SCRIPT_ELEMENT_SIZE / MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1;
        if hash_outputs.len() == 32 {
            // We want to cat the last 6 elements(5 cats) in suffix
            if stack.len() < max_elems {
                return Err(interpreter::Error::UnexpectedStackEnd);
            }
            let mut outputs_builder = Vec::new();
            outputs_builder.extend(&self.pref);
            let len = stack.len();
            // Add the max_elems suffix elements
            for i in 0..max_elems {
                outputs_builder.extend(stack[len - max_elems + i].into_slice());
            }
            // Pop the max_elems suffix elements
            for _ in 0..max_elems {
                stack.pop().unwrap();
            }
            if sha256d::Hash::hash(&outputs_builder).as_inner() == hash_outputs {
                stack.push(interpreter::Element::Satisfied);
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(interpreter::Error::CovWitnessSizeErr {
                pos: 9,
                expected: 32,
                actual: hash_outputs.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::PublicKey;

    use super::*;
    use crate::{Miniscript, Segwitv0};

    #[test]
    fn test_outputs_pref() {
        type MsExtVer = Miniscript<PublicKey, Segwitv0, LegacyOutputsPref>;

        let ms = MsExtVer::from_str_insane("outputs_pref(aa)").unwrap();
        // test string rtt
        assert_eq!(ms.to_string(), "outputs_pref(aa)");
        // script rtt
        assert_eq!(ms, MsExtVer::parse_insane(&ms.encode()).unwrap())
    }
}
