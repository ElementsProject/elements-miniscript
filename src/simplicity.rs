// SPDX-License-Identifier: CC0-1.0
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin_miniscript::ToPublicKey;
use elements::{LockTime, SchnorrSig, Sequence};
use elements::taproot::TapLeafHash;
use simplicity::{Policy, FailEntropy, Preimage32};

use crate::policy::concrete::PolicyError;
use crate::{expression, Error, MiniscriptKey};

impl_from_tree!(
    Policy<Pk>,
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        match (top.name, top.args.len() as u32) {
            ("UNSATISFIABLE", 0) => Ok(Policy::Unsatisfiable(FailEntropy::ZERO)),
            ("TRIVIAL", 0) => Ok(Policy::Trivial),
            ("pk", 1) => expression::terminal(&top.args[0], |pk| Pk::from_str(pk).map(Policy::Key)),
            ("after", 1) => expression::terminal(&top.args[0], |x| {
                expression::parse_num(x).map(Policy::After)
            }),
            ("older", 1) => expression::terminal(&top.args[0], |x| {
                expression::parse_num(x).map(Policy::Older)
            }),
            ("sha256", 1) => expression::terminal(&top.args[0], |x| {
                Pk::Sha256::from_str(x).map(Policy::Sha256)
            }),
            ("and", _) => {
                if top.args.len() != 2 {
                    return Err(Error::PolicyError(PolicyError::NonBinaryArgAnd));
                }
                let left = Arc::new(Policy::from_tree(&top.args[0])?);
                let right = Arc::new(Policy::from_tree(&top.args[0])?);
                Ok(Policy::And { left, right })
            }
            ("or", _) => {
                if top.args.len() != 2 {
                    return Err(Error::PolicyError(PolicyError::NonBinaryArgOr));
                }
                let left = Arc::new(Policy::from_tree(&top.args[0])?);
                let right = Arc::new(Policy::from_tree(&top.args[0])?);
                Ok(Policy::Or { left, right })
            }
            ("thresh", nsubs) => {
                if nsubs == 0 {
                    return Err(Error::Unexpected("thresh without args".to_owned()));
                }
                if nsubs < 3 {
                    return Err(Error::Unexpected(
                        "thresh must have a threshold value and at least 2 children".to_owned(),
                    ));
                }
                if !top.args[0].args.is_empty() {
                    return Err(Error::Unexpected(top.args[0].args[0].name.to_owned()));
                }

                let thresh: u32 = expression::parse_num(top.args[0].name)?;
                if thresh >= nsubs {
                    return Err(Error::Unexpected(top.args[0].name.to_owned()));
                }

                let mut subs = Vec::with_capacity(top.args.len() - 1);
                for arg in &top.args[1..] {
                    subs.push(Policy::from_tree(arg)?);
                }
                Ok(Policy::Threshold(thresh as usize, subs))
            }
            _ => Err(Error::Unexpected(top.name.to_owned())),
        }
    }
);

// We cannot implement FromStr for Policy<Pk> because neither is defined in this crate
// Use a crate-local wrapper type to avoid code repetition
// Users use `Tr` / `Descriptor` and never encounter this wrapper
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub(crate) struct PolicyWrapper<Pk: MiniscriptKey>(pub Policy<Pk>);

impl<Pk: MiniscriptKey> fmt::Debug for PolicyWrapper<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl_from_str!(
    PolicyWrapper<Pk>,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tree = expression::Tree::from_str(s)?;
        <Policy<Pk> as expression::FromTree>::from_tree(&tree).map(PolicyWrapper)
    }
);

// We cannot implement ForEachKey for Policy<Pk> because it is not defined in this crate
// We cannot use our wrapper because we don't own the Policy (we have a reference)
// Implementing a wrapper of Cow<'a, Policy<Pk>> leads to lifetime issues
// when implementing ForEachKey, because for_each_key() has its own lifetime 'a
pub fn for_each_key<'a, Pk: MiniscriptKey, F: FnMut(&'a Pk) -> bool>(policy: &'a Policy<Pk>, mut pred: F) -> bool
where
    Pk: 'a,
{
    let mut stack = vec![policy];

    while let Some(top) = stack.pop() {
        match top {
            Policy::Key(key) => {
                if !pred(key) {
                    return false;
                }
            }
            Policy::And { left, right } | Policy::Or { left, right } => {
                stack.push(right);
                stack.push(left);
            }
            Policy::Threshold(_, sub_policies) => {
                stack.extend(sub_policies.iter());
            }
            _ => {}
        }
    }

    true
}

// We could make crate::Satisfier a subtrait of simplicity::Satisfier,
// but then we would have to implement simplicity::Satisfier for all the blanket implementations
// of crate::Satisfier, such as HashMap<Pk, ElementsSig>, which is annoying
// We might choose to do so in the future, but for now a crate-local wrapper is easier
// This wrapper is internally used by `Tr` and is never encountered by users
pub(crate) struct SatisfierWrapper<Pk: ToPublicKey, S: crate::Satisfier<Pk>>(S, PhantomData<Pk>);

impl<Pk: ToPublicKey, S: crate::Satisfier<Pk>> SatisfierWrapper<Pk, S> {
    pub fn new(satisfier: S) -> Self {
        Self(satisfier, PhantomData)
    }
}

impl<Pk: ToPublicKey, S: crate::Satisfier<Pk>> simplicity::Satisfier<Pk> for SatisfierWrapper<Pk, S> {
    fn lookup_tap_leaf_script_sig(&self, pk: &Pk, hash: &TapLeafHash) -> Option<SchnorrSig> {
        self.0.lookup_tap_leaf_script_sig(pk, hash)
    }

    fn lookup_sha256(&self, hash: &Pk::Sha256) -> Option<Preimage32> {
        self.0.lookup_sha256(hash)
    }

    fn check_older(&self, sequence: Sequence) -> bool {
        self.0.check_older(sequence)
    }

    fn check_after(&self, locktime: LockTime) -> bool {
        self.0.check_after(locktime)
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::XOnlyPublicKey;
    use crate::DescriptorPublicKey;
    use super::*;

    #[test]
    fn parse_bad_thresh() {
        assert_eq!(
            PolicyWrapper::<XOnlyPublicKey>::from_str("thresh()"),
            Err(Error::Unexpected(
                "thresh must have a threshold value and at least 2 children".to_string()
            )),
        );

        assert_eq!(
            PolicyWrapper::<XOnlyPublicKey>::from_str("thresh"),
            Err(Error::Unexpected("thresh without args".to_string())),
        );

        assert_eq!(
            PolicyWrapper::<XOnlyPublicKey>::from_str("thresh(0)"),
            Err(Error::Unexpected(
                "thresh must have a threshold value and at least 2 children".to_string()
            )),
        );

        assert_eq!(
            PolicyWrapper::<XOnlyPublicKey>::from_str("thresh(0,TRIVIAL)"),
            Err(Error::Unexpected(
                "thresh must have a threshold value and at least 2 children".to_string()
            )),
        );

        assert!(PolicyWrapper::<XOnlyPublicKey>::from_str("thresh(0,TRIVIAL,TRIVIAL)").is_ok());
        assert!(PolicyWrapper::<XOnlyPublicKey>::from_str("thresh(2,TRIVIAL,TRIVIAL)").is_ok());

        assert_eq!(
            PolicyWrapper::<XOnlyPublicKey>::from_str("thresh(3,TRIVIAL,TRIVIAL)"),
            Err(Error::Unexpected("3".to_string())),
        );
    }

    #[test]
    fn decode_xpub() {
        let s = "[78412e3a/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*";
        let decoded_key = DescriptorPublicKey::from_str(s).expect("constant key");
        let s = format!("pk({})", s);
        let decoded_policy = PolicyWrapper::<DescriptorPublicKey>::from_str(&s).expect("decode policy").0;

        if let Policy::Key(key) = decoded_policy {
            assert_eq!(decoded_key, key);
        } else {
            panic!("Decoded policy should be public key")
        }
    }
}
