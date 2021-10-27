// Miniscript
// Written in 2019 by
//     Sanket Kanjalkar and Andrew Poelstra
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

use miniscript::limits::{
    MAX_OPS_PER_SCRIPT, MAX_SCRIPTSIG_SIZE, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE,
    MAX_STANDARD_P2WSH_SCRIPT_SIZE, MAX_STANDARD_P2WSH_STACK_ITEMS,
};
use miniscript::types;
use std::fmt;
use util::witness_to_scriptsig;
use Error;

use Extension;
use {Miniscript, MiniscriptKey, Terminal};
/// Error for Script Context
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ScriptContextError {
    /// Script Context does not permit PkH for non-malleability
    /// It is not possible to estimate the pubkey size at the creation
    /// time because of uncompressed pubkeys
    MalleablePkH,
    /// Script Context does not permit OrI for non-malleability
    /// Legacy fragments allow non-minimal IF which results in malleability
    MalleableOrI,
    /// Script Context does not permit DupIf for non-malleability
    /// Legacy fragments allow non-minimal IF which results in malleability
    MalleableDupIf,
    /// Only Compressed keys allowed under current descriptor
    /// Segwitv0 fragments do not allow uncompressed pubkeys
    CompressedOnly,
    /// At least one satisfaction path in the Miniscript fragment has more than
    /// `MAX_STANDARD_P2WSH_STACK_ITEMS` (100) witness elements.
    MaxWitnessItemssExceeded,
    /// At least one satisfaction path in the Miniscript fragment contains more
    /// than `MAX_OPS_PER_SCRIPT`(201) opcodes.
    MaxOpCountExceeded,
    /// The Miniscript(under segwit context) corresponding
    /// Script would be larger than `MAX_STANDARD_P2WSH_SCRIPT_SIZE` bytes.
    MaxWitnessScriptSizeExceeded,
    /// The Miniscript (under p2sh context) corresponding Script would be
    /// larger than `MAX_SCRIPT_ELEMENT_SIZE` bytes.
    MaxRedeemScriptSizeExceeded,
    /// The policy rules of bitcoin core only permit Script size upto 1650 bytes
    MaxScriptSigSizeExceeded,
    /// Impossible to satisfy the miniscript under the current context
    ImpossibleSatisfaction,
    /// Covenant Prefix/ Suffix maximum allowed stack element exceeds 520 bytes
    CovElementSizeExceeded,
    /// Extension Error for Downstream implementations, includes a string
    ExtensionError(String),
}

impl fmt::Display for ScriptContextError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ScriptContextError::MalleablePkH => write!(f, "PkH is malleable under Legacy rules"),
            ScriptContextError::MalleableOrI => write!(f, "OrI is malleable under Legacy rules"),
            ScriptContextError::MalleableDupIf => {
                write!(f, "DupIf is malleable under Legacy rules")
            }
            ScriptContextError::CompressedOnly => {
                write!(f, "Uncompressed pubkeys not allowed in segwit context")
            }
            ScriptContextError::MaxWitnessItemssExceeded => write!(
                f,
                "At least one spending path in the Miniscript fragment has more \
                 witness items than MAX_STANDARD_P2WSH_STACK_ITEMS.",
            ),
            ScriptContextError::MaxOpCountExceeded => write!(
                f,
                "At least one satisfaction path in the Miniscript fragment contains \
                 more than MAX_OPS_PER_SCRIPT opcodes."
            ),
            ScriptContextError::MaxWitnessScriptSizeExceeded => write!(
                f,
                "The Miniscript corresponding Script would be larger than \
                    MAX_STANDARD_P2WSH_SCRIPT_SIZE bytes."
            ),
            ScriptContextError::MaxRedeemScriptSizeExceeded => write!(
                f,
                "The Miniscript corresponding Script would be larger than \
                MAX_SCRIPT_ELEMENT_SIZE bytes."
            ),
            ScriptContextError::MaxScriptSigSizeExceeded => write!(
                f,
                "At least one satisfaction in Miniscript would be larger than \
                MAX_SCRIPTSIG_SIZE scriptsig"
            ),
            ScriptContextError::ImpossibleSatisfaction => {
                write!(
                    f,
                    "Impossible to satisfy Miniscript under the current context"
                )
            }
            ScriptContextError::CovElementSizeExceeded => {
                write!(
                    f,
                    "Prefix/Suffix len in sighash covenents exceeds 520 bytes"
                )
            }
            ScriptContextError::ExtensionError(ref s) => write!(f, "Extension Error: {}", s),
        }
    }
}

/// The ScriptContext for Miniscript. Additional type information associated with
/// miniscript that is used for carrying out checks that dependent on the
/// context under which the script is used.
/// For example, disallowing uncompressed keys in Segwit context
pub trait ScriptContext:
    fmt::Debug + Clone + Ord + PartialOrd + Eq + PartialEq + private::Sealed
{
    /// Depending on ScriptContext, fragments can be malleable. For Example,
    /// under Legacy context, PkH is malleable because it is possible to
    /// estimate the cost of satisfaction because of compressed keys
    /// This is currently only used in compiler code for removing malleable
    /// compilations.
    /// This does NOT recursively check if the children of the fragment are
    /// valid or not. Since the compilation proceeds in a leaf to root fashion,
    /// a recursive check is unnecessary.
    fn check_terminal_non_malleable<Pk, Ctx, Ext>(
        _frag: &Terminal<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError>
    where
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>;

    /// Check whether the given satisfaction is valid under the ScriptContext
    /// For example, segwit satisfactions may fail if the witness len is more
    /// 3600 or number of stack elements are more than 100.
    fn check_witness<Pk, Ctx, Ext>(_witness: &[Vec<u8>]) -> Result<(), ScriptContextError>
    where
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>,
    {
        // Only really need to do this for segwitv0 and legacy
        // Bare is already restrcited by standardness rules
        // and would reach these limits.
        Ok(())
    }

    /// Depending on script context, the size of a satifaction witness may slightly differ.
    fn max_satisfaction_size<Pk, Ctx, Ext>(ms: &Miniscript<Pk, Ctx, Ext>) -> Option<usize>
    where
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>;
    /// Depending on script Context, some of the Terminals might not
    /// be valid under the current consensus rules.
    /// Or some of the script resource limits may have been exceeded.
    /// These miniscripts would never be accepted by the Bitcoin network and hence
    /// it is safe to discard them
    /// For example, in Segwit Context with MiniscriptKey as bitcoin::PublicKey
    /// uncompressed public keys are non-standard and thus invalid.
    /// In LegacyP2SH context, scripts above 520 bytes are invalid.
    /// Post Tapscript upgrade, this would have to consider other nodes.
    /// This does *NOT* recursively check the miniscript fragments.
    fn check_global_consensus_validity<
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>,
    >(
        _ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    /// Depending on script Context, some of the script resource limits
    /// may have been exceeded under the current bitcoin core policy rules
    /// These miniscripts would never be accepted by the Bitcoin network and hence
    /// it is safe to discard them. (unless explicitly disabled by non-standard flag)
    /// For example, in Segwit Context with MiniscriptKey as bitcoin::PublicKey
    /// scripts over 3600 bytes are invalid.
    /// Post Tapscript upgrade, this would have to consider other nodes.
    /// This does *NOT* recursively check the miniscript fragments.
    fn check_global_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    /// Consensus rules at the Miniscript satisfaction time.
    /// It is possible that some paths of miniscript may exceed resource limits
    /// and our current satisfier and lifting analysis would not work correctly.
    /// For example, satisfaction path(Legacy/Segwitv0) may require more than 201 opcodes.
    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    /// Policy rules at the Miniscript satisfaction time.
    /// It is possible that some paths of miniscript may exceed resource limits
    /// and our current satisfier and lifting analysis would not work correctly.
    /// For example, satisfaction path in Legacy context scriptSig more
    /// than 1650 bytes
    fn check_local_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    /// Check the consensus + policy(if not disabled) rules that are not based
    /// satisfaction
    fn check_global_validity<Pk, Ctx, Ext>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError>
    where
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>,
    {
        Self::check_global_consensus_validity(ms)?;
        Self::check_global_policy_validity(ms)?;
        Ok(())
    }

    /// Check the consensus + policy(if not disabled) rules including the
    /// ones for satisfaction
    fn check_local_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Self::check_global_consensus_validity(ms)?;
        Self::check_global_policy_validity(ms)?;
        Self::check_local_consensus_validity(ms)?;
        Self::check_local_policy_validity(ms)?;
        Ok(())
    }

    /// Check whether the top-level is type B
    fn top_level_type_check<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), Error> {
        if ms.ty.corr.base != types::Base::B {
            return Err(Error::NonTopLevel(format!("{:?}", ms)));
        }
        Ok(())
    }

    /// Other top level checks that are context specific
    fn other_top_level_checks<Pk, Ctx, Ext>(_ms: &Miniscript<Pk, Ctx, Ext>) -> Result<(), Error>
    where
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>,
    {
        Ok(())
    }

    /// Check top level consensus rules.
    // All the previous check_ were applied at each fragment while parsing script
    // Because if any of sub-miniscripts failed the reource level check, the entire
    // miniscript would also be invalid. However, there are certain checks like
    // in Bare context, only c:pk(key) (P2PK),
    // c:pk_h(key) (P2PKH), and thresh_m(k,...) up to n=3 are allowed
    // that are only applicable at the top-level
    // We can also combine the top-level check for Base::B here
    // even though it does not depend on context, but helps in cleaner code
    fn top_level_checks<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), Error> {
        Self::top_level_type_check(ms)?;
        Self::other_top_level_checks(ms)
    }
}

/// Legacy ScriptContext
/// To be used as P2SH scripts
/// For creation of Bare scriptpubkeys, construct the Miniscript
/// under `Bare` ScriptContext
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Legacy {}

impl ScriptContext for Legacy {
    fn check_terminal_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        frag: &Terminal<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        match *frag {
            Terminal::PkH(ref _pkh) => Err(ScriptContextError::MalleablePkH),
            Terminal::OrI(ref _a, ref _b) => Err(ScriptContextError::MalleableOrI),
            Terminal::DupIf(ref _ms) => Err(ScriptContextError::MalleableDupIf),
            _ => Ok(()),
        }
    }

    fn check_witness<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        witness: &[Vec<u8>],
    ) -> Result<(), ScriptContextError> {
        // In future, we could avoid by having a function to count only
        // len of script instead of converting it.
        if witness_to_scriptsig(witness).len() > MAX_SCRIPTSIG_SIZE {
            return Err(ScriptContextError::MaxScriptSigSizeExceeded);
        }
        Ok(())
    }

    fn check_global_consensus_validity<
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>,
    >(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        if ms.ext.pk_cost > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptContextError::MaxRedeemScriptSizeExceeded);
        }
        if let Terminal::Ext(ref _e) = ms.node {
            return Err(ScriptContextError::ExtensionError(String::from(
                "No Extensions in Legacy context",
            )));
        }
        Ok(())
    }

    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        match ms.ext.ops_count_sat {
            None => Err(ScriptContextError::MaxOpCountExceeded),
            Some(op_count) if op_count > MAX_OPS_PER_SCRIPT => {
                Err(ScriptContextError::MaxOpCountExceeded)
            }
            _ => Ok(()),
        }
    }

    fn check_local_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        // Legacy scripts permit upto 1000 stack elements, 520 bytes consensus limits
        // on P2SH size, it is not possible to reach the 1000 elements limit and hence
        // we do not check it.
        match ms.max_satisfaction_size() {
            Err(_e) => Err(ScriptContextError::ImpossibleSatisfaction),
            Ok(size) if size > MAX_SCRIPTSIG_SIZE => {
                Err(ScriptContextError::MaxScriptSigSizeExceeded)
            }
            _ => Ok(()),
        }
    }

    fn max_satisfaction_size<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Option<usize> {
        // The scriptSig cost is the second element of the tuple
        ms.ext.max_sat_size.map(|x| x.1)
    }
}

/// Segwitv0 ScriptContext
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Segwitv0 {}

impl ScriptContext for Segwitv0 {
    fn check_terminal_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _frag: &Terminal<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    fn check_witness<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        witness: &[Vec<u8>],
    ) -> Result<(), ScriptContextError> {
        if witness.len() > MAX_STANDARD_P2WSH_STACK_ITEMS {
            return Err(ScriptContextError::MaxWitnessItemssExceeded);
        }
        Ok(())
    }

    fn check_global_consensus_validity<
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>,
    >(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        if ms.ext.pk_cost > MAX_SCRIPT_SIZE {
            return Err(ScriptContextError::MaxWitnessScriptSizeExceeded);
        }

        match ms.node {
            Terminal::PkK(ref pk) => {
                if pk.is_uncompressed() {
                    return Err(ScriptContextError::CompressedOnly);
                }
                Ok(())
            }
            Terminal::Ext(ref e) => {
                e.segwit_ctx_checks()?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        match ms.ext.ops_count_sat {
            None => Err(ScriptContextError::MaxOpCountExceeded),
            Some(op_count) if op_count > MAX_OPS_PER_SCRIPT => {
                Err(ScriptContextError::MaxOpCountExceeded)
            }
            _ => Ok(()),
        }
    }

    fn check_global_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        if ms.ext.pk_cost > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
            return Err(ScriptContextError::MaxWitnessScriptSizeExceeded);
        }
        Ok(())
    }

    fn check_local_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        // We don't need to know if this is actually a p2wsh as the standard satisfaction for
        // other Segwitv0 defined programs all require (much) less than 100 elements.
        // The witness script item is accounted for in max_satisfaction_witness_elements().
        match ms.max_satisfaction_witness_elements() {
            // No possible satisfactions
            Err(_e) => Err(ScriptContextError::ImpossibleSatisfaction),
            Ok(max_witness_items) if max_witness_items > MAX_STANDARD_P2WSH_STACK_ITEMS => {
                Err(ScriptContextError::MaxWitnessItemssExceeded)
            }
            _ => Ok(()),
        }
    }

    fn max_satisfaction_size<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Option<usize> {
        // The witness stack cost is the first element of the tuple
        ms.ext.max_sat_size.map(|x| x.0)
    }
}

/// Bare ScriptContext
/// To be used as raw script pubkeys
/// In general, it is not recommended to use Bare descriptors
/// as they as strongly limited by standardness policies.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BareCtx {}

impl ScriptContext for BareCtx {
    fn check_terminal_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _frag: &Terminal<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        // Bare fragments can't contain miniscript because of standardness rules
        // This function is only used in compiler which already checks the standardness
        // and consensus rules, and because of the limited allowance of bare scripts
        // we need check for malleable scripts
        Ok(())
    }

    fn check_global_consensus_validity<
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>,
    >(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        if ms.ext.pk_cost > MAX_SCRIPT_SIZE {
            return Err(ScriptContextError::MaxWitnessScriptSizeExceeded);
        }
        if let Terminal::Ext(ref _e) = ms.node {
            return Err(ScriptContextError::ExtensionError(String::from(
                "No Extensions in Bare context",
            )));
        }
        Ok(())
    }

    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        match ms.ext.ops_count_sat {
            None => Err(ScriptContextError::MaxOpCountExceeded),
            Some(op_count) if op_count > MAX_OPS_PER_SCRIPT => {
                Err(ScriptContextError::MaxOpCountExceeded)
            }
            _ => Ok(()),
        }
    }

    fn other_top_level_checks<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), Error> {
        match &ms.node {
            Terminal::Check(ref ms) => match &ms.node {
                Terminal::PkH(_pkh) => Ok(()),
                Terminal::PkK(_pk) => Ok(()),
                _ => Err(Error::NonStandardBareScript),
            },
            Terminal::Multi(_k, subs) if subs.len() <= 3 => Ok(()),
            _ => Err(Error::NonStandardBareScript),
        }
    }

    fn max_satisfaction_size<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Option<usize> {
        // The witness stack cost is the first element of the tuple
        ms.ext.max_sat_size.map(|x| x.1)
    }
}

/// "No Checks" Context
///
/// Used by the "satisified constraints" iterator, which is intended to read
/// scripts off of the blockchain without doing any sanity checks on them.
/// This context should not be used unless you know what you are doing.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NoChecks {}
impl ScriptContext for NoChecks {
    fn check_terminal_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _frag: &Terminal<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    fn check_global_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    fn check_global_consensus_validity<
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
        Ext: Extension<Pk>,
    >(
        _ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    fn check_local_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    fn max_satisfaction_size<Pk: MiniscriptKey, Ctx: ScriptContext, Ext: Extension<Pk>>(
        _ms: &Miniscript<Pk, Ctx, Ext>,
    ) -> Option<usize> {
        panic!("Tried to compute a satisfaction size bound on a no-checks miniscript")
    }
}

/// Private Mod to prevent downstream from implementing this public trait
mod private {
    use super::{BareCtx, Legacy, NoChecks, Segwitv0};

    pub trait Sealed {}

    // Implement for those same types, but no others.
    impl Sealed for BareCtx {}
    impl Sealed for Legacy {}
    impl Sealed for Segwitv0 {}
    impl Sealed for NoChecks {}
}
