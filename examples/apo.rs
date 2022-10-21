//! Sighash any-prevout emulation using the new opcodes.

use bitcoin;
use elements::confidential::{Asset, Value};
use elements::encode::{self, deserialize};
use elements::hashes::hex::{FromHex, ToHex};
use elements::{confidential, opcodes, AddressParams, AssetId, TxOut};
use miniscript::descriptor::Tr;
use miniscript::extensions::{
    AssetExpr, CovExtArgs, CovOps, ParseableExt, Spk, SpkExpr, ValueExpr,
};
use miniscript::miniscript::satisfy::{Satisfaction, Witness};
use miniscript::miniscript::types::extra_props::{OpLimits, TimelockInfo};
use miniscript::miniscript::types::{Correctness, ExtData, Malleability};
use miniscript::{expression, Extension, TxEnv};
extern crate elements_miniscript as miniscript;

use std::fmt;

/// The data that needs to be signed in apo + all.
/// We can decompose this into into individual parts for fixing version, amt, script pubkey
///
/// This structure is onyl an example of how one might implement extension. We do pay any
/// special attention the serialization format, order of serialization etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SighashAllAPO {
    /// The outputs of transaction
    outputs: Vec<elements::TxOut>,
    /// The input script pubkey
    in_asset: elements::confidential::Asset,
    /// Input value
    in_value: elements::confidential::Value,
    /// Input script pubkey
    in_spk: elements::Script,
    /// The tx version
    version: u32,
    /// The tx locktime
    locktime: u32,
    /// The tx sequence
    sequence: u32,
}

impl SighashAllAPO {
    /// Evaluate the sighash_all_apo
    pub fn eval(&self, env: &TxEnv) -> Result<bool, miniscript::interpreter::Error> {
        let tx_inp = env
            .tx()
            .input
            .get(env.idx())
            .ok_or(miniscript::interpreter::Error::IncorrectCovenantWitness)?;
        let spent_utxo = env
            .spent_utxos()
            .get(env.idx())
            .ok_or(miniscript::interpreter::Error::IncorrectCovenantWitness)?;
        if tx_inp.sequence != self.sequence
            || env.tx().version != self.version
            || env.tx().lock_time != self.locktime
            || spent_utxo.asset != self.in_asset
            || spent_utxo.value != self.in_value
            || spent_utxo.script_pubkey != self.in_spk
            || env.tx().output != self.outputs
        {
            return Ok(false);
        }
        Ok(true)
    }
}

impl PartialOrd for SighashAllAPO {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SighashAllAPO {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // HACKY implementation that allocates a string
        self.to_string().cmp(&other.to_string())
    }
}

impl fmt::Display for SighashAllAPO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "all_apo({},{},{},{},{},{},{})",
            encode::serialize_hex(&self.outputs),
            encode::serialize_hex(&self.in_asset),
            encode::serialize_hex(&self.in_value),
            encode::serialize_hex(&self.in_spk),
            self.version,
            self.locktime,
            self.sequence,
        )
    }
}

impl Extension for SighashAllAPO {
    fn corr_prop(&self) -> miniscript::miniscript::types::Correctness {
        Correctness {
            base: miniscript::miniscript::types::Base::B,
            input: miniscript::miniscript::types::Input::Zero,
            dissatisfiable: true,
            unit: true,
        }
    }

    fn mall_prop(&self) -> miniscript::miniscript::types::Malleability {
        Malleability {
            dissat: miniscript::miniscript::types::Dissat::Unknown,
            safe: false,
            non_malleable: true,
        }
    }

    fn extra_prop(&self) -> miniscript::miniscript::types::ExtData {
        ExtData {
            pk_cost: 500, // dummy size, check real size later
            has_free_verify: true,
            stack_elem_count_sat: Some(0),
            stack_elem_count_dissat: Some(0),
            max_sat_size: Some((0, 0)),
            max_dissat_size: Some((0, 0)),
            timelock_info: TimelockInfo::default(),
            exec_stack_elem_count_sat: Some(2), // max stack size during execution = 2 elements
            exec_stack_elem_count_dissat: Some(2),
            ops: OpLimits {
                // Opcodes are really not relevant in tapscript as BIP342 removes all rules on them
                count: 1,
                sat: Some(0),
                nsat: Some(0),
            },
        }
    }

    fn script_size(&self) -> usize {
        todo!()
    }

    fn from_name_tree(
        name: &str,
        children: &[miniscript::expression::Tree<'_>],
    ) -> Result<Self, ()> {
        if children.len() == 7 && name == "all_apo" {
            if children.iter().any(|x| !x.args.is_empty()) {
                return Err(());
            }
            let outputs = deser_hex::<Vec<TxOut>>(children[0].name)?;
            let in_asset = deser_hex::<elements::confidential::Asset>(children[1].name)?;
            let in_value = deser_hex::<elements::confidential::Value>(children[2].name)?;
            let in_spk = deser_hex::<elements::Script>(children[3].name)?;
            let version = expression::parse_num(children[4].name).map_err(|_e| ())?;
            let locktime = expression::parse_num(children[5].name).map_err(|_e| ())?;
            let sequence = expression::parse_num(children[6].name).map_err(|_e| ())?;
            Ok(SighashAllAPO {
                outputs,
                in_asset,
                in_value,
                in_spk,
                version,
                locktime,
                sequence,
            })
        } else {
            // Correct error handling while parsing fromtree
            Err(())
        }
    }
}

impl ParseableExt for SighashAllAPO {
    fn from_token_iter(
        _tokens: &mut miniscript::miniscript::lex::TokenIter<'_>,
    ) -> Result<Self, ()> {
        // Parsing back from script is currently not implemented
        Err(())
    }

    fn evaluate<'intp, 'txin>(
        &'intp self,
        _stack: &mut miniscript::interpreter::Stack<'txin>,
        txenv: Option<&miniscript::TxEnv>,
    ) -> Result<bool, miniscript::interpreter::Error> {
        let env = txenv.ok_or(miniscript::interpreter::Error::IncorrectCovenantWitness)?;
        self.eval(env)
    }

    #[rustfmt::skip]
    fn push_to_builder(&self, builder: elements::script::Builder) -> elements::script::Builder {
        let mut builder = builder;
        for (i, out) in self.outputs.iter().enumerate() {
            let asset_eq = CovOps::<CovExtArgs>::AssetEq(
                AssetExpr::Const(out.asset.into()),
                AssetExpr::Output(i),
            );
            let value_eq = CovOps::<CovExtArgs>::ValueEq(
                ValueExpr::Const(out.value.into()),
                ValueExpr::Output(i),
            );
            let spk_eq = CovOps::<CovExtArgs>::SpkEq(
                SpkExpr::Const(Spk(out.script_pubkey.clone()).into()),
                SpkExpr::Output(i),
            );
            builder = asset_eq.push_to_builder(builder).push_opcode(opcodes::all::OP_VERIFY);
            builder = value_eq.push_to_builder(builder).push_opcode(opcodes::all::OP_VERIFY);
            builder = spk_eq.push_to_builder(builder).push_opcode(opcodes::all::OP_VERIFY);
        }

        use opcodes::all::*;
        builder = builder
            .push_opcode(OP_INSPECTVERSION).push_slice(&self.version.to_le_bytes()).push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_INSPECTLOCKTIME).push_slice(&self.locktime.to_le_bytes()).push_opcode(OP_EQUALVERIFY);
        builder = builder
            .push_opcode(OP_PUSHCURRENTINPUTINDEX)
            .push_opcode(OP_INSPECTINPUTSEQUENCE)
            .push_slice(&self.sequence.to_le_bytes())
            .push_opcode(OP_EQUALVERIFY);
        let in_asset_eq = CovOps::<CovExtArgs>::AssetEq(
            AssetExpr::Const(self.in_asset.into()),
            AssetExpr::CurrInputAsset,
        );
        let in_value_eq = CovOps::<CovExtArgs>::ValueEq(
            ValueExpr::Const(self.in_value.into()),
            ValueExpr::CurrInputValue,
        );
        let in_spk_eq = CovOps::<CovExtArgs>::SpkEq(
            SpkExpr::Const(Spk(self.in_spk.clone()).into()),
            SpkExpr::CurrInputSpk,
        );
        builder = in_asset_eq.push_to_builder(builder).push_opcode(opcodes::all::OP_VERIFY);
        builder = in_value_eq.push_to_builder(builder).push_opcode(opcodes::all::OP_VERIFY);
        in_spk_eq.push_to_builder(builder)
    }

    fn satisfy<Pk, S>(&self, sat: &S) -> miniscript::miniscript::satisfy::Satisfaction
    where
        Pk: miniscript::ToPublicKey,
        S: miniscript::Satisfier<Pk>,
    {
        let env = match (
            sat.lookup_tx(),
            sat.lookup_spent_utxos(),
            sat.lookup_curr_inp(),
        ) {
            (Some(tx), Some(spent_utxos), Some(idx)) => TxEnv::new(tx, spent_utxos, idx),
            _ => {
                return Satisfaction {
                    stack: Witness::Impossible,
                    has_sig: false,
                }
            }
        };
        let env = match env {
            Some(env) => env,
            None => {
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

    fn dissatisfy<Pk, S>(&self, _sat: &S) -> miniscript::miniscript::satisfy::Satisfaction
    where
        Pk: miniscript::ToPublicKey,
        S: miniscript::Satisfier<Pk>,
    {
        // This is incorrect!!!!, but done for testing purposes
        Satisfaction {
            stack: Witness::Impossible,
            has_sig: false,
        }
    }
}

fn deser_hex<T>(hex: &str) -> Result<T, ()>
where
    T: encode::Decodable,
{
    let bytes = Vec::<u8>::from_hex(hex).map_err(|_| ())?;
    deserialize(&bytes).map_err(|_| ())
}

fn main() {
    let tap_script = elements::script::Builder::default()
        .push_opcode(opcodes::all::OP_PUSHNUM_1)
        .push_slice(
            &Vec::<u8>::from_hex(
                "052ef9779ac3955ef438bbcde77411f31bf0e05fbe1b2b563fb5f0475c8a8e71",
            )
            .unwrap(),
        )
        .into_script();
    let conf_asset = Asset::from_commitment(
        &Vec::<u8>::from_hex("0bdabc318c05dfc1f911bd7e4608ad75c75b3cc25b2fe98fa3966597ab9a0a473f")
            .unwrap(),
    )
    .unwrap();
    let conf_value = Value::from_commitment(
        &Vec::<u8>::from_hex("08fb70255ab047990780c71fed7b874ca4ece6583ade26b37bf7d7f1c9284f4c84")
            .unwrap(),
    )
    .unwrap();
    let mut apo = SighashAllAPO {
        outputs: vec![elements::TxOut::default(); 2],
        in_asset: confidential::Asset::Explicit(
            AssetId::from_hex("5a62ef74ac90662be6a115855853c1a9d4407d955d28446c67c1568e532e61e9")
                .unwrap(),
        ),
        in_value: confidential::Value::Explicit(1000),
        in_spk: tap_script.clone(),
        version: 3,
        locktime: 1_000_000,
        sequence: 0xfffffffe,
    };
    apo.outputs[0].asset = conf_asset;
    apo.outputs[0].value = conf_value;
    apo.outputs[0].script_pubkey = tap_script.clone();
    apo.outputs[1].asset = conf_asset;
    apo.outputs[1].value = conf_value;
    apo.outputs[1].script_pubkey = tap_script.clone();

    let internal_pk = "02052ef9779ac3955ef438bbcde77411f31bf0e05fbe1b2b563fb5f0475c8a8e71";

    let desc = Tr::<bitcoin::PublicKey, SighashAllAPO>::from_str_insane(&format!(
        "eltr({},{})",
        internal_pk, &apo,
    ))
    .unwrap();
    println!(
        "desc addr: {}",
        desc.address(None, &AddressParams::ELEMENTS)
    );

    let tap_script = desc.iter_scripts().next().unwrap().1;
    println!("{}", tap_script.encode().to_hex());
    println!("{:?}", tap_script.encode());
}
