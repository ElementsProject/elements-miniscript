// Miniscript
// Written in 2018 by
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

//! Covenant Descriptor support
//!
//! Traits and implementations for Covenant descriptors
//! A cov() descriptor puts a context items required for
//! sighash onto the top of the stack in the required order
//!
//! ** WORKS only for Segwit sighash
//! A new transaction digest algorithm is defined, but only applicable to sigops in version 0 witness program:
//! Text from BIP 143:
//!  Double SHA256 of the serialization of:
//! 1. nVersion of the transaction (4-byte little endian)
//! 2. hashPrevouts (32-byte hash)
//! 3. hashSequence (32-byte hash)
//! 3b. ELEMENTS EXTRA hashIssuances (32-byte hash)
//! 4. outpoint (32-byte hash + 4-byte little endian)
//! 5. scriptCode of the input (serialized as scripts inside CTxOuts)
//! 6. value of the output spent by this input (8-byte little endian)
//! 7. nSequence of the input (4-byte little endian)
//! 8. hashOutputs (32-byte hash)
//! 9. nLocktime of the transaction (4-byte little endian)
//! 10. sighash type of the signature (4-byte little endian)
//!
//! The miniscript fragments lookups all the relevant fragment
//! from the stack using using OP_PICK(specifying the relative)
//! position using OP_DEPTH.
//! After all the miniscript fragments are evaluated, we concat
//! all the items using OP_CAT to obtain a Sighash on which we
//! which we verify using CHECKSIGFROMSTACK
use std::{fmt, str::FromStr};

use bitcoin;
use elements::hashes::{sha256d, Hash};
use elements::opcodes::all;
use elements::secp256k1;
use elements::sighash::SigHashCache;
use elements::{
    self,
    encode::{serialize, Encodable},
    SigHash,
};
use elements::{confidential, script};
use elements::{OutPoint, Script, SigHashType, Transaction, TxOut};

use {
    expression::{self, FromTree},
    miniscript::{
        decode,
        lex::{lex, Token, TokenIter},
    },
    util::varint_len,
    ForEach, ForEachKey, Miniscript, ScriptContext, Segwitv0, TranslatePk,
};

use super::{
    checksum::{desc_checksum, verify_checksum},
    ElementsTrait, ELMTS_STR,
};
use {MiniscriptKey, ToPublicKey};

use {DescriptorTrait, Error, Satisfier};

pub trait CovOperations: Sized {
    /// pick an element indexed from the bottom of
    /// the stack. This cannot check whether the idx is within
    /// stack limits.
    /// Copies the element at index idx to the top of the stack
    fn pick(self, idx: u32) -> Self;

    /// Assuming the 10 sighash components + 1 sig on the top of
    /// stack for segwit sighash as created by [init_stack]
    /// CAT all of them and check sig from stack
    fn verify_cov(self, key: &bitcoin::PublicKey) -> Self;

    /// Put version on top of stack
    fn pick_version(self) -> Self {
        self.pick(9)
    }
}

/// Create an initial stack with Sighash components
/// The 10 items are from BIP 143 with an item 0
/// containing the signature over the sha256d of
/// concatanation of the following 10 items.
/// Note the sig here does not contain the sighash
/// type flag
#[allow(dead_code)]
pub fn init_stack(
    tx: &Transaction,
    idx: u32,
    value: u64,
    script_code: Script,
    hash_ty: SigHashType,
    sig: Vec<u8>,
) -> Vec<Vec<u8>> {
    let mut sighash_cache = SigHashCache::new(tx);
    vec![
        sig,                                                // item 0
        serialize(&hash_ty.as_u32()),                       // item 10
        serialize(&tx.lock_time),                           // item 9
        serialize(&sighash_cache.hash_outputs()),           // item 8
        serialize(&tx.input[idx as usize].sequence),        // item 7
        serialize(&value),                                  // item 6
        serialize(&script_code),                            // item 5
        serialize(&tx.input[idx as usize].previous_output), // item 4
        serialize(&sighash_cache.hash_sequence()),          // item 3
        serialize(&sighash_cache.hash_prevouts()),          // item 2
        serialize(&tx.version),                             // item 1
    ]
}

impl CovOperations for script::Builder {
    fn pick(self, idx: u32) -> Self {
        self.push_int((idx + 1) as i64) // +1 for depth increase
            .push_opcode(all::OP_DEPTH)
            .push_opcode(all::OP_SUB)
            .push_opcode(all::OP_PICK)
    }

    fn verify_cov(self, key: &bitcoin::PublicKey) -> Self {
        let mut builder = self;
        // The miniscript is of type B, which should have pushed 1
        // onto the stack if it satisfied correctly.(which it should)
        // because this is a top level check
        builder = builder.push_opcode(all::OP_VERIFY);
        // pick signature. stk_size = 12
        builder = builder.push_int(11).push_opcode(all::OP_PICK);
        // convert sighash type into 1 byte
        builder = builder.push_opcode(all::OP_OVER);
        builder = builder.push_int(1).push_opcode(all::OP_LEFT);
        // create a bitcoinsig = cat the sig and hashtype
        builder = builder.push_opcode(all::OP_CAT);

        // check the sig and push pk to alt stack
        builder = builder
            .push_key(key)
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_TOALTSTACK);
        builder = builder.push_opcode(all::OP_CHECKSIGVERIFY);
        for _ in 0..10 {
            builder = builder.push_opcode(all::OP_CAT);
        }

        // Now sighash is on the top of the stack
        builder = builder.push_opcode(all::OP_SHA256);
        builder = builder.push_opcode(all::OP_FROMALTSTACK);
        builder.push_opcode(all::OP_CHECKSIGFROMSTACK)
    }
}

/// The covenant descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CovenantDescriptor<Pk: MiniscriptKey> {
    /// the pk constraining the Covenant
    /// The key over which we want CHECKSIGFROMSTACK
    pub pk: Pk,
    /// the underlying Miniscript
    /// Must be under segwit context
    pub ms: Miniscript<Pk, Segwitv0>,
}

impl<Pk: MiniscriptKey> CovenantDescriptor<Pk> {
    /// Encode
    pub fn encode(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        let builder = self.ms.node.encode(script::Builder::new());
        builder.verify_cov(&self.pk.to_public_key()).into_script()
    }

    /// Create a satisfaction for the Covenant Descriptor
    pub fn satisfy<S: Satisfier<Pk>>(&self, s: S) -> Result<Vec<Vec<u8>>, Error>
    where
        Pk: ToPublicKey,
    {
        let mut wit = {
            let n_version = s.lookup_nversion().ok_or(Error::CouldNotSatisfy)?;
            let hash_prevouts = s.lookup_hashprevouts().ok_or(Error::CouldNotSatisfy)?;
            let hash_sequence = s.lookup_hashsequence().ok_or(Error::CouldNotSatisfy)?;
            let hash_issuances = s.lookup_hashissuances().ok_or(Error::CouldNotSatisfy)?;
            let outpoint = s.lookup_outpoint().ok_or(Error::CouldNotSatisfy)?;
            let script_code = s.lookup_scriptcode().ok_or(Error::CouldNotSatisfy)?;
            let value = s.lookup_value().ok_or(Error::CouldNotSatisfy)?;
            let n_sequence = s.lookup_nsequence().ok_or(Error::CouldNotSatisfy)?;
            let hash_outputs = s.lookup_hashoutputs().ok_or(Error::CouldNotSatisfy)?;
            let n_locktime = s.lookup_nlocktime().ok_or(Error::CouldNotSatisfy)?;
            let sighash_ty = s.lookup_sighashu32().ok_or(Error::CouldNotSatisfy)?;

            let (sig, hash_ty) = s.lookup_sig(&self.pk).ok_or(Error::CouldNotSatisfy)?;
            // Hashtype must be the same
            if sighash_ty != hash_ty.as_u32() {
                return Err(Error::CouldNotSatisfy);
            }

            vec![
                Vec::from(sig.serialize_der().as_ref()), // The covenant sig
                serialize(&n_version),                   // item 1
                serialize(&hash_prevouts),               // item 2
                serialize(&hash_sequence),               // item 3
                serialize(&hash_issuances),              // ELEMENTS EXTRA: item 3b
                serialize(&outpoint),                    // item 4
                serialize(script_code),                  // item 5
                serialize(&value),                       // item 6
                serialize(&n_sequence),                  // item 7
                serialize(&hash_outputs),                // item 8
                serialize(&n_locktime),                  // item 9
                serialize(&sighash_ty),                  // item 10
            ]
        };

        let ms_wit = self.ms.satisfy(s)?;
        wit.extend(ms_wit);
        Ok(wit)
    }
}

/// A satisfier for Covenant descriptors
/// that can do transaction introspection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CovSatisfier<'tx> {
    // Common fields in Segwit and Taphash
    /// The transaction being spent
    tx: &'tx Transaction,
    /// The script code required for
    /// The input index being spent
    idx: u32,
    /// The sighash type
    hash_type: SigHashType,

    // Segwitv0
    /// The script code required for segwit sighash
    script_code: Option<&'tx Script>,
    /// The value of the output being spent
    value: Option<confidential::Value>,

    // Taproot
    /// The utxos used in transaction
    /// This construction should suffice for Taproot
    /// related covenant spends too.
    spent_utxos: Option<&'tx [TxOut]>,
}

impl<'tx> CovSatisfier<'tx> {
    /// Create a new CovSatisfier for taproot spends
    /// **Panics**
    /// 1) if number of spent_utxos is not equal to
    /// number of transaction inputs.
    /// 2) if idx is out of bounds
    pub fn new_taproot(
        tx: &'tx Transaction,
        spent_utxos: &'tx [TxOut],
        idx: u32,
        hash_type: SigHashType,
    ) -> Self {
        assert!(spent_utxos.len() == tx.input.len());
        assert!((idx as usize) < spent_utxos.len());
        Self {
            tx,
            idx,
            hash_type,
            script_code: None,
            value: None,
            spent_utxos: Some(spent_utxos),
        }
    }

    /// Create  a new Covsatisfier for v0 spends
    /// Panics if idx is out of bounds
    pub fn new_segwitv0(
        tx: &'tx Transaction,
        idx: u32,
        value: confidential::Value,
        script_code: &'tx Script,
        hash_type: SigHashType,
    ) -> Self {
        assert!((idx as usize) < tx.input.len());
        Self {
            tx,
            idx,
            hash_type,
            script_code: Some(script_code),
            value: Some(value),
            spent_utxos: None,
        }
    }

    /// Easy way to get sighash since we already have
    /// all the required information.
    /// Note that this does not do any caching, so it
    /// will be slightly inefficient as compared to
    /// using sighash
    pub fn segwit_sighash(&self) -> Result<SigHash, Error> {
        let mut cache = SigHashCache::new(self.tx);
        // TODO: error types
        let script_code = self
            .script_code
            .ok_or(Error::Unexpected(String::from("Missing")))?;
        let value = self
            .value
            .ok_or(Error::Unexpected(String::from("Missing")))?;
        Ok(cache.segwitv0_sighash(self.idx as usize, script_code, value, self.hash_type))
    }
}

impl<'tx, Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for CovSatisfier<'tx> {
    fn lookup_nversion(&self) -> Option<u32> {
        Some(self.tx.version)
    }

    fn lookup_hashprevouts(&self) -> Option<sha256d::Hash> {
        let mut enc = sha256d::Hash::engine();
        for txin in &self.tx.input {
            txin.previous_output.consensus_encode(&mut enc).unwrap();
        }
        Some(sha256d::Hash::from_engine(enc))
    }

    fn lookup_hashsequence(&self) -> Option<sha256d::Hash> {
        let mut enc = sha256d::Hash::engine();
        for txin in &self.tx.input {
            txin.sequence.consensus_encode(&mut enc).unwrap();
        }
        Some(sha256d::Hash::from_engine(enc))
    }

    fn lookup_hashissuances(&self) -> Option<sha256d::Hash> {
        let mut enc = sha256d::Hash::engine();
        for txin in &self.tx.input {
            if txin.has_issuance() {
                txin.asset_issuance.consensus_encode(&mut enc).unwrap();
            } else {
                0u8.consensus_encode(&mut enc).unwrap();
            }
        }
        Some(sha256d::Hash::from_engine(enc))
    }

    fn lookup_outpoint(&self) -> Option<OutPoint> {
        Some(self.tx.input[self.idx as usize].previous_output)
    }

    fn lookup_scriptcode(&self) -> Option<&Script> {
        self.script_code
    }

    fn lookup_value(&self) -> Option<confidential::Value> {
        self.value
    }

    fn lookup_nsequence(&self) -> Option<u32> {
        Some(self.tx.input[self.idx as usize].sequence)
    }

    fn lookup_hashoutputs(&self) -> Option<sha256d::Hash> {
        let mut enc = sha256d::Hash::engine();
        for txout in &self.tx.output {
            txout.consensus_encode(&mut enc).unwrap();
        }
        Some(sha256d::Hash::from_engine(enc))
    }

    fn lookup_nlocktime(&self) -> Option<u32> {
        Some(self.tx.lock_time)
    }

    fn lookup_sighashu32(&self) -> Option<u32> {
        Some(self.hash_type.as_u32())
    }
}

impl CovenantDescriptor<bitcoin::PublicKey> {
    /// Check if the given script is a covenant descriptor
    fn check_cov_script(_iter: &mut TokenIter) -> Result<bitcoin::PublicKey, Error> {
        //let iter2 = iter.clone().take(10);
        Ok(bitcoin::PublicKey::from_slice(&[0x02]).unwrap())
    }

    /// Parse a descriptor from script. While parsing
    /// other descriptors, we only parse the inner miniscript
    /// with ScriptContext. But Covenant descriptors only
    /// applicable under Wsh context to avoid implementation
    /// complexity.
    // All code for covenants can thus be separated in a module
    pub fn parse(script: &script::Script) -> Result<Self, Error> {
        let tokens = lex(script)?;
        let mut iter = TokenIter::new(tokens);

        if let Some(Token::CheckSigFromStack) = iter.peek() {
            let pk = CovenantDescriptor::<bitcoin::PublicKey>::check_cov_script(&mut iter)?;
            let ms = decode::parse(&mut iter)?;
            Ok(Self { pk: pk, ms: ms })
        } else {
            unreachable!("Not a Covenant descriptor")
        }
    }
}

impl<Pk: MiniscriptKey> FromTree for CovenantDescriptor<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "elwshcov" && top.args.len() == 2 {
            let pk = expression::terminal(&top.args[0], |pk| Pk::from_str(pk))?;
            let top = &top.args[1];
            let sub = Miniscript::from_tree(&top)?;
            Segwitv0::top_level_checks(&sub)?;
            Ok(CovenantDescriptor { pk: pk, ms: sub })
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing elwshcov descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
}
impl<Pk: MiniscriptKey> fmt::Debug for CovenantDescriptor<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}wshcov({},{})", ELMTS_STR, self.pk, self.ms)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for CovenantDescriptor<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = format!("{}wshcov({},{})", ELMTS_STR, self.pk, self.ms);
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl<Pk: MiniscriptKey> FromStr for CovenantDescriptor<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        CovenantDescriptor::<Pk>::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> ElementsTrait<Pk> for CovenantDescriptor<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn blind_addr(
        &self,
        blinder: Option<secp256k1::PublicKey>,
        params: &'static elements::AddressParams,
    ) -> Result<elements::Address, Error>
    where
        Pk: ToPublicKey,
    {
        Ok(elements::Address::p2wsh(
            &self.explicit_script(),
            blinder,
            params,
        ))
    }
}

impl<Pk: MiniscriptKey> DescriptorTrait<Pk> for CovenantDescriptor<Pk>
where
    Pk: FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn sanity_check(&self) -> Result<(), Error> {
        self.ms.sanity_check()?;
        // 1) Check the 201 opcode count here
        // 2) Check that the sighash does not exceed 520 bytes
        // 3) Check that the script size does not exceed 3600 bytes
        // It's hard to break 3) without 2), but with OP_CODESEP
        // it is possible
        Ok(())
    }

    fn address(&self, params: &'static elements::AddressParams) -> Result<elements::Address, Error>
    where
        Pk: ToPublicKey,
    {
        Ok(elements::Address::p2wsh(
            &self.explicit_script(),
            None,
            params,
        ))
    }

    fn script_pubkey(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.explicit_script().to_v0_p2wsh()
    }

    fn unsigned_script_sig(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        Script::new()
    }

    fn explicit_script(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.encode()
    }

    fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let mut witness = self.satisfy(satisfier)?;
        witness.push(self.explicit_script().into_bytes());
        let script_sig = Script::new();
        Ok((witness, script_sig))
    }

    fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        let script_size = self.ms.script_size() + 100;
        let max_sat_elems = self.ms.max_satisfaction_witness_elements()? + 11;
        let max_sat_size = self.ms.max_satisfaction_size()? + 250;

        Ok(4 +  // scriptSig length byte
            varint_len(script_size) +
            script_size +
            varint_len(max_sat_elems) +
            max_sat_size)
    }

    fn script_code(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        // Change this if we use codesep
        self.explicit_script()
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for CovenantDescriptor<Pk> {
    fn for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, mut pred: F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        pred(ForEach::Key(&self.pk)) && self.ms.for_any_key(pred)
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for CovenantDescriptor<P> {
    type Output = CovenantDescriptor<Q>;

    fn translate_pk<Fpk, Fpkh, E>(
        &self,
        mut translatefpk: Fpk,
        mut translatefpkh: Fpkh,
    ) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        Ok(CovenantDescriptor {
            pk: translatefpk(&self.pk)?,
            ms: self
                .ms
                .translate_pk(&mut translatefpk, &mut translatefpkh)?,
        })
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {

    use {descriptor::DescriptorType, Descriptor, ElementsSig};

    use super::*;
    use elements::{self, confidential};
    use elements::{AssetId, AssetIssuance, OutPoint, TxIn, TxInWitness, Txid};
    use std::str::FromStr;

    const BTC_ASSET: [u8; 32] = [
        0x23, 0x0f, 0x4f, 0x5d, 0x4b, 0x7c, 0x6f, 0xa8, 0x45, 0x80, 0x6e, 0xe4, 0xf6, 0x77, 0x13,
        0x45, 0x9e, 0x1b, 0x69, 0xe8, 0xe6, 0x0f, 0xce, 0xe2, 0xe4, 0x94, 0x0c, 0x7a, 0x0d, 0x5d,
        0xe1, 0xb2,
    ];

    #[test]
    fn parse_cov() {
        Descriptor::<String>::from_str("elwshcov(A,pk(B))").unwrap();
        Descriptor::<String>::from_str("elwshcov(A,or_i(pk(B),pk(C)))").expect("Failed");
        Descriptor::<String>::from_str("elwshcov(A,multi(2,B,C,D))").unwrap();
        Descriptor::<String>::from_str("elwshcov(A,and_v(v:pk(B),pk(C)))").unwrap();
    }

    // Some deterministic keys for ease of testing
    fn setup_keys(n: usize) -> (Vec<bitcoin::PublicKey>, Vec<secp256k1::SecretKey>) {
        let secp_sign = secp256k1::Secp256k1::signing_only();

        let mut sks = vec![];
        let mut pks = vec![];
        let mut sk = [0; 32];
        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;
            let sk = secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key");
            let pk = bitcoin::PublicKey {
                key: secp256k1::PublicKey::from_secret_key(&secp_sign, &sk),
                compressed: true,
            };
            sks.push(sk);
            pks.push(pk);
        }
        (pks, sks)
    }

    #[test]
    fn fund_output() {
        let (pks, _sks) = setup_keys(5);
        let desc =
            Descriptor::<bitcoin::PublicKey>::from_str(&format!("elwshcov({},1)", pks[0])).unwrap();

        assert_eq!(desc.desc_type(), DescriptorType::Cov);
        assert_eq!(
            desc.address(&elements::AddressParams::ELEMENTS)
                .unwrap()
                .to_string(),
            "ert1qjk0kxztzvsmuygsxvyzcgaexk8rt04ttgu4sgsxhcal20agdr4vq4z5a7w"
        );

        println!(
            "{}",
            desc.address(&elements::AddressParams::ELEMENTS)
                .unwrap()
                .to_string()
        );
    }

    #[test]
    fn spend_tx() {
        let (pks, sks) = setup_keys(5);
        let desc =
            Descriptor::<bitcoin::PublicKey>::from_str(&format!("elwshcov({},1)", pks[0])).unwrap();

        assert_eq!(desc.desc_type(), DescriptorType::Cov);
        assert_eq!(
            desc.address(&elements::AddressParams::ELEMENTS)
                .unwrap()
                .to_string(),
            "ert1qjk0kxztzvsmuygsxvyzcgaexk8rt04ttgu4sgsxhcal20agdr4vq4z5a7w"
        );
        // Now create a transaction spending this.
        let mut spend_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![txin_from_txid_vout(
                "23d86b629f607ff35cb2c88f5a90aee80f6fbe6473ccb515ce491e117f46eb6e",
                1,
            )],
            output: vec![],
        };

        spend_tx.output.push(TxOut::default());
        spend_tx.output[0].script_pubkey = desc.script_pubkey(); // send back to self
        spend_tx.output[0].value = confidential::Value::Explicit(99_000);
        spend_tx.output[0].asset =
            confidential::Asset::Explicit(AssetId::from_slice(&BTC_ASSET).unwrap());

        // same second output
        let second_out = spend_tx.output[0].clone();
        spend_tx.output.push(second_out);

        // Add a fee output
        spend_tx.output.push(TxOut::default());
        spend_tx.output[2].asset =
            confidential::Asset::Explicit(AssetId::from_slice(&BTC_ASSET).unwrap());
        spend_tx.output[2].value = confidential::Value::Explicit(2_000);

        // Try to satisfy the covenant part
        let script_code = desc.explicit_script();
        let cov_sat = CovSatisfier::new_segwitv0(
            &spend_tx,
            0,
            confidential::Value::Explicit(200_000),
            &script_code,
            SigHashType::All,
        );

        // Create a signature to sign the input

        let sighash_u256 = cov_sat.segwit_sighash().unwrap();
        let secp = secp256k1::Secp256k1::signing_only();
        let sig = secp.sign(
            &secp256k1::Message::from_slice(&sighash_u256[..]).unwrap(),
            &sks[0],
        );
        let sig = (sig, SigHashType::All);

        // For satisfying the Pk part of the covenant
        struct SimpleSat {
            sig: ElementsSig,
            pk: bitcoin::PublicKey,
        };

        impl Satisfier<bitcoin::PublicKey> for SimpleSat {
            fn lookup_sig(&self, pk: &bitcoin::PublicKey) -> Option<ElementsSig> {
                if *pk == self.pk {
                    Some(self.sig)
                } else {
                    None
                }
            }
        }

        let pk_sat = SimpleSat { sig, pk: pks[0] };

        // A pair of satisfiers is also a satisfier
        let (wit, _) = desc.get_satisfaction((cov_sat, pk_sat)).unwrap();
        // Commented Demo test code:
        // 1) Send 0.002 btc to above address
        // 2) Create a tx by filling up txid
        // 3) Send the tx
        // spend_tx.input[0].witness.script_witness = wit;
        // use elements::encode::serialize_hex;
        // println!("{}", serialize_hex(&spend_tx));
        // println!("{}", serialize_hex(&desc.explicit_script()));
    }

    fn txin_from_txid_vout(txid: &str, vout: u32) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(txid).unwrap(),
                vout: vout,
            },
            sequence: 0xfffffffe,
            is_pegin: false,
            has_issuance: false,
            // perhaps make this an option in elements upstream?
            asset_issuance: AssetIssuance {
                asset_blinding_nonce: [0; 32],
                asset_entropy: [0; 32],
                amount: confidential::Value::Null,
                inflation_keys: confidential::Value::Null,
            },
            script_sig: Script::new(),
            witness: TxInWitness {
                amount_rangeproof: vec![],
                inflation_keys_rangeproof: vec![],
                script_witness: vec![],
                pegin_witness: vec![],
            },
        }
    }
}
