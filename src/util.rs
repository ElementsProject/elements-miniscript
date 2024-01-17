// SPDX-License-Identifier: CC0-1.0
use bitcoin::hashes::Hash;
use elements::{self, opcodes, script, PubkeyHash, Script};

use crate::miniscript::context;
use crate::{ScriptContext, ToPublicKey};

pub(crate) fn varint_len(n: usize) -> usize {
    elements::VarInt(n as u64).size()
}

// Helper function to calculate witness size
pub(crate) fn witness_size(wit: &[Vec<u8>]) -> usize {
    wit.iter().map(Vec::len).sum::<usize>() + varint_len(wit.len())
}

pub(crate) fn witness_to_scriptsig(witness: &[Vec<u8>]) -> Script {
    let mut b = script::Builder::new();
    for wit in witness {
        if let Ok(n) = script::read_scriptint(wit) {
            b = b.push_int(n);
        } else {
            b = b.push_slice(wit);
        }
    }
    b.into_script()
}

macro_rules! define_slice_to_le {
    ($name: ident, $type: ty) => {
        #[inline]
        pub(crate) fn $name(slice: &[u8]) -> $type {
            assert_eq!(slice.len(), ::std::mem::size_of::<$type>());
            let mut res = 0;
            for i in 0..::std::mem::size_of::<$type>() {
                res |= (slice[i] as $type) << i * 8;
            }
            res
        }
    };
}

define_slice_to_le!(slice_to_u32_le, u32);

/// Helper to encode an integer in script format
/// Copied from rust-bitcoin
pub(crate) fn build_scriptint(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }

    let neg = n < 0;

    let mut abs = if neg { -n } else { n } as usize;
    let mut v = vec![];
    while abs > 0xFF {
        v.push((abs & 0xFF) as u8);
        abs >>= 8;
    }
    // If the number's value causes the sign bit to be set, we need an extra
    // byte to get the correct value and correct sign bit
    if abs & 0x80 != 0 {
        v.push(abs as u8);
        v.push(if neg { 0x80u8 } else { 0u8 });
    }
    // Otherwise we just set the sign bit ourselves
    else {
        abs |= if neg { 0x80 } else { 0 };
        v.push(abs as u8);
    }
    v
}
/// Get the count of non-push opcodes
// Export to upstream
#[cfg(test)]
pub(crate) fn count_non_push_opcodes(script: &Script) -> Result<usize, elements::script::Error> {
    let mut count = 0;
    for ins in script.instructions() {
        if let script::Instruction::Op(..) = ins? {
            count += 1;
        }
    }
    Ok(count)
}
// trait for pushing key that depend on context
pub(crate) trait MsKeyBuilder {
    /// Serialize the key as bytes based on script context. Used when encoding miniscript into bitcoin script
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext;

    /// Serialize the key hash as bytes based on script context. Used when encoding miniscript into bitcoin script
    fn push_ms_key_hash<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext;
}

impl MsKeyBuilder for script::Builder {
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_key(&key.to_public_key()),
            context::SigType::Schnorr => self.push_slice(&key.to_x_only_pubkey().serialize()),
        }
    }

    fn push_ms_key_hash<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_slice(key.to_public_key().pubkey_hash().as_ref()),
            context::SigType::Schnorr => {
                self.push_slice(PubkeyHash::hash(&key.to_x_only_pubkey().serialize()).as_ref())
            }
        }
    }
}

/// Checks whether a script pubkey is a P2TR output.
#[inline]
pub fn is_v1_p2tr(script: &Script) -> bool {
    script.len() == 34
        && script[0] == opcodes::all::OP_PUSHNUM_1.into_u8()
        && script[1] == opcodes::all::OP_PUSHBYTES_32.into_u8()
}
