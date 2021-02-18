use elements::Script;
use elements::{self, script};
pub(crate) fn varint_len(n: usize) -> usize {
    elements::VarInt(n as u64).len()
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

/// Get the count of non-push opcodes
// Export to upstream
#[cfg(test)]
pub(crate) fn count_non_push_opcodes(script: &Script) -> Result<usize, elements::script::Error> {
    let mut count = 0;
    for ins in script.instructions().into_iter() {
        if let script::Instruction::Op(..) = ins? {
            count += 1;
        }
    }
    Ok(count)
}
