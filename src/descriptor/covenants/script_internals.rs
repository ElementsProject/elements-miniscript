// Miniscript
// Written in 2021 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     Sanket Kanjalkar <sanket1729@gmail.com>
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
//! Script Internals for Covenant Descriptor Support

use bitcoin;
use elements::{opcodes::all, script};
/// Additional operations required on script builder
/// for Covenant operations support
pub trait CovOperations: Sized {
    /// Assert that the size of top stack elem is `len`
    fn chk_size(self, len: usize) -> Self;
    /// Assert that the top item is a valid confidential Amount
    /// If it starts with 1, the len must be 9, otherwise the
    /// len must be 33
    fn chk_amt(self) -> Self;
    /// Assuming the 10 sighash components + 1 sig on the top of
    /// stack for segwit sighash as created by [init_stack]
    /// CAT all of them and check sig from stack
    fn verify_cov(self, key: &bitcoin::PublicKey) -> Self;

    /// Get the script code for the covenant script
    /// assuming the above construction of covenants
    /// which uses OP_CODESEP
    fn post_codesep_script(self) -> Self;
}

impl CovOperations for script::Builder {
    fn chk_size(self, len: usize) -> Self {
        self.push_opcode(all::OP_SIZE)
            .push_int(len as i64)
            .push_opcode(all::OP_EQUALVERIFY)
    }

    fn chk_amt(self) -> Self {
        let mut builder = self;

        // Copy the first byte onto the stack
        builder = builder.push_opcode(all::OP_DUP);
        builder = builder.push_int(1).push_opcode(all::OP_LEFT);
        // Check if first byte is equal to 1
        builder = builder.push_int(1).push_opcode(all::OP_EQUAL);
        // Assert that explicit size is 9
        builder = builder
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_SIZE)
            .push_int(9)
            .push_opcode(all::OP_EQUALVERIFY);
        // Else assert that commitment size is 33
        builder
            .push_opcode(all::OP_ELSE)
            .push_opcode(all::OP_SIZE)
            .push_int(33)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_ENDIF)
    }

    fn verify_cov(self, key: &bitcoin::PublicKey) -> Self {
        let mut builder = self;
        // The miniscript is of type B, which should have pushed 1
        // onto the stack if it satisfied correctly.(which it should)
        // because this is a top level check
        // Initially the stack contains the [ec_sig..sighash_items]
        // where sighash_items are items from segwit bip143 sighash for
        // elements arranged sequentially such that item 1 is at top,
        // item 10 is the last. The top of stack is miniscript execution result
        // denoted by B type
        // stk = [ecsig i10 i9 i8 i7 i6 i5 i4 i3b i3 i2 i1 B]
        // alt_stk = []
        builder = builder.push_verify();
        // stk = [ecsig i10 i9 i8 i7 i6 i5 i4 i3b i3 i2 i1]
        // alt_stk = []
        // pick signature. stk_size = 12
        // Why can we pick have a fixed pick of 11?
        // The covenant check enforces that the the next 12 elements
        // of the stack must be elements from the sighash.
        // We don't additionally need to check the depth because
        // cleanstack is a consensus rule in segwit.
        // Copy the ec_sig to the stack top
        builder = builder.push_int(11).push_opcode(all::OP_PICK);
        // convert sighash type into 1 byte(It is 4 byte in sighash calculation)
        // Since we copied the ecsig onto stack top, this will now be at pos 11
        builder = builder.push_int(11).push_opcode(all::OP_PICK);
        builder = builder.push_int(1).push_opcode(all::OP_LEFT);
        // create a bitcoinsig = [ecsig || sighashtype]cat the sig and hashtype
        builder = builder.push_opcode(all::OP_CAT);
        // Push the bitcoinsig to alt stack
        builder = builder.push_opcode(all::OP_TOALTSTACK);
        // alt_stk = [bitcoinsig]
        // stk = [ecsig i10 i9 i8 i7 i6 i5 i4 i3b i3 i2 i1]
        // Ignore fmt skip because it butchers these lines
        #[cfg_attr(feature="cargo-fmt", rustfmt_skip)]
        {
            // Do the size checks on all respective items in sighash calculation
            use elements::opcodes::all::{OP_CAT, OP_SWAP};
            builder = builder.chk_size(4).push_opcode(OP_SWAP); // item 1: ver
            builder = builder.chk_size(32).push_opcode(OP_CAT).push_opcode(OP_SWAP);//item 2: hashprevouts
            builder = builder.chk_size(32).push_opcode(OP_CAT).push_opcode(OP_SWAP);//item 3: hashsequence
            builder = builder.chk_size(32).push_opcode(OP_CAT).push_opcode(OP_SWAP);//item 3b: hashissuances
            builder = builder.chk_size(36).push_opcode(OP_CAT).push_opcode(OP_SWAP);//item 4: outpoint
            // Item 5: Script code is of constant size because we only consider everything after
            // codeseparator. This will be replaced with a push slice in a later commit
            builder = builder.chk_size(3).push_opcode(OP_CAT).push_opcode(OP_SWAP);//item 5: script code
            builder = builder.chk_amt().push_opcode(OP_CAT).push_opcode(OP_SWAP);       //item 6: check confAmt
            builder = builder.chk_size(4).push_opcode(OP_CAT).push_opcode(OP_SWAP); //item 7: sequence
            builder = builder.chk_size(32).push_opcode(OP_CAT).push_opcode(OP_SWAP);//item 8: hashoutputs
            builder = builder.chk_size(4).push_opcode(OP_CAT).push_opcode(OP_SWAP); //item 9: nlocktime
            builder = builder.chk_size(4).push_opcode(OP_CAT);                           //item 10: sighash type
        }
        // Now sighash is on the top of the stack
        // alt_stk = [bitcoinsig]
        // stk = [ecsig (i1||i2||i3||i3b||i4||i5||i6||i7||i8||i9||i10)]
        // Note that item order is reversed
        // || denotes concat operation
        builder = builder.push_opcode(all::OP_SHA256);
        builder = builder.push_key(key).push_opcode(all::OP_DUP);
        builder = builder
            .push_opcode(all::OP_FROMALTSTACK)
            .push_opcode(all::OP_SWAP);
        // stk = [ecsig sha2_msg pk btcsig pk]
        // alt_stk = []

        // Code separator. Everything before this(and including this codesep)
        // won't be used in script code calculation
        builder = builder.push_opcode(all::OP_CODESEPARATOR);
        builder.post_codesep_script()
    }

    /// The second parameter decides whether the script code should
    /// a hashlock verifying the entire script
    fn post_codesep_script(self) -> Self {
        let builder = self;
        // Now sighash is on the top of the stack
        // stk = [ecsig sha2_msg pk btcsig pk]
        builder
            .push_opcode(all::OP_CHECKSIGVERIFY)
            .push_opcode(all::OP_CHECKSIGFROMSTACK)
    }
}
