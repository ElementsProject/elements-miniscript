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
    fn verify_cov(self, key: &bitcoin::PublicKey) -> Self {
        let mut builder = self;
        // The miniscript is of type B, which should have pushed 1
        // onto the stack if it satisfied correctly.(which it should)
        // because this is a top level check
        builder = builder.push_verify();
        // pick signature. stk_size = 12
        // Why can we pick have a fixed pick of 11.
        // The covenant check enforces that the the next 12 elements
        // of the stack must be elements from the sighash.
        // We don't additionally need to check the depth because
        // cleanstack is a consensus rule in segwit.
        builder = builder.push_int(11).push_opcode(all::OP_PICK);
        // convert sighash type into 1 byte
        // OP_OVER copies the second to top element onto
        // the top of the stack
        builder = builder.push_opcode(all::OP_OVER);
        builder = builder.push_int(1).push_opcode(all::OP_LEFT);
        // create a bitcoinsig = cat the sig and hashtype
        builder = builder.push_opcode(all::OP_CAT);

        // check the sig and push pk to alt stack
        builder = builder
            .push_key(key)
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_TOALTSTACK);

        // Code separtor. Everything before this(and including this codesep)
        // won't be used in script code calculation
        builder = builder.push_opcode(all::OP_CODESEPARATOR);
        builder.post_codesep_script()
    }

    /// The second parameter decides whether the script code should
    /// a hashlock verifying the entire script
    fn post_codesep_script(self) -> Self {
        let mut builder = self;
        // let script_slice = builder.clone().into_script().into_bytes();
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
