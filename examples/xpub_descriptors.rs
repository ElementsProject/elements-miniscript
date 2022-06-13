// Miniscript
// Written in 2019 by
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

//! Example: Parsing a xpub and getting an address.

extern crate elements_miniscript as miniscript;

use std::str::FromStr;

use elements::Address;

use crate::miniscript::elements::secp256k1_zkp::{Secp256k1, Verification};
use crate::miniscript::{Descriptor, DescriptorPublicKey};

const XPUB_1: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
const XPUB_2: &str = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";

fn main() {
    // For deriving from descriptors, we need to provide a secp context.
    let secp = Secp256k1::verification_only();

    // P2WSH and single xpubs.
    let _ = p2wsh(&secp);

    // P2WSH-P2SH and ranged xpubs.
    let _ = p2sh_p2wsh(&secp);
}

/// Parses a P2WSH descriptor, returns the associated address.
fn p2wsh<C: Verification>(secp: &Secp256k1<C>) -> Address {
    // It does not matter what order the two xpubs go in, the same address will be generated.
    let s = format!("elwsh(sortedmulti(1,{},{}))", XPUB_1, XPUB_2);
    // let s = format!("wsh(sortedmulti(1,{},{}))", XPUB_2, XPUB_1);

    let address = Descriptor::<DescriptorPublicKey>::from_str(&s)
        .unwrap()
        .derived_descriptor(&secp, 0) // dummy index value if it not a wildcard
        .unwrap()
        .address(&elements::AddressParams::ELEMENTS)
        .unwrap();
    let expected = elements::Address::from_str(
        "ert1qpq2cfgz5lktxzr5zqv7nrzz46hsvq3492ump9pz8rzcl8wqtwqcs2yqnuv",
    )
    .unwrap();
    assert_eq!(address, expected);
    address
}

/// Parses a P2SH-P2WSH descriptor, returns the associated address.
fn p2sh_p2wsh<C: Verification>(secp: &Secp256k1<C>) -> Address {
    // It does not matter what order the two xpubs go in, the same address will be generated.
    let s = format!(
        "elsh(wsh(sortedmulti(1,{}/1/0/*,{}/0/0/*)))",
        XPUB_1, XPUB_2
    );
    // let s = format!("sh(wsh(sortedmulti(1,{}/1/0/*,{}/0/0/*)))", XPUB_2, XPUB_1);

    let address = Descriptor::<DescriptorPublicKey>::from_str(&s)
        .unwrap()
        .derived_descriptor(secp, 5)
        .unwrap()
        .address(&elements::AddressParams::ELEMENTS)
        .unwrap();
    let expected = elements::Address::from_str("XBkDY63XnRTz6BbwzJi3ifGhBwLTomEzkq").unwrap();
    assert_eq!(address, expected);
    address
}
