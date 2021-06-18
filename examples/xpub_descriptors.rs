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

//! Example: Parsing a xpub and getting address

extern crate bitcoin;
extern crate elements;
extern crate elements_miniscript as miniscript;

use miniscript::elements::secp256k1_zkp;
use miniscript::{Descriptor, DescriptorPublicKey, DescriptorTrait, TranslatePk2};

use std::str::FromStr;
fn main() {
    // For deriving from descriptors, we need to provide a secp context
    let secp_ctx = secp256k1_zkp::Secp256k1::verification_only();
    // P2WSH and single xpubs
    let addr_one = Descriptor::<DescriptorPublicKey>::from_str(
            "elwsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH))",
        )
        .unwrap()
        .translate_pk2(|xpk| xpk.derive_public_key(&secp_ctx))
        .unwrap()
        .address(&elements::AddressParams::ELEMENTS).unwrap();

    let addr_two = Descriptor::<DescriptorPublicKey>::from_str(
            "elwsh(sortedmulti(1,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB))",
        )
        .unwrap()
        .translate_pk2(|xpk| xpk.derive_public_key(&secp_ctx))
        .unwrap()
        .address(&elements::AddressParams::ELEMENTS).unwrap();
    let expected = elements::Address::from_str(
        "ert1qpq2cfgz5lktxzr5zqv7nrzz46hsvq3492ump9pz8rzcl8wqtwqcs2yqnuv",
    )
    .unwrap();
    assert_eq!(addr_one, expected);
    assert_eq!(addr_two, expected);

    // P2WSH-P2SH and ranged xpubs
    let addr_one = Descriptor::<DescriptorPublicKey>::from_str(
            "elsh(wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*)))",
        )
        .unwrap()
        .derive(5)
        .translate_pk2(|xpk| xpk.derive_public_key(&secp_ctx))
        .unwrap()
        .address(&elements::AddressParams::ELEMENTS).unwrap();

    let addr_two = Descriptor::<DescriptorPublicKey>::from_str(
            "elsh(wsh(sortedmulti(1,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*)))",
        )
        .unwrap()
        .derive(5)
        .translate_pk2(|xpk| xpk.derive_public_key(&secp_ctx))
        .unwrap()
        .address( &elements::AddressParams::ELEMENTS).unwrap();
    let expected = elements::Address::from_str("XBkDY63XnRTz6BbwzJi3ifGhBwLTomEzkq").unwrap();
    assert_eq!(addr_one, expected);
    assert_eq!(addr_two, expected);
}
