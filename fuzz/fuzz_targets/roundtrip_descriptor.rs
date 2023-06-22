extern crate elements_miniscript as miniscript;
extern crate regex;

use std::str::FromStr;

use miniscript::Descriptor;

fn do_test(data: &[u8]) {
    // This is how we test in rust-miniscript. It is difficult to enforce wrapping logic in fuzzer
    // for alias like t: and_v(1), likely and unlikely.
    // Just directly check whether the inferred descriptor is the same.
    let s = String::from_utf8_lossy(data);
    if let Ok(desc) = Descriptor::<String>::from_str(&s) {
        let str2 = desc.to_string();
        let desc2 = Descriptor::<String>::from_str(&str2).unwrap();

        assert_eq!(desc.to_string(), desc2.to_string());
    }
}

fn main() {
    loop {
        honggfuzz::fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    use miniscript::elements::hex::FromHex;

    #[test]
    fn duplicate_crash() {
        let hex = Vec::<u8>::from_hex("00").unwrap();
        super::do_test(&hex);
    }
}
