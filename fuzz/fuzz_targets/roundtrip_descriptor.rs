extern crate elements_miniscript as miniscript;
extern crate regex;

use miniscript::Descriptor;
use regex::Regex;
use std::str::FromStr;

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

#[cfg(feature = "afl")]
extern crate afl;
#[cfg(feature = "afl")]
fn main() {
    afl::read_stdio_bytes(|data| {
        do_test(&data);
    });
}

#[cfg(feature = "honggfuzz")]
#[macro_use]
extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        do_test(b"elc:pk_h()");
    }
}
