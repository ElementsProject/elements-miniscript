extern crate elements_miniscript as miniscript;

use std::str::FromStr;

use miniscript::{policy, Miniscript, Segwitv0};
use policy::Liftable;

type Script = Miniscript<String, Segwitv0>;
type Policy = policy::Concrete<String>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = Policy::from_str(&data_str) {
        // Compile
        if let Ok(desc) = pol.compile::<Segwitv0>() {
            // Lift
            assert_eq!(desc.lift().unwrap().sorted(), pol.lift().unwrap().sorted());
            // Try to roundtrip the output of the compiler
            let output = desc.to_string();
            if let Ok(desc) = Script::from_str(&output) {
                let rtt = desc.to_string();
                assert_eq!(output.to_lowercase(), rtt.to_lowercase());
            } else {
                panic!("compiler output something unparseable: {}", output)
            }
        }
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
