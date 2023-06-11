extern crate elements_miniscript as miniscript;

use miniscript::bitcoin::PublicKey;
use miniscript::elements::script;
use miniscript::{Miniscript, NoExt, Segwitv0};

fn do_test(data: &[u8]) {
    // Try round-tripping as a script
    let script = script::Script::from(data.to_owned());

    if let Ok(pt) = Miniscript::<PublicKey, Segwitv0, NoExt>::parse(&script) {
        let output = pt.encode();
        assert_eq!(pt.script_size(), output.len());
        assert_eq!(output, script);
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
