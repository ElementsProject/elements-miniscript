extern crate elements_miniscript as miniscript;

use std::str::FromStr;

use miniscript::DescriptorPublicKey;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(dpk) = DescriptorPublicKey::from_str(&data_str) {
        let _output = dpk.to_string();
        // assert_eq!(data_str.to_lowercase(), output.to_lowercase());
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
