extern crate elements_miniscript as miniscript;
extern crate regex;
use std::str::FromStr;

use miniscript::policy;
use regex::Regex;

type Policy = policy::Concrete<String>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = Policy::from_str(&data_str) {
        let output = pol.to_string();
        //remove all instances of 1@
        let re = Regex::new("(\\D)1@").unwrap();
        let output = re.replace_all(&output, "$1");
        let data_str = re.replace_all(&data_str, "$1");
        assert_eq!(data_str.to_lowercase(), output.to_lowercase());
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
