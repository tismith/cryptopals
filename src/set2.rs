use std;
use utils;
//use utils::types::ResultExt;
use common;

pub fn run_set2() -> utils::types::Result<()> {
    {
        println!("Set 2 Challenge 9");
        //this doesn't print the padding..
        println!("{}", std::str::from_utf8(&pkcs7_pad(b"YELLOW SUBMARINE", 20))?);
    }

    {
        println!("Set 2 Challenge 10");
        let _buffer = common::read_base64_file("data/set2-challenge10.txt")?;
    }

    Ok(())
}

fn pkcs7_pad(plaintext: &[u8], key_len: usize) -> Vec<u8> {
    let mut padded = Vec::<u8>::from(plaintext);
    let len = padded.len();
    let padding = key_len - (len % key_len);
    for _ in 0..padding {
        padded.push(padding.clone() as u8);
    }

    padded
}


#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_pkcs7_pad() {
        let plaintext = b"YELLOW SUBMARINE";
        let known_good = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        assert_eq!(pkcs7_pad(plaintext, 20), known_good);
    }
}
