use std;
use rand;
use utils;
//use utils::types::ResultExt;
use common;

pub fn run_set2() -> utils::types::Result<()> {
    {
        println!("Set 2 Challenge 9");
        //this doesn't print the padding..
        println!(
            "{}",
            std::str::from_utf8(&common::pkcs7_pad(b"YELLOW SUBMARINE", 20))?
        );
    }

    {
        println!("Set 2 Challenge 10");
        let key = b"YELLOW SUBMARINE";
        let buffer = common::read_base64_file("data/set2-challenge10.txt")?;
        let cleartext = common::aes_128_cbc_decrypt(&buffer, &[0;16], key)?;
        println!("{}", std::str::from_utf8(&cleartext)?);
    }

    {
        println!("Set 2 Challenge 11");
        let buffer = vec![b'X';40];
        let (cryptotext, mode) = encryption_oracle(&buffer)?;
        match detect_ecb_or_cbc(&cryptotext) {
            EcbOrCbc::ECB => println!("Was {:?}, found ECB!", mode),
            EcbOrCbc::CBC => println!("Was {:?}, found CBC!", mode),
        }
    }

    Ok(())
}

fn encryption_oracle(cleartext: &[u8]) -> utils::types::Result<(Vec<u8>, EcbOrCbc)> {
    use rand::{Rng, distributions::IndependentSample};
    let mut key = vec![0u8;16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut key);
    let num_prepend = rand::distributions::Range::new(5, 11).ind_sample(&mut rng);
    let num_append = rand::distributions::Range::new(5, 11).ind_sample(&mut rng);
    let mut plaintext = vec![0u8; num_prepend];
    rng.fill_bytes(&mut plaintext);
    plaintext.extend_from_slice(cleartext);
    let mut footer = vec![0u8; num_append];
    rng.fill_bytes(&mut footer);
    plaintext.append(&mut footer);

    if rng.gen::<bool>() {
        //ECB
        trace!("Chose ECB");
        Ok((common::aes_128_ecb_encrypt(&plaintext, &key)?, EcbOrCbc::ECB))
    } else {
        //CBC
        trace!("Chose CBC");
        let mut iv = vec![0u8;16];
        rng.fill_bytes(&mut iv);
        Ok((common::aes_128_cbc_encrypt(&plaintext, &iv, &key)?, EcbOrCbc::CBC))
    }
}

#[derive(Debug, PartialEq)]
enum EcbOrCbc {
    ECB,
    CBC
}

fn detect_ecb_or_cbc(cryptotext: &[u8]) -> EcbOrCbc {
    //sort and dedup our chunks - repeated chunks will be stripped
    //by the dedup, so the shortest resultant vec is our winner!
    let mut chunks: Vec<&[u8]> = cryptotext.chunks(16).collect();
    let origin_len = chunks.len();
    chunks.sort();
    chunks.dedup();
    if chunks.len() < origin_len {
        EcbOrCbc::ECB
    } else {
        EcbOrCbc::CBC
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_detect_ecb_or_cbc() {
        for _ in 0..10 {
            let buffer = vec![b'X';100];
            let (cryptotext, mode) = encryption_oracle(&buffer).unwrap();
            assert_eq!(detect_ecb_or_cbc(&cryptotext), mode);
        }
    }
}


