use std;
use rand;
use utils;
use base64;
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
        let cleartext = common::aes_128_cbc_decrypt(&buffer, &[0; 16], key)?;
        println!("{}", std::str::from_utf8(&cleartext)?);
    }

    {
        println!("Set 2 Challenge 11");
        let buffer = vec![b'X'; 40];
        let (cryptotext, mode) = encryption_oracle(&buffer)?;
        match detect_ecb_or_cbc(&cryptotext) {
            EcbOrCbc::ECB => println!("Was {:?}, found ECB!", mode),
            EcbOrCbc::CBC => println!("Was {:?}, found CBC!", mode),
        }
    }

    {
        println!("Set 2 Challenge 12");
        //block size discovery
        let mut block_size_discovery = vec![b'A', 1];
        let mut repeating_length = None;
        let previous_length = encryption_oracle2(&block_size_discovery)?.len();
        for _ in 0..100 {
            block_size_discovery.push(b'A');
            let out = encryption_oracle2(&block_size_discovery)?;
            if out.len() > previous_length {
                repeating_length = Some(out.len() - previous_length);
                break;
            }
        }

        match repeating_length {
            None => println!("Couldn't find blocksize!"),
            Some(length) => println!("Block length is {}", length),
        }

        //ecb detection
        let mut buffer = vec![b'X'; 40];
        buffer = encryption_oracle2(&buffer)?;
        match detect_ecb_or_cbc(&buffer) {
            EcbOrCbc::ECB => println!("Found ECB!"),
            EcbOrCbc::CBC => println!("Found CBC!"),
        }
        //TODO
    }

    Ok(())
}

fn encryption_oracle(cleartext: &[u8]) -> utils::types::Result<(Vec<u8>, EcbOrCbc)> {
    use rand::{Rng, distributions::IndependentSample};
    let mut key = vec![0u8; 16];
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
        Ok((
            common::aes_128_ecb_encrypt(&plaintext, &key)?,
            EcbOrCbc::ECB,
        ))
    } else {
        //CBC
        trace!("Chose CBC");
        let mut iv = vec![0u8; 16];
        rng.fill_bytes(&mut iv);
        Ok((
            common::aes_128_cbc_encrypt(&plaintext, &iv, &key)?,
            EcbOrCbc::CBC,
        ))
    }
}

fn encryption_oracle2(cleartext: &[u8]) -> utils::types::Result<Vec<u8>> {
    let base_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                       aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                       dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                       YnkK";
    let key = b"vnaskaclkAaskjc;"; //just mashed the keyboard
    let mut secret = base64::decode(base_secret)?;
    let mut plaintext = cleartext.to_vec();
    plaintext.append(&mut secret);
    Ok(common::aes_128_ecb_encrypt(&plaintext, key)?)
}

#[derive(Debug, PartialEq)]
enum EcbOrCbc {
    ECB,
    CBC,
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
        (0..10).for_each(|| {
            let buffer = vec![b'X'; 100];
            let (cryptotext, mode) = encryption_oracle(&buffer).unwrap();
            assert_eq!(detect_ecb_or_cbc(&cryptotext), mode);
        })
    }
}
