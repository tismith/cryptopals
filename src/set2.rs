use std;
use rand;
use utils;
use base64;
//use utils::types::ResultExt;
use common;
use hex;

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
        if let None = repeating_length {
            bail!("Couldn't find blocksize");
        }
        let blocksize = repeating_length.unwrap();
        println!("Block length is {}", blocksize);

        //ecb detection
        let mut buffer = vec![b'X'; 40];
        buffer = encryption_oracle2(&buffer)?;
        match detect_ecb_or_cbc(&buffer) {
            EcbOrCbc::ECB => println!("Found ECB!"),
            EcbOrCbc::CBC => println!("Found CBC!"),
        }

        let mut secret = Vec::new();
        let plaintext_len = encryption_oracle2(b"")?.len();
        loop {
            let mut dictionary = std::collections::HashMap::new();
            let lots_of_as = vec![b'A'; blocksize];
            let mut block: Vec<u8> = secret.iter().rev()
                .chain(lots_of_as.iter()).take(blocksize - 1).cloned().collect();
            block.reverse();
            trace!("block is {:?}", block);
            for c in 0..std::u8::MAX {
                //build up dictionary
                let mut this_block = block.clone();
                this_block.push(c);
                trace!("this_block is {:?}", this_block);
                let mut output = encryption_oracle2(&this_block)?;
                output = output.iter().take(blocksize).cloned().collect();
                debug!("inserting {} -> {}", hex::encode(&output), c as char);
                dictionary.insert(output, c);
            }
            let input : Vec<u8> = lots_of_as.iter().take(blocksize - (secret.len() % blocksize) - 1).cloned().collect();
            let interested_block = secret.len() / blocksize;
            let output = encryption_oracle2(&input)?;
            let output_block = output.chunks(blocksize).nth(interested_block).unwrap();
            debug!("looking up {}", hex::encode(&output_block));
            let secret_char = dictionary.get(output_block);
            match secret_char {
                None => {
                    //bail when I can't find any more characters in the dictionary
                    break;
                }
                Some(secret_char) => {
                    secret.push(*secret_char);
                }
            }
            if secret.len() >= plaintext_len {
                break;
            }
        }
        println!("Secret is:\n{}", ::std::str::from_utf8(&secret)?);
        //lookup output in dictionary, and push into secret

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
