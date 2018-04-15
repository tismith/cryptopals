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
        println!("\nSet 2 Challenge 12");
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
        if repeating_length.is_none() {
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
            let block = last_n_bytes_left_padded(&secret, blocksize - 1);
            trace!("block is {:?}", block);
            for c in 0..std::u8::MAX {
                //build up dictionary
                let mut this_block = block.clone();
                this_block.push(c);
                trace!("this_block is {:?}", this_block);
                let mut output = encryption_oracle2(&this_block)?;
                output = output.iter().take(blocksize).cloned().collect();
                trace!("inserting {} -> {}", hex::encode(&output), c as char);
                dictionary.insert(output, c);
            }
            //The interesting character is in the middle of the stream,
            //so we need to work out which block it is in (interested_block)
            //and then pad the input so that we can control where the
            //interest charater appears on a blocksize boundary (basically, it needs
            //to appear at the end of a block)
            let lots_of_as = vec![b'A'; blocksize];
            let input: Vec<u8> = lots_of_as
                .iter()
                .take(blocksize - (secret.len() % blocksize) - 1)
                .cloned()
                .collect();
            let interested_block = secret.len() / blocksize;
            let mut output = encryption_oracle2(&input)?;
            output = output
                .chunks(blocksize)
                .nth(interested_block)
                .unwrap()
                .to_vec();
            trace!("looking up {}", hex::encode(&output));
            match dictionary.get(&output) {
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

fn last_n_bytes_left_padded(buffer: &[u8], size: usize) -> Vec<u8> {
    let lots_of_as = vec![b'A'; size];
    //take the last blocksize - 1 chars from secret, left padded with As
    let mut block: Vec<u8> = buffer
        .iter()
        .rev()
        .chain(lots_of_as.iter())
        .take(size)
        .cloned()
        .collect();
    block.reverse();
    block
}

fn encryption_oracle(cleartext: &[u8]) -> utils::types::Result<(Vec<u8>, EcbOrCbc)> {
    use rand::{Rng, distributions::IndependentSample};
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rand::random();
    let range = rand::distributions::Range::new(5, 11);
    let num_prepend = range.ind_sample(&mut rng);
    let num_append = range.ind_sample(&mut rng);
    let mut plaintext = vec![0u8; num_prepend];
    rng.fill_bytes(&mut plaintext);
    plaintext.extend_from_slice(cleartext);
    let mut footer = vec![0u8; num_append];
    rng.fill_bytes(&mut footer);
    plaintext.append(&mut footer);

    if rand::random::<bool>() {
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
    let key = b"vnaSkaclkAaskjc;"; //just mashed the keyboard
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
