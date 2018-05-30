use base64;
use byteorder::{LittleEndian, WriteBytesExt};
use common;
use rand;
use std;
use utils;
use utils::types::ResultExt;

pub fn run_set3() -> utils::types::Result<()> {
//--------------------------------------------------
//     set3_challenge17()?;
//     set3_challenge18()?;
//     set3_challenge19()?;
//     set3_challenge20()?;
//-------------------------------------------------- 
    set3_challenge21()?;
    Ok(())
}

fn set3_challenge21() -> utils::types::Result<()> {
    println!("Set 3 Challenge 21");
    let mut mt = common::mt19937_seed(0);
    for _ in 0..10 {
        println!("{}", common::mt19937_rand(&mut mt));
    }
    Ok(())
}

fn set3_challenge20() -> utils::types::Result<()> {
    println!("Set 3 Challenge 20");
    use std::io::BufRead;
    let k: [u8; 16] = rand::random();
    let file = std::fs::File::open("data/set3-challenge20.txt")
        .chain_err(|| "Failed to open data/set3-challenge20.txt")?;
    let file = std::io::BufReader::new(&file);
    let mut source: Vec<_> = file
        .lines()
        .flat_map(Result::ok)
        .flat_map(|x| base64::decode(&x))
    //--------------------------------------------------
    //         .flat_map(|x| base64::decode(&x)).map(|x| x[39]).collect();
    //     println!("{}", String::from_utf8_lossy(&source));
    //--------------------------------------------------
        .flat_map(|x| aes_ctr(&k, &[0; 8], &x)).collect();
    //.inspect(|x| println!("{}", String::from_utf8_lossy(x)))
    let min_length = source
        .iter()
        .fold(std::usize::MAX, |m, elem| std::cmp::min(m, elem.len()));
    source.iter_mut().for_each(|x| x.truncate(min_length));
    let buffer = source.concat();
    //now we can just break flattened as if it's a repeating-key-xor
    //transpose into key_len vectors
    trace!("min_length is {}", min_length);
    let key_len = min_length;
    let mut transposed = Vec::new();
    for _ in 0..key_len {
        transposed.push(Vec::new());
    }
    for chunk in buffer.chunks(key_len) {
        for (i, b) in chunk.iter().enumerate() {
            transposed[i].push(b.clone());
        }
    }

    let mut cracked_key = Vec::new();
    //now single-xor crack each transpose vector
    for slice in &transposed {
        cracked_key.push(common::crack_single_xor(slice).0);
    }

//--------------------------------------------------
//     //row 39 is an example of where I'm getting it wrong
//     let real39 = b"etag e?H   xt saTu a a t/in  e/d/e merao onsciit///i'iossieo";
//     println!("correct score is {}", common::chi2_score_english(real39));
//     println!("{}", String::from_utf8_lossy(&transposed[39]));
//     let x = common::crack_single_xor(&transposed[39]);
//     println!("{:#?}", &x);
//     println!(
//         "{}",
//         String::from_utf8_lossy(&common::repeating_key_xor(&transposed[39], &vec![x.0; 1]))
//     );
//-------------------------------------------------- 

    for line in &source {
        println!(
            "{}",
            String::from_utf8_lossy(&common::repeating_key_xor(line, &cracked_key))
        );
    }

    Ok(())
}

fn set3_challenge19() -> utils::types::Result<()> {
    println!("Set 3 Challenge 19");
    use std::io::BufRead;
    let k: [u8; 16] = rand::random();
    let file = std::fs::File::open("data/set3-challenge19.txt")
        .chain_err(|| "Failed to open data/set3-challenge19.txt")?;
    let file = std::io::BufReader::new(&file);
    let source: Vec<_> = file
        .lines()
        .flat_map(Result::ok)
        .flat_map(|x| base64::decode(&x))
        .flat_map(|x| aes_ctr(&k, &[0; 8], &x))
        .collect();
    println!("number of lines {}", source.len());

    let _key = common::xor(b"The", &source[0]);
    let _key = common::xor(b"I d", &source[0]);
    let _key = common::xor(b"Thi", &source[0]);
    let _key = common::xor(b"I'm ", &source[42]);
    let _key = common::xor(b"Think", &source[0]);
    let _key = common::xor(
        b"I'm aaaaaaaaa aaaaaaaa                         ",
        &source[0],
    );
    let _key = common::xor(
        b"I'm eeeeeeeaaaaaaaaa aaaaaaaa                 ",
        &source[0],
    );
    let _key = common::xor(b"Lyrics", &source[24]);
    let _key = common::xor(b"Thinkin", &source[42]);
    let _key = common::xor(b"So I stand", &source[44]);
    let _key = common::xor(b"Novocain ", &source[35]);
    let _key = common::xor(b"So I start ", &source[44]);
    let _key = common::xor(b"MC's decaying ", &source[16]);
    let _key = common::xor(b"Musical madness", &source[30]);
    let _key = common::xor(b"Battle's tempting ", &source[32]);
    let _key = common::xor(b"Flashbacks interfereing", &source[13]);
    let _key = common::xor(b"Hazardous to your health", &source[20]);
    let _key = common::xor(b"I bless the child, the earth", &source[19]);
    let _key = common::xor(b"But now I learned to earn 'cuz", &source[47]);
    let _key = common::xor(b"So I walk up the street whistlin", &source[49]);
    let _key = common::xor(b"'Cuz I don't like to dream about ", &source[52]);
    let _key = common::xor(b"I wake ya with hundreds of thousands", &source[34]);
    let _key = common::xor(b"Melodies-unmakable, pattern-unescapable ", &source[18]);
    let _key = common::xor(b"Thinkin' of a master plan / 'Cuz ain't n", &source[42]);
    let _key = common::xor(b"'Cause my girl is definitely mad / 'Cause", &source[55]);
    let _key = common::xor(b"You want to hear some sounds that not only ", &source[26]);
    let _key = common::xor(b"Cuz I came back to attack others in spite-", &source[1]);
    let _key = common::xor(
        b"Yo, I hear what you're saying / So let's just",
        &source[56],
    );
    let _key = common::xor(
        b"Worse than a nightmare, you don't have to sleep ",
        &source[12],
    );
    let key = common::xor(
        b"Music's the clue, when I come your warned / Apocalypse",
        &source[5],
    );
    //.... I can just keep trying till I get the answer out...

    for (count, s) in source.iter().enumerate() {
        println!(
            "{:3}: {}",
            count,
            String::from_utf8_lossy(&common::xor(&key, s))
        );
    }

    Ok(())
}

fn aes_ctr(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> utils::types::Result<Vec<u8>> {
    let mut ciphertext: Vec<u8> = Vec::with_capacity(plaintext.len());
    for (count, chunk) in (0u64..).zip(plaintext.chunks(16)) {
        let mut ctr = nonce.to_vec();
        ctr.write_u64::<LittleEndian>(count)?;
        let keystream = common::aes_128_ecb_encrypt(&ctr, key)?;
        let ciphertext_chunk = common::xor(&keystream, &chunk);
        ciphertext.extend(&ciphertext_chunk);
    }
    Ok(ciphertext)
}

fn set3_challenge18() -> utils::types::Result<()> {
    println!("Set 3 Challenge 18");
    let original_ciphertext: &[u8] =
        b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

    let ciphertext = base64::decode(original_ciphertext)?;
    let key = b"YELLOW SUBMARINE";

    let cleartext = aes_ctr(key, &[0u8; 8], &ciphertext)?;
    println!("{}", std::str::from_utf8(&cleartext)?);
    Ok(())
}

fn set3_challenge17() -> utils::types::Result<()> {
    println!("Set 3 Challenge 17");
    let iv: [u8; 16] = rand::random();
    let key: [u8; 16] = rand::random();
    //Like the last challenge, rely on corrupting the previous block
    //to cause an single-char xor in the current block to
    //find which character, Control, gives valid padding
    //at the end of the cryptotext. Once we know that we know that:
    //Decrypted(CipherChar) ^ Control = 0x01,
    //i.e Decrypted(CipherChar) = 0x01 ^ Control
    //Once we know that. We can make a new control to make the last
    //character 0x02, i.e
    //Control = Decrypted(CipherChar) ^ 0x02
    //And then solve for the second to last character

    let original_ciphertext = challenge17_oracle(&iv, &key)?;
    let blocksize = 16;
    //use a deque so I can prepend
    let mut plaintext = std::collections::VecDeque::new();
    debug!("original_ciphertext len is {}", original_ciphertext.len());

    //need to treat first block specially, using the IV for manipulation
    for i in 0..(original_ciphertext.len() - blocksize) {
        let index = original_ciphertext.len() - blocksize - 1 - i;
        let target_padding = (i % blocksize + 1) as u8;

        let mut mangled_ciphertext = original_ciphertext.clone();
        mangled_ciphertext.truncate(original_ciphertext.len() - (i / blocksize) * blocksize);
        //set up the rest of our block for our target padding
        for j in 0..(target_padding as usize - 1) {
            mangled_ciphertext[index + j + 1] =
                original_ciphertext[index + j + 1] ^ plaintext[j] ^ target_padding;
        }

        //count downwards, which leaves the control = 0 as our last option
        //if we count upwards, the first last block triggers a false positive
        let mut control = std::u8::MAX;
        loop {
            mangled_ciphertext[index] = original_ciphertext[index] ^ control;
            if decrypt_and_check_padding(&mangled_ciphertext, &iv, &key)? {
                trace!(
                    "found valid padding with control {} and char is {}",
                    control,
                    target_padding ^ control
                );
                break;
            }
            if control == 0 {
                bail!("didn't find any valid padding");
            }
            control -= 1;
        }
        plaintext.push_front(target_padding ^ control);
    }

    //need to treat first block specially, using the IV for manipulation
    for i in 0..blocksize {
        //index is now an index in the iv
        let index = blocksize - i - 1;
        let target_padding = (i % blocksize + 1) as u8;

        let mut mangled_ciphertext = original_ciphertext.clone();
        mangled_ciphertext.truncate(blocksize);

        let mut mangled_iv = iv.to_vec();
        //set up the rest of our block for our target padding
        for j in 0..(target_padding as usize - 1) {
            mangled_iv[index + j + 1] = iv[index + j + 1] ^ plaintext[j] ^ target_padding;
        }

        //count downwards, which leaves the control = 0 as our last option
        //if we count upwards, the first last block triggers a false positive
        let mut control = std::u8::MAX;
        loop {
            mangled_iv[index] = iv[index] ^ control;
            if decrypt_and_check_padding(&mangled_ciphertext, &mangled_iv, &key)? {
                trace!(
                    "found valid padding with control {} and char is {}",
                    control,
                    target_padding ^ control
                );
                break;
            }
            if control == 0 {
                bail!("didn't find any valid padding");
            }
            control -= 1;
        }
        plaintext.push_front(target_padding ^ control);
    }

    //convert the vecdeque to a vec
    let simple_plaintext: Vec<_> = plaintext.into();
    println!(
        "{}",
        std::str::from_utf8(&common::strip_pkcs7_padding(&simple_plaintext)?)?
    );

    Ok(())
}

fn challenge17_oracle(iv: &[u8], key: &[u8]) -> utils::types::Result<Vec<u8>> {
    let plaintexts: Vec<&[u8]> = vec![
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];
    let chosen_plaintext: &[u8] = plaintexts[rand::random::<usize>() % plaintexts.len()];
    let plaintext = base64::decode(chosen_plaintext)?;
    common::aes_128_cbc_encrypt(&plaintext, iv, key)
}

fn decrypt_and_check_padding(
    ciphertext: &[u8],
    iv: &[u8],
    key: &[u8],
) -> utils::types::Result<bool> {
    let mut iv = iv.to_vec();
    let mut cleartext = Vec::new();
    for chunk in ciphertext.chunks(16) {
        let mut block = common::aes_128_ecb_decrypt(chunk, key)?;
        block = common::xor(&iv, &block);
        iv = chunk.to_vec();
        cleartext.extend(block.iter());
    }
    match common::strip_pkcs7_padding(&cleartext) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod test {
    use super::*;
}
