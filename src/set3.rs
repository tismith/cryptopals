use std;
use rand;
use utils;
use base64;
use common;

pub fn run_set3() -> utils::types::Result<()> {
    set3_challenge17()?;
    Ok(())
}

fn set3_challenge17() -> utils::types::Result<()> {
    println!("Set 3 Challenge 17");
    let iv :[u8; 16] = rand::random();
    let key :[u8; 16] = rand::random();
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
    let mut reversed_plaintext = Vec::new();

    let target_padding = b'\x01';
    let index = original_ciphertext.len() - blocksize;
    let mut mangled_ciphertext = original_ciphertext.clone();
    let clean_cipherchar = original_ciphertext[index];
    let mut control = b'\x00';
    for c in 0..std::u8::MAX {
        control = c;
        mangled_ciphertext[index] = clean_cipherchar ^ control;
        if decrypt_and_check_padding(&mangled_ciphertext, &iv, &key)? {
            debug!("found valid padding and char is {}", target_padding ^ control);
            break;
        }
    }
    reversed_plaintext.push(target_padding ^ control);

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

fn decrypt_and_check_padding(ciphertext: &[u8], iv: &[u8], key: &[u8]) -> utils::types::Result<bool> {
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
