use std;
use utils;
use utils::types::ResultExt;
use base64;
use bit_vec;
#[cfg(test)]
use hex;

pub fn strip_pkcs7_padding(plaintext: &[u8]) -> utils::types::Result<Vec<u8>> {
    let blocksize = 16;
    if plaintext.len() % blocksize != 0 {
        bail!("Invalid padding - not padded");
    }
    let last_chunk = plaintext.chunks(blocksize).last().unwrap();
    let padding_char = *last_chunk.iter().last().unwrap();
    trace!("padding_char is {}", padding_char);
    if padding_char > blocksize as u8 || padding_char == 0 {
        //this isn't a pkcs#7 padding character
        bail!("Invalid padding - invalid padding character");
    }
    let mut expected_padding = padding_char;
    for ch in last_chunk.iter().rev() {
        if *ch == padding_char {
            expected_padding -= 1;
        } else {
            bail!("Invalid padding - incorrect padding");
        }
        if expected_padding == 0 {
            return Ok(plaintext[..(plaintext.len() - padding_char as usize)].to_vec());
        }
    }
    bail!("Invalid padding");
}

pub fn read_base64_file(path: &str) -> utils::types::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).chain_err(|| format!("Failed to open {}", path))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .chain_err(|| "Failed to read file in memory")?;
    //strip newlines
    buffer.retain(|x| *x != b'\n');
    base64::decode(&buffer).chain_err(|| "Failed to base64 encode")
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn single_char_xor(plaintext: &[u8], key: &u8) -> Vec<u8> {
    plaintext.iter().map(|x| x ^ key).collect()
}

pub fn repeating_key_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let key_len = key.len();
    plaintext
        .iter()
        .enumerate()
        .map(|(n, x)| x ^ key[n % key_len])
        .collect()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    let a = bit_vec::BitVec::from_bytes(a);
    let b = bit_vec::BitVec::from_bytes(b);
    a.iter()
        .zip(b.iter())
        .fold(0, |count, (x, y)| count + (x != y) as usize)
}

pub fn crack_single_xor(encrypted: &[u8]) -> (u8, f64) {
    let mut best_key = 0;
    let mut best_score = std::f64::MAX;
    for key in 0..std::u8::MAX {
        let plaintext = single_char_xor(encrypted, &key);
        let score = chi2_score_english(&plaintext);

        if score < best_score {
            best_score = score;
            best_key = key;
        }
    }
    (best_key, best_score)
}

//#[allow(unreadable_literal)]
pub fn chi2_score_english(plaintext: &[u8]) -> f64 {
    //this came from the gen-chi2 subcommand
    let pop_frequencies: std::collections::HashMap<u8, f64> = [
        (b'a', 0.058_387_284_011_251_504),
        (b'v', 0.007_730_499_620_484_887),
        (b'w', 0.016_764_447_619_472_846),
        (b'z', 0.000_678_662_320_846_542),
        (b'j', 0.000_674_495_096_069_414),
        (b'q', 0.000_683_424_863_448_973),
        (b'.', 0.009_190_218_928_130_255),
        (b'f', 0.015_762_230_060_573_59),
        (b'b', 0.009_242_904_555_669_658),
        (b'u', 0.019_084_698_843_595_125),
        (b'l', 0.028_521_677_010_313_88),
        (b'-', 0.000_544_715_810_153_145_5),
        (b'p', 0.011_613_757_794_942_775),
        (b'x', 0.001_104_612_224_851_542_6),
        (b'd', 0.034_611_778_363_173_64),
        (b'`', 0.0),
        (b'g', 0.014_890_089_446_503_251),
        (b'o', 0.056_093_226_771_442_61),
        (b'y', 0.013_385_721_301_960_083),
        (b'!', 0.001_168_608_891_071_721),
        (b'h', 0.048_529_416_142_042_835),
        (b'c', 0.017_713_086_574_094_743),
        (b',', 0.011_874_209_343_513_268),
        (b':', 0.000_302_123_796_341_771_94),
        (b'k', 0.005_724_278_549_210_459),
        (b's', 0.047_598_934_381_092_71),
        (b' ', 0.153_896_206_337_158_25),
        (b'?', 0.000_933_160_691_163_995_2),
        (b'"', 0.0),
        (b'r', 0.043_271_866_767_870_7),
        (b'e', 0.092_666_577_368_992_88),
        (b'n', 0.053_748_269_857_570_21),
        (b'm', 0.017_377_624_979_535_95),
        (b'\'', 0.0),
        (b'i', 0.048_913_098_480_451_25),
        (b't', 0.065_364_706_582_726_85),
    ].iter()
        .cloned()
        .collect();
    let mut score = 0.0;
    let mut sample_size = 0.0;
    let mut plaintext_counts = std::collections::HashMap::new();
    for c in plaintext {
        if c.is_ascii() {
            let c = c.to_ascii_lowercase();
            let current_count = *(plaintext_counts.get(&c).unwrap_or(&0.0));
            plaintext_counts.insert(c, current_count + 1.0);
        } else {
            //not ascii, just bail early
            return std::f64::MAX;
        }
        sample_size += 1.0;
    }
    for (key, observed) in &plaintext_counts {
        let population_freq = *(pop_frequencies.get(key).unwrap_or(&0.0));
        let expected = population_freq * sample_size;
        //add something so we never divide by 0
        score += ((observed - expected).powi(2)) / (expected + 0.000_000_000_000_01);
    }
    score
}

pub fn pkcs7_pad(plaintext: &[u8], key_len: usize) -> Vec<u8> {
    trace!("pkcs7_pad()");
    let mut padded = Vec::<u8>::from(plaintext);
    let len = padded.len();
    let padding = key_len - (len % key_len);
    debug!("padding is {}", padding);
    for _ in 0..padding {
        padded.push(padding as u8);
    }

    padded
}

pub fn aes_128_ecb_decrypt(cryptotext: &[u8], key: &[u8]) -> utils::types::Result<Vec<u8>> {
    use openssl::symm::{Cipher, Crypter, Mode};
    // Create a cipher context for encryption.
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    //do my own padding
    decrypter.pad(false);

    let block_size = Cipher::aes_128_ecb().block_size();
    let mut cleartext = vec![0; cryptotext.len() + block_size];

    let mut count = decrypter.update(cryptotext, &mut cleartext)?;
    count += decrypter.finalize(&mut cleartext[count..])?;
    cleartext.truncate(count);
    Ok(cleartext)
}

pub fn aes_128_ecb_encrypt(cleartext: &[u8], key: &[u8]) -> utils::types::Result<Vec<u8>> {
    use openssl::symm::{Cipher, Crypter, Mode};
    // Create a cipher context for encryption.
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None)?;
    //do my own padding
    encrypter.pad(false);

    let block_size = Cipher::aes_128_ecb().block_size();
    let padded = pkcs7_pad(cleartext, block_size);
    let mut cryptotext = vec![0; padded.len() + block_size];

    let mut count = encrypter.update(&padded, &mut cryptotext)?;
    count += encrypter.finalize(&mut cryptotext[count..])?;
    cryptotext.truncate(count);
    Ok(cryptotext)
}

pub fn aes_128_cbc_decrypt(
    ciphertext: &[u8],
    iv: &[u8],
    key: &[u8],
) -> utils::types::Result<Vec<u8>> {
    let mut iv = iv.to_owned();
    let mut cleartext = Vec::new();
    for chunk in ciphertext.chunks(16) {
        let mut block = aes_128_ecb_decrypt(chunk, key)?;
        block = xor(&iv, &block);
        iv = chunk.to_vec();
        cleartext.extend_from_slice(&block);
    }
    Ok(strip_pkcs7_padding(&cleartext)?)
}

pub fn aes_128_cbc_encrypt(
    plaintext: &[u8],
    iv: &[u8],
    key: &[u8],
) -> utils::types::Result<Vec<u8>> {
    use openssl::symm::{Cipher, Crypter, Mode};
    let mut iv = iv.to_owned();
    let mut ciphertext = Vec::new();
    let plaintext = pkcs7_pad(plaintext, key.len());
    for chunk in plaintext.chunks(16) {
        let mut block = xor(&iv, chunk);

        let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None)?;
        //do my own padding
        encrypter.pad(false);

        let block_size = Cipher::aes_128_ecb().block_size();
        let mut cryptotext = vec![0; plaintext.len() + block_size];

        let mut count = encrypter.update(&block, &mut cryptotext)?;
        count += encrypter.finalize(&mut cryptotext[count..])?;
        cryptotext.truncate(count);

        iv = cryptotext.clone();
        ciphertext.extend_from_slice(&cryptotext);
    }
    Ok(ciphertext)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chi2_english() {
        let score1 = chi2_score_english(b"this is an english sentence");
        let score2 = chi2_score_english(b"q0394ui[ear vadadasf");
        let score3 = chi2_score_english(b"This is an English sentence");
        let score4 = chi2_score_english(b"this^^english sentence");
        assert!(score1 < score2);
        //floating point comparision using e of 0.0001
        assert!(score1 > (score3 - 0.0001) && score1 < (score3 + 0.0001));
        assert!(score1 < score4);
    }

    #[test]
    fn test_repeating_key_xor() {
        let plaintext = b"Burning 'em, if you ain't quick and nimble\n\
            I go crazy when I hear a cymbal";
        let key = b"ICE";
        let encrypted_source = b"0b3637272a2b2e63622c2e69692a23693a2a\
            3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2\
            c652a3124333a653e2b2027630c692b20283165286326302e27282f"
            .to_vec();
        let encrypted = hex::decode(encrypted_source).unwrap();
        assert_eq!(repeating_key_xor(plaintext, key), encrypted);
    }

    #[test]
    fn test_hamming_distance() {
        let one = b"this is a test";
        let two = b"wokka wokka!!!";
        assert_eq!(37, hamming_distance(one, two));
    }

    #[test]
    fn test_pkcs7_pad() {
        let plaintext = b"YELLOW SUBMARINE";
        let known_good = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        assert_eq!(pkcs7_pad(plaintext, 20), known_good);
    }

    #[test]
    fn test_strip_pkcs7_padding() {
        let test1 = b"0123456789\x06\x06\x06\x06\x06\x06";
        let stripped = strip_pkcs7_padding(test1).unwrap();
        assert_eq!(stripped, b"0123456789");
    }

    #[test]
    #[should_panic]
    fn test_strip_pkcs7_padding_unpadded() {
        let test1 = b"0123456789";
        let _ = strip_pkcs7_padding(test1).unwrap();
    }

    #[test]
    fn test_strip_pkcs7_padding_aligned() {
        let test1 = b"0123456789123456\x10\x10\x10\x10\x10\
                    \x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
        let stripped = strip_pkcs7_padding(test1).unwrap();
        assert_eq!(stripped, b"0123456789123456");
    }

    #[test]
    #[should_panic]
    fn test_strip_pkcs7_padding_error_incrementing() {
        let test1 = b"0123456789\x01\x02\x03\x04\x05\x06";
        let _ = strip_pkcs7_padding(test1).unwrap();
    }

    #[test]
    fn test_strip_pkcs7_padding_error_incorrect() {
        let test1 = b"0123456789\x01\x01\x01\x01\x01\x01";
        let stripped = strip_pkcs7_padding(test1).unwrap();
        assert_eq!(b"0123456789\x01\x01\x01\x01\x01".to_vec(), stripped);
    }

    #[test]
    fn test_aes_cbc() {
        use rand;
        let plaintext = b"I\'ve seen fire and I\'ve seen rain";
        let iv: [u8; 16] = rand::random();
        let key: [u8; 16] = rand::random();
        let ciphertext = aes_128_cbc_encrypt(plaintext, &iv, &key).unwrap();
        let output = aes_128_cbc_decrypt(&ciphertext, &iv, &key).unwrap();
        assert_eq!(std::str::from_utf8(&output), std::str::from_utf8(plaintext));
    }
}
