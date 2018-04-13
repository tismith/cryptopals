use std;
use utils;
use utils::types::ResultExt;
use base64;
use bit_vec;
#[cfg(test)]
use hex;

pub fn read_base64_file(path: &str) -> utils::types::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .chain_err(|| format!("Failed to open {}", path))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).chain_err(|| "Failed to read file in memory")?;
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
        (b'a', 0.058387284011251504),
        (b'v', 0.007730499620484887),
        (b'w', 0.016764447619472846),
        (b'z', 0.000678662320846542),
        (b'j', 0.000674495096069414),
        (b'q', 0.0006834248634489739),
        (b'.', 0.009190218928130255),
        (b'f', 0.01576223006057359),
        (b'b', 0.009242904555669658),
        (b'u', 0.019084698843595125),
        (b'l', 0.02852167701031388),
        (b'-', 0.0005447158101531455),
        (b'p', 0.011613757794942775),
        (b'x', 0.0011046122248515426),
        (b'd', 0.03461177836317364),
        (b'`', 0.0),
        (b'g', 0.014890089446503251),
        (b'o', 0.05609322677144261),
        (b'y', 0.013385721301960083),
        (b'!', 0.001168608891071721),
        (b'h', 0.048529416142042835),
        (b'c', 0.017713086574094743),
        (b',', 0.011874209343513268),
        (b':', 0.00030212379634177194),
        (b'k', 0.005724278549210459),
        (b's', 0.04759893438109271),
        (b' ', 0.15389620633715825),
        (b'?', 0.0009331606911639952),
        (b'"', 0.0),
        (b'r', 0.0432718667678707),
        (b'e', 0.09266657736899288),
        (b'n', 0.05374826985757021),
        (b'm', 0.01737762497953595),
        (b'\'', 0.0),
        (b'i', 0.04891309848045125),
        (b't', 0.06536470658272685),
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
        score += ((observed - expected).powi(2)) / (expected + 0.00000000000001);
    }
    score
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
}
