use utils;
use utils::types::ResultExt;
use base64;
use bit_vec;
use bytecount;
use hex;
use std;

pub fn gen_chi2(source: &str) -> utils::types::Result<()> {
    use std::io::Read;
    trace!("gen_chi2()");
    let mut file = std::fs::File::open(source).chain_err(|| "Failed to open source file")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let base_chars = "abcdefghijklmnopqrstuvwxyz '\"`-:.,?!";
    let mut pop_frequencies: std::collections::HashMap<u8, f64> = std::collections::HashMap::new();
    let total_len = buffer.len() as f64;
    debug!("total_len is {}", &total_len);
    for c in base_chars.chars() {
        debug!("considering {}", &c);
        let count = bytecount::count(&buffer, c as u8);
        let _ = pop_frequencies.insert(c as u8, count as f64 / total_len);
    }

    println!("let pop_frequencies: std::collections::HashMap<u8, f64> = [");
    for (key, val) in &pop_frequencies {
        println!("\t(b\'{}\', {}),", *key as char, val);
    }
    println!("].iter().cloned().collect();");

    Ok(())
}

pub fn run_set1() -> utils::types::Result<()> {
    trace!("run_set1()");
    {
        println!("Set 1 Challenge 1");
        let buffer = hex::decode(
            "49276d206b696c6c696e6720796f7\
             57220627261696e206c696b65206120\
             706f69736f6e6f7573206d757368726f6f6d",
        )?;
        let base64 = base64::encode(&buffer);
        println!("{}", base64);
    }

    {
        println!("Set 1 Challenge 2");
        let buffer1 = hex::decode("1c0111001f010100061a024b53535009181c")?;
        let buffer2 = hex::decode("686974207468652062756c6c277320657965")?;
        let xored: Vec<u8> = buffer1
            .iter()
            .zip(buffer2.iter())
            .map(|(x, y)| x ^ y)
            .collect();
        println!("{}", hex::encode(&xored));
    }

    {
        println!("Set 1 Challenge 3");
        let buffer = hex::decode(
            "1b37373331363f78151b7f2b783431333d7\
             8397828372d363c78373e783a393b3736",
        )?;
        let mut best_key = 0;
        let mut best_count_of_common_english = 0;
        let frequents = "etaoinshrdlu";
        for key in 0..std::u8::MAX {
            let xored = single_char_xor(&buffer, &key);
            let mut count_of_common_english = 0;
            for c in frequents.chars() {
                count_of_common_english += bytecount::count(&xored, c as u8);
            }
            if count_of_common_english > best_count_of_common_english {
                best_count_of_common_english = count_of_common_english;
                best_key = key;
            }
        }
        let plaintext: Vec<u8> = buffer.iter().map(|x| x ^ best_key).collect();
        println!("{}", std::str::from_utf8(&plaintext)?);
    }

    {
        println!("Set 1 Challenge 4");
        use std::io::BufRead;
        let file = std::fs::File::open("data/set1-challenge4.txt")
            .chain_err(|| "Failed to open data/set1-challenge4.txt")?;
        let file = std::io::BufReader::new(&file);
        let mut best_plaintext = Vec::new();
        let mut best_total_score = std::f64::MAX;
        for line in file.lines().filter_map(std::io::Result::ok) {
            let buffer = match hex::decode(line) {
                Err(_) => continue,
                Ok(b) => b,
            };
            let (key, score) = crack_single_xor(&buffer);
            let plaintext = single_char_xor(&buffer, &key);
            if score < best_total_score {
                best_total_score = score;
                best_plaintext = plaintext.clone();
            }
        }

        println!("{}", std::str::from_utf8(&best_plaintext)?);
    }

    {
        println!("Set 1 Challenge 5");
        let plaintext = b"Burning 'em, if you ain't quick and nimble \
            I go crazy when I hear a cymbal";
        let key = b"ICE";
        println!("{}", hex::encode(repeating_key_xor(plaintext, key)));
    }

    {
        println!("Set 1 Challenge 6");
        use std::io::Read;
        let mut file = std::fs::File::open("data/set1-challenge6.txt")
            .chain_err(|| "Failed to open source file")?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        //strip newlines
        buffer.retain(|x| *x != b'\n');
        buffer = base64::decode(&buffer)?;

        //find repeating xor keysize
        let mut average_hamming_by_keylen = Vec::new();
        for key_len in 2..41 {
            let mut total_distance = 0;
            let mut previous = None;
            //only consider the first 10 blocks
            let num_blocks = 10;
            for chunk in buffer.chunks(key_len).take(num_blocks) {
                if let Some(previous) = previous {
                    total_distance += hamming_distance(previous, chunk);
                };
                previous = Some(chunk);
            }
            let average_distance = total_distance as f64 / num_blocks as f64;
            let normalized_distance = average_distance as f64 / key_len as f64;
            trace!(
                "Keysize {} has normalized_distance of {}",
                key_len,
                normalized_distance
            );

            average_hamming_by_keylen.push((key_len, normalized_distance));
        }
        average_hamming_by_keylen.sort_by(|&(_, a), &(_, b)| a.partial_cmp(&b).unwrap());

        //debug:
        debug!("Most likely key lengths are:");
        for &(len, score) in average_hamming_by_keylen.iter().take(3) {
            debug!("Keysize {} has normalized_distance of {}", len, score);
        }

        //transpose into key_len vectors
        let key_len = average_hamming_by_keylen[0].0;
        debug!("Trying key len {}", key_len);
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
            cracked_key.push(crack_single_xor(slice).0);
        }
        println!("Cracked key is {}", std::str::from_utf8(&cracked_key)?);

        //now we have cracked_key
        println!(
            "{}",
            std::str::from_utf8(&repeating_key_xor(&buffer, &cracked_key))?
        );
    }

    {
        use openssl::symm::{Cipher, Crypter, Mode};
        use std::io::Read;

        println!("Set 1 Challenge 7");

        let key = b"YELLOW SUBMARINE";
        let mut file = std::fs::File::open("data/set1-challenge7.txt")
            .chain_err(|| "Failed to open source file")?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        //strip newlines
        buffer.retain(|x| *x != b'\n');
        buffer = base64::decode(&buffer)?;

        // Create a cipher context for encryption.
        let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
        //do my own padding
        encrypter.pad(false);

        let block_size = Cipher::aes_128_ecb().block_size();
        let mut ciphertext = vec![0; buffer.len() + block_size];

        let mut count = encrypter.update(&buffer, &mut ciphertext).unwrap();
        count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);
        println!("{}", std::str::from_utf8(&ciphertext)?);
    }

    {
        use std::io::BufRead;

        println!("Set 1 Challenge 8");
        let file = std::fs::File::open("data/set1-challenge8.txt")
            .chain_err(|| "Failed to open data/set1-challenge8.txt")?;
        let file = std::io::BufReader::new(&file);
        let mut best_line = String::new();
        let mut best_score = std::usize::MAX;
        for line in file.lines().filter_map(std::io::Result::ok) {
            let buffer = match hex::decode(&line) {
                Err(_) => continue,
                Ok(b) => b,
            };
            //sort and dedup our chunks - repeated chunks will be stripped
            //by the dedup, so the shortest resultant vec is our winner!
            let mut chunks: Vec<&[u8]> = buffer.chunks(16).collect();
            chunks.sort();
            chunks.dedup();
            let score = chunks.len();
            if score < best_score {
                debug!("New best score!: {}", score);
                debug!("{}", &line);
                best_score = score;
                best_line = line.clone();
            }
        }

        println!("{}", &best_line);
    }

    Ok(())
}

fn single_char_xor(plaintext: &[u8], key: &u8) -> Vec<u8> {
    plaintext.iter().map(|x| x ^ key).collect()
}

fn repeating_key_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let key_len = key.len();
    plaintext
        .iter()
        .enumerate()
        .map(|(n, x)| x ^ key[n % key_len])
        .collect()
}

//#[allow(unreadable_literal)]
fn chi2_score_english(plaintext: &[u8]) -> f64 {
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

fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    let a = bit_vec::BitVec::from_bytes(a);
    let b = bit_vec::BitVec::from_bytes(b);
    a.iter()
        .zip(b.iter())
        .fold(0, |count, (x, y)| count + (x != y) as usize)
}

fn crack_single_xor(encrypted: &[u8]) -> (u8, f64) {
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
