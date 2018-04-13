use utils;
use utils::types::ResultExt;
use common;
use base64;
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
        let xored = common::xor(&buffer1, &buffer2);
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
            let xored = common::single_char_xor(&buffer, &key);
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
            let (key, score) = common::crack_single_xor(&buffer);
            let plaintext = common::single_char_xor(&buffer, &key);
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
        println!("{}", hex::encode(common::repeating_key_xor(plaintext, key)));
    }

    {
        println!("Set 1 Challenge 6");
        let buffer = common::read_base64_file("data/set1-challenge6.txt")?;

        //find repeating xor keysize
        let mut average_hamming_by_keylen = Vec::new();
        for key_len in 2..41 {
            let mut total_distance = 0;
            let mut previous = None;
            //only consider the first 10 blocks
            let num_blocks = 10;
            for chunk in buffer.chunks(key_len).take(num_blocks) {
                if let Some(previous) = previous {
                    total_distance += common::hamming_distance(previous, chunk);
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
            cracked_key.push(common::crack_single_xor(slice).0);
        }
        println!("Cracked key is {}", std::str::from_utf8(&cracked_key)?);

        //now we have cracked_key
        println!(
            "{}",
            std::str::from_utf8(&common::repeating_key_xor(&buffer, &cracked_key))?
        );
    }

    {
        println!("Set 1 Challenge 7");

        let key = b"YELLOW SUBMARINE";
        let buffer = common::read_base64_file("data/set1-challenge7.txt")?;
        let cleartext = common::aes_128_ecb_decrypt(&buffer, key)?;
        println!("{}", std::str::from_utf8(&cleartext)?);
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
