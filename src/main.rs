// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]

//standard includes
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate stderrlog;
#[macro_use]
extern crate clap;
extern crate base64;
extern crate bytecount;
extern crate hex;

mod cmdline;
mod logging;
mod types;
use types::*;

fn main() {
    let mut config = cmdline::parse_cmdline();
    config.module_path = Some(module_path!().into());
    logging::configure_logger(&config);

    if let Err(ref e) = run(&config) {
        use error_chain::ChainedError; // trait which holds `display_chain`
        error!("{}", e.display_chain());
        ::std::process::exit(1);
    }
}

// Most functions will return the `Result` type, imported from the
// `types` module. It is a typedef of the standard `Result` type
// for which the error type is always our own `Error`.
fn run(config: &Settings) -> Result<()> {
    trace!("run()");

    match config.subcommand {
        types::SubCommand::None => Ok(()),
        types::SubCommand::Set1 => run_set1(),
        types::SubCommand::GenChi2(ref source) => gen_chi2(source),
    }
}

fn gen_chi2(source: &str) -> types::Result<()> {
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

fn run_set1() -> types::Result<()> {
    trace!("run_challenges()");
    {
        println!("Set 1 Challenge 1");
        let buffer = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")?;
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
        let buffer =
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
        let mut best_key = 0;
        let mut best_count_of_common_english = 0;
        let frequents = "etaoinshrdlu";
        for key in 0..std::u8::MAX {
            let xored: Vec<u8> = buffer.iter().map(|x| x ^ key).collect();
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
            let buffer = hex::decode(line)?;
            let mut best_key = 0;
            let mut best_score = std::f64::MAX;
            for key in 0..std::u8::MAX {
                let plaintext: Vec<u8> = buffer.iter().map(|x| *x ^ key).collect();
                let score = chi2_score_english(&plaintext);

                if score < best_score {
                    best_score = score;
                    best_key = key;
                }
            }
            let plaintext: Vec<u8> = buffer.iter().map(|x| *x ^ best_key).collect();
            if best_score < best_total_score {
                best_total_score = best_score;
                best_plaintext = plaintext.clone();
            }
        }

        println!("{}", std::str::from_utf8(&best_plaintext)?);
    }

    {
        println!("Set 1 Challenge 5");
        let plaintext : Vec<u8> = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
        let key : Vec<u8> = b"ICE".to_vec();
        let key_len = key.len();
        let encrypted : Vec<u8>  = plaintext.iter().enumerate().map(|(n, x)| x ^ key[n % key_len]).collect();
        println!("{}", hex::encode(encrypted));
    }


    Ok(())
}

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
}
