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
fn run(_config: &Settings) -> Result<()> {
    trace!("Entry to top level run()");
    //DO STUFF

    println!("Set 1 Challenge 1");
    let buffer = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")?;
    let base64 = base64::encode(&buffer);
    println!("{}", base64);

    println!("Set 1 Challenge 2");
    let buffer1 = hex::decode("1c0111001f010100061a024b53535009181c")?;
    let buffer2 = hex::decode("686974207468652062756c6c277320657965")?;
    let xored: Vec<u8> = buffer1
        .iter()
        .zip(buffer2.iter())
        .map(|(x, y)| x ^ y)
        .collect();
    println!("{}", hex::encode(&xored));

    println!("Set 1 Challenge 3");
    let buffer = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
    let mut best_key = 0;
    let mut best_count_of_common_english = 0;
    let frequents = "etaoinshrdlu";
    for key in 0..255 {
        let xored : Vec<u8> = buffer.iter().map(|x| x ^ key).collect();
        let mut count_of_common_english = 0;
        for c in frequents.chars() {
            count_of_common_english += xored.iter().filter(|&n| *n == c as u8).count();
        }
        if count_of_common_english > best_count_of_common_english {
            best_count_of_common_english = count_of_common_english;
            best_key = key;
        }
    }
    let plaintext : Vec<u8> = buffer.iter().map(|x| x ^ best_key).collect();
    println!("{}", std::str::from_utf8(&plaintext)?);

    Ok(())
}
