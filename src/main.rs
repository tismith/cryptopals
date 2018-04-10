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

    println!("Challenge 1");
    let buffer = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")?;
    let base64 = base64::encode(&buffer);
    println!("{}", base64);

    Ok(())
}

