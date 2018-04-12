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
extern crate bit_vec;
extern crate bytecount;
extern crate hex;
extern crate openssl;

mod utils;
mod set1;
mod set2;

use error_chain::ChainedError; // trait which holds `display_chain`

fn main() {
    let mut config = utils::cmdline::parse_cmdline();
    config.module_path = Some(module_path!().into());
    utils::logging::configure_logger(&config);

    if let Err(ref e) = run(&config) {
        error!("{}", e.display_chain());
        ::std::process::exit(1);
    }
}

// Most functions will return the `Result` type, imported from the
// `types` module. It is a typedef of the standard `Result` type
// for which the error type is always our own `Error`.
fn run(config: &utils::types::Settings) -> utils::types::Result<()> {
    trace!("run()");

    match config.subcommand {
        utils::types::SubCommand::None => Ok(()),
        utils::types::SubCommand::Set1 => set1::run_set1(),
        utils::types::SubCommand::Set2 => set2::run_set2(),
        utils::types::SubCommand::GenChi2(ref source) => set1::gen_chi2(source),
    }
}
