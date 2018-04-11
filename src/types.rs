//reexport Timestamp, so other modules don't need to use stderrlog
pub use stderrlog::Timestamp;

// Create the Error, ErrorKind, ResultExt, and Result types
error_chain!{
    //add custom or mapped error types here
    foreign_links {
        FromHexError(::hex::FromHexError);
        StringConv(::std::str::Utf8Error);
        Io(::std::io::Error);
    }
}

#[derive(Debug)]
pub enum SubCommand {
    None,
    GenChi2(String),
    Set1,
}

#[derive(Debug)]
pub struct Settings {
    pub verbosity: usize,
    pub quiet: bool,
    pub timestamp: Timestamp,
    pub module_path: Option<String>,
    pub subcommand: SubCommand,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            verbosity: 0,
            quiet: false,
            timestamp: Timestamp::Off,
            module_path: None,
            subcommand: SubCommand::None,
        }
    }
}
