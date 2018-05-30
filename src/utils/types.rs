//reexport Timestamp, so other modules don't need to use stderrlog
pub use stderrlog::Timestamp;

// Create the Error, ErrorKind, ResultExt, and Result types
error_chain!{
    //add custom or mapped error types here
    foreign_links {
        FromHexError(::hex::FromHexError);
        Utf8Error(::std::str::Utf8Error);
        Base64DecodeError(::base64::DecodeError);
        Io(::std::io::Error);
        OpenSSL(::openssl::error::ErrorStack);
        SystemTime(::std::time::SystemTimeError);
    }
}

#[derive(Debug)]
pub enum SubCommand {
    None,
    GenChi2(String),
    Set1,
    Set2,
    Set3,
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
