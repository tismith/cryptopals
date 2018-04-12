use clap;
use utils::types;

pub fn parse_cmdline() -> types::Settings {
    let matches = clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .arg(
            clap::Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity, maximum 4"),
        )
        .arg(
            clap::Arg::with_name("quiet")
                .short("q")
                .long("quiet")
                .help("Silence all output"),
        )
        .arg(
            clap::Arg::with_name("timestamp")
                .short("t")
                .long("timestamp")
                .help("prepend log lines with a timestamp")
                .takes_value(true)
                .possible_values(&["none", "sec", "ms", "ns"]),
        )
        .subcommand(
            clap::SubCommand::with_name("gen-chi2")
                .arg(clap::Arg::with_name("source").required(true)),
        )
        .subcommand(clap::SubCommand::with_name("set1"))
        .subcommand(clap::SubCommand::with_name("set2"))
        .get_matches();

    let verbosity = matches.occurrences_of("verbosity") as usize;
    if verbosity > 4 {
        clap::Error {
            message: "invalid number of 'v' flags".into(),
            kind: clap::ErrorKind::InvalidValue,
            info: None,
        }.exit()
    }
    let quiet = matches.is_present("quiet");
    let timestamp = match matches.value_of("timestamp") {
        Some("ns") => types::Timestamp::Nanosecond,
        Some("ms") => types::Timestamp::Microsecond,
        Some("sec") => types::Timestamp::Second,
        Some("none") | None => types::Timestamp::Off,
        Some(_) => clap::Error {
            message: "invalid value for 'timestamp'".into(),
            kind: clap::ErrorKind::InvalidValue,
            info: None,
        }.exit(),
    };

    let subcommand = match matches.subcommand() {
        ("gen-chi2", Some(sub_matches)) => {
            //this unwrap should be safe, since clap will error earlier
            //if it's not present
            let source = sub_matches.value_of("source").unwrap();
            types::SubCommand::GenChi2(source.into())
        }
        ("set1", _) => types::SubCommand::Set1,
        ("set2", _) => types::SubCommand::Set2,
        _ => types::SubCommand::None,
    };

    types::Settings {
        verbosity,
        quiet,
        timestamp,
        subcommand,
        ..Default::default()
    }
}
