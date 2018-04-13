use std;
use utils;
//use utils::types::ResultExt;
use common;

pub fn run_set2() -> utils::types::Result<()> {
    {
        println!("Set 2 Challenge 9");
        //this doesn't print the padding..
        println!(
            "{}",
            std::str::from_utf8(&common::pkcs7_pad(b"YELLOW SUBMARINE", 20))?
        );
    }

    {
        println!("Set 2 Challenge 10");
        let _buffer = common::read_base64_file("data/set2-challenge10.txt")?;
    }

    Ok(())
}
