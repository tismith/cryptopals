use base64;
use rand;
use std;
use utils;
//use utils::types::ResultExt;
use common;
use hex;

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
        let key = b"YELLOW SUBMARINE";
        let buffer = common::read_base64_file("data/set2-challenge10.txt")?;
        let cleartext = common::aes_128_cbc_decrypt(&buffer, &[0; 16], key)?;
        println!("{}", std::str::from_utf8(&cleartext)?);
    }

    {
        println!("Set 2 Challenge 11");
        let buffer = vec![b'X'; 100];
        let (cryptotext, mode) = encryption_oracle(&buffer)?;
        match detect_ecb_or_cbc(&cryptotext) {
            EcbOrCbc::ECB => println!("Was {:?}, found ECB!", mode),
            EcbOrCbc::CBC => println!("Was {:?}, found CBC!", mode),
        }
    }

    {
        println!("\nSet 2 Challenge 12");
        //block size discovery
        let mut block_size_discovery = vec![b'A', 1];
        let mut repeating_length = None;
        let previous_length = encryption_oracle2(&block_size_discovery)?.len();
        for _ in 0..100 {
            block_size_discovery.push(b'A');
            let out = encryption_oracle2(&block_size_discovery)?;
            if out.len() > previous_length {
                repeating_length = Some(out.len() - previous_length);
                break;
            }
        }
        if repeating_length.is_none() {
            bail!("Couldn't find blocksize");
        }
        let blocksize = repeating_length.unwrap();
        println!("Block length is {}", blocksize);

        //ecb detection
        let mut buffer = vec![b'X'; 40];
        buffer = encryption_oracle2(&buffer)?;
        match detect_ecb_or_cbc(&buffer) {
            EcbOrCbc::ECB => println!("Found ECB!"),
            EcbOrCbc::CBC => println!("Found CBC!"),
        }

        let mut secret = Vec::new();
        let plaintext_len = encryption_oracle2(b"")?.len();
        loop {
            let mut dictionary = std::collections::HashMap::new();
            let block = last_n_bytes_left_padded(&secret, blocksize - 1);
            trace!("block is {:?}", block);
            for c in 0..=std::u8::MAX {
                //build up dictionary
                let mut this_block = block.clone();
                this_block.push(c);
                trace!("this_block is {:?}", this_block);
                let mut output = encryption_oracle2(&this_block)?;
                output = output.iter().take(blocksize).cloned().collect();
                trace!("inserting {} -> {}", hex::encode(&output), c as char);
                dictionary.insert(output, c);
            }
            //The interesting character is in the middle of the stream,
            //so we need to work out which block it is in (interested_block)
            //and then pad the input so that we can control where the
            //interest charater appears on a blocksize boundary (basically, it needs
            //to appear at the end of a block)
            let lots_of_as = vec![b'A'; blocksize];
            let input: Vec<u8> = lots_of_as
                .iter()
                .take(blocksize - (secret.len() % blocksize) - 1)
                .cloned()
                .collect();
            let interested_block = secret.len() / blocksize;
            let mut output = encryption_oracle2(&input)?;
            output = output
                .chunks(blocksize)
                .nth(interested_block)
                .unwrap()
                .to_vec();
            trace!("looking up {}", hex::encode(&output));
            match dictionary.get(&output) {
                None => {
                    //bail when I can't find any more characters in the dictionary
                    break;
                }
                Some(secret_char) => {
                    secret.push(*secret_char);
                }
            }
            if secret.len() >= plaintext_len {
                break;
            }
        }
        println!("Secret is:\n{}", ::std::str::from_utf8(&secret)?);
        //lookup output in dictionary, and push into secret
    }

    {
        println!("Set 2 Challenge 13");
        //part A
        //Encrypt the encoded user profile under the key
        //"provide" that to the "attacker".
        let key: [u8; 16] = rand::random();
        println!("legit user is toby@tismith.id.au");
        let crypted = encrypt_profile("toby@tismith.id.au", &key)?;

        //part B
        //Decrypt the encoded user profile and parse it.
        let decrypted = common::aes_128_ecb_decrypt(&crypted, &key)?;
        let parsed = parse_kv_query(std::str::from_utf8(&decrypted)?)?;
        let role = &parsed["role"];
        println!("legit role is {}", &role);

        //form the AES block encrypted of "admin......." where .. is the
        //pkcs#7 padding
        trace!("making fake admin block");
        //need to be long enough to get 'admin' to appear at the start of a
        //block, and then pkcs#7 pad the rest of the second block
        let admin_input = common::pkcs7_pad(b"1234567890admin", 32);
        let admin_crypt = encrypt_profile(std::str::from_utf8(&admin_input)?, &key)?;
        let admin = admin_crypt[16..32].to_vec();
        //up to the role in the plain text we have
        //email={}&uid=10&role={}
        //i.e 19 characters, so to get the role= to end on a block boundary
        //I need an email address of 32-19 = 13 characters

        trace!("making fake profile blocks");
        let email = "123456789@123";
        let legit = encrypt_profile(email, &key)?;
        let mut forged: Vec<u8> = legit[0..32].to_vec();

        trace!("copying and pasting the bits together");
        forged.append(&mut admin.to_owned());

        //part B
        //Decrypt the encoded user profile and parse it.
        let decrypted2 = common::aes_128_ecb_decrypt(&forged, &key)?;
        println!("decrypted is {}", &std::str::from_utf8(&decrypted2)?);
        let parsed2 = parse_kv_query(std::str::from_utf8(&decrypted2)?)?;
        println!("forged profile is ");
        for (k, v) in &parsed2 {
            println!("{} = {}", k, v);
        }
    }

    //cyclomatic complexity is getting too high, start pulling functions out
    set2_challenge14()?;

    {
        println!("Set 2 Challenge 15");
        println!(
            "{}",
            std::str::from_utf8(&common::strip_pkcs7_padding(
                b"ICE ICE BABY\x04\x04\x04\x04"
            )?)?
        );
    }

    set2_challenge16()?;

    Ok(())
}

fn set2_challenge16() -> utils::types::Result<()> {
    println!("Set 2 Challenge 16");
    let iv: [u8; 16] = rand::random();
    let key: [u8; 16] = rand::random();
    //; is 0x3b, = is 0x3d
    //: is 0x3a, < is 0x3c
    //pad the 'user input' with clean usertext so
    //I've got a clean slate to mutate, without touching
    //the oracle's prefix
    let cryptotext = encryption_oracle4(b"0123456789012345:admin<true:", &iv, &key)?;
    let mut faked_cryptotext: Vec<u8> = Vec::new();
    //skip two blocks.. could I know this without knowing
    //what the plaintext prefix is?
    faked_cryptotext.extend(cryptotext[0..32].iter());
    let mut block_to_mutate = cryptotext[32..48].to_vec();
    let semicolon_mask = b';' ^ b':';
    let equal_mask = b'=' ^ b'<';
    block_to_mutate[0] ^= semicolon_mask;
    block_to_mutate[6] ^= equal_mask;
    block_to_mutate[11] ^= semicolon_mask;
    faked_cryptotext.extend(block_to_mutate.iter());
    faked_cryptotext.extend(cryptotext[48..].iter());
    if is_admin_profile(&faked_cryptotext, &iv, &key)? {
        println!("We have admin!");
    } else {
        println!("We don't have admin :(");
    }
    Ok(())
}

fn set2_challenge14() -> utils::types::Result<()> {
    use rand::Rng;
    println!("Set Challenge 14");

    let mut rng = rand::thread_rng();
    let random_count: usize = rand::random::<usize>() % 100;
    let mut random_bytes = vec![0u8; random_count];
    rng.fill_bytes(&mut random_bytes);

    //find an prefix and an offset into the output
    //that lets us skip over the prefix

    //first, find what the key encrypts a block of 'A' to
    let output = encryption_oracle3(&random_bytes, &[b'A'; 100])?;
    debug!("collecting chunks by count");
    let chunks: Vec<_> = output.chunks(16).collect();
    let mut chunk_count = std::collections::HashMap::new();
    for chunk in &chunks {
        let current_count = *chunk_count.get(chunk).unwrap_or(&0);
        chunk_count.insert(chunk, current_count + 1);
    }
    debug!("about to look for largest counted block");
    let base = vec![0u8; 16];
    let (k, v): (&[u8], _) = chunk_count.iter().fold((&base, &0), |(ko, vo), (k, v)| {
        if v > vo {
            (k, v)
        } else {
            (ko, vo)
        }
    });
    debug!("Highest scoring block was:\n{:?} = {}", k, v);

    let mut index = 0;
    let mut chunk_index = 0;
    for i in 0..100 {
        index = i;
        let trial_padding = vec![b'A'; i];
        let output = encryption_oracle3(&random_bytes, &trial_padding)?;
        let mut found_chunk = false;
        let chunks: Vec<_> = output.chunks(16).collect();
        chunk_index = 0;
        for chunk in &chunks {
            if chunk == &k {
                found_chunk = true;
                break;
            }
            chunk_index += 1;
        }
        if found_chunk {
            break;
        }
    }
    debug!("index is {}, chunk_index is {}", index, chunk_index);
    //so now I know that with index As at the start, I get a known
    //block at index chunk_index.
    //I.e. I just need to start all plaintext with index As and skip
    //over chunk_index blocks of the output.

    let prefix_as = vec![b'A'; index];

    //now just do challenge 12 with those offsets
    let mut secret = Vec::new();
    let blocksize = 16;
    loop {
        let mut dictionary = std::collections::HashMap::new();
        let block = last_n_bytes_left_padded(&secret, blocksize - 1);
        trace!("block is {:?}", block);
        for c in 0..std::u8::MAX {
            //build up dictionary
            let mut this_block = block.clone();
            this_block.push(c);
            trace!("this_block is {:?}", this_block);
            let mut input = prefix_as.clone();
            input.append(&mut this_block);
            let mut output = encryption_oracle3(&random_bytes, &input)?;
            output = output[((chunk_index + 1) * 16)..].to_vec();
            output = output.iter().take(blocksize).cloned().collect();
            trace!("inserting {} -> {}", hex::encode(&output), c as char);
            dictionary.insert(output, c);
        }
        //The interesting character is in the middle of the stream,
        //so we need to work out which block it is in (interested_block)
        //and then pad the input so that we can control where the
        //interest charater appears on a blocksize boundary (basically, it needs
        //to appear at the end of a block)
        let lots_of_as = vec![b'A'; blocksize];
        let mut input: Vec<u8> = lots_of_as
            .iter()
            .take(blocksize - (secret.len() % blocksize) - 1)
            .cloned()
            .collect();
        let interested_block = secret.len() / blocksize;
        let mut input_padded = prefix_as.clone();
        input_padded.append(&mut input);
        let mut output = encryption_oracle3(&random_bytes, &input_padded)?;
        output = output[((chunk_index + 1) * 16)..].to_vec();
        output = output
            .chunks(blocksize)
            .nth(interested_block)
            .unwrap()
            .to_vec();
        trace!("looking up {}", hex::encode(&output));
        match dictionary.get(&output) {
            None => {
                //bail when I can't find any more characters in the dictionary
                break;
            }
            Some(secret_char) => {
                debug!("Adding secret {}", secret_char);
                secret.push(*secret_char);
            }
        }
    }
    println!("Secret is:\n{}", ::std::str::from_utf8(&secret)?);
    Ok(())
}

fn encryption_oracle4(plaintext: &[u8], iv: &[u8], key: &[u8]) -> utils::types::Result<Vec<u8>> {
    let prefix = b"comment1=cooking%20MCs;userdata=";
    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
    let mut input = Vec::new();
    input.extend(prefix.iter());
    for c in plaintext {
        if *c == b';' {
            input.push(b'%');
            input.push(b'3');
            input.push(b'B');
        } else if *c == b'=' {
            input.push(b'%');
            input.push(b'3');
            input.push(b'D');
        } else {
            input.push(*c);
        }
    }
    input.extend(suffix.iter());
    //this will do pkcs#7 padding for me
    Ok(common::aes_128_cbc_encrypt(&input, iv, key)?)
}

fn is_admin_profile(session: &[u8], iv: &[u8], key: &[u8]) -> utils::types::Result<bool> {
    let plaintext = common::aes_128_cbc_decrypt(session, iv, key)?;
    for segment in plaintext.split(|ch| *ch == b';') {
        if segment == b"admin=true" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn encrypt_profile(email: &str, key: &[u8]) -> utils::types::Result<Vec<u8>> {
    let profile = profile_for(email);
    Ok(common::aes_128_ecb_encrypt(profile.as_bytes(), key)?)
}

fn parse_kv_query(query: &str) -> utils::types::Result<std::collections::HashMap<String, String>> {
    let mut decoded = std::collections::HashMap::new();
    for kv in query.split('&') {
        let k_v: Vec<&str> = kv.split('=').collect();
        if k_v.len() != 2 {
            bail!(format!("Invalid kv of {}", kv));
        }
        let k = k_v[0];
        let v = k_v[1];
        decoded.insert(k.to_string(), v.to_string());
    }
    Ok(decoded)
}

fn profile_for(email: &str) -> String {
    let sanitized = email.replace("&", "").replace("=", "");
    format!("email={}&uid=10&role=user", sanitized)
}

fn last_n_bytes_left_padded(buffer: &[u8], size: usize) -> Vec<u8> {
    let lots_of_as = vec![b'A'; size];
    //take the last blocksize - 1 chars from secret, left padded with As
    let mut block: Vec<u8> = buffer
        .iter()
        .rev()
        .chain(lots_of_as.iter())
        .take(size)
        .cloned()
        .collect();
    block.reverse();
    block
}

fn encryption_oracle(cleartext: &[u8]) -> utils::types::Result<(Vec<u8>, EcbOrCbc)> {
    use rand::{distributions::IndependentSample, Rng};
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rand::random();
    let range = rand::distributions::Range::new(5, 11);
    let num_prepend = range.ind_sample(&mut rng);
    let num_append = range.ind_sample(&mut rng);
    let mut plaintext = vec![0u8; num_prepend];
    rng.fill_bytes(&mut plaintext);
    plaintext.extend_from_slice(cleartext);
    let mut footer = vec![0u8; num_append];
    rng.fill_bytes(&mut footer);
    plaintext.append(&mut footer);

    if rand::random::<bool>() {
        //ECB
        trace!("Chose ECB");
        Ok((
            common::aes_128_ecb_encrypt(&plaintext, &key)?,
            EcbOrCbc::ECB,
        ))
    } else {
        //CBC
        trace!("Chose CBC");
        let iv: [u8; 16] = rand::random();
        Ok((
            common::aes_128_cbc_encrypt(&plaintext, &iv, &key)?,
            EcbOrCbc::CBC,
        ))
    }
}

fn encryption_oracle2(cleartext: &[u8]) -> utils::types::Result<Vec<u8>> {
    let base_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                       aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                       dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                       YnkK";
    let key = b"vnaSkaclkAaskjc;"; //just mashed the keyboard
    let mut secret = base64::decode(base_secret)?;
    let mut plaintext = cleartext.to_vec();
    plaintext.append(&mut secret);
    Ok(common::aes_128_ecb_encrypt(&plaintext, key)?)
}

fn encryption_oracle3(prefix: &[u8], cleartext: &[u8]) -> utils::types::Result<Vec<u8>> {
    let base_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                       aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                       dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                       YnkK";
    let key = b"vnaSkaclkAaskjc;"; //just mashed the keyboard
    let mut plaintext = Vec::new();
    let secret = base64::decode(base_secret)?;
    plaintext.extend_from_slice(prefix);
    plaintext.extend_from_slice(cleartext);
    plaintext.extend_from_slice(&secret);
    Ok(common::aes_128_ecb_encrypt(&plaintext, key)?)
}

#[derive(Debug, PartialEq)]
enum EcbOrCbc {
    ECB,
    CBC,
}

fn detect_ecb_or_cbc(cryptotext: &[u8]) -> EcbOrCbc {
    //sort and dedup our chunks - repeated chunks will be stripped
    //by the dedup, so the shortest resultant vec is our winner!
    let mut chunks: Vec<&[u8]> = cryptotext.chunks(16).collect();
    let origin_len = chunks.len();
    chunks.sort();
    chunks.dedup();
    if chunks.len() < origin_len {
        EcbOrCbc::ECB
    } else {
        EcbOrCbc::CBC
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_detect_ecb_or_cbc() {
        (0..10).for_each(|_| {
            let buffer = vec![b'X'; 100];
            let (cryptotext, mode) = encryption_oracle(&buffer).unwrap();
            assert_eq!(detect_ecb_or_cbc(&cryptotext), mode);
        })
    }

    #[test]
    fn test_is_admin_profile() {
        {
            let plaintext = b"hello;admin=true;world";
            let key: [u8; 16] = rand::random();
            let iv: [u8; 16] = rand::random();
            let crypted = common::aes_128_cbc_encrypt(plaintext, &iv, &key).unwrap();
            assert_eq!(is_admin_profile(&crypted, &iv, &key).unwrap(), true);
        }

        {
            let plaintext = b"hello;admin=false;world";
            let key: [u8; 16] = rand::random();
            let iv: [u8; 16] = rand::random();
            let crypted = common::aes_128_cbc_encrypt(plaintext, &iv, &key).unwrap();
            assert_eq!(is_admin_profile(&crypted, &iv, &key).unwrap(), false);
        }
    }

    #[test]
    fn test_parse_kv_query() {
        let test_query = "foo=bar&baz=qux&zap=zazzle";
        let output = parse_kv_query(test_query).unwrap();
        let mut expected = std::collections::HashMap::new();
        expected.insert("foo".to_string(), "bar".to_string());
        expected.insert("baz".to_string(), "qux".to_string());
        expected.insert("zap".to_string(), "zazzle".to_string());
        assert_eq!(output, expected);
    }
}
