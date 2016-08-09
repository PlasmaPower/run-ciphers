use std::io::Read;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::vec::Vec;
use std::thread;

use utils;
use openssl;
use openssl_ffi;

fn check_data(ciphertext: &Vec<u8>, cipher: *const openssl_ffi::EVP_CIPHER, key_iv_pair: &openssl::KeyIvPair) -> Option<String> {
    match openssl::decrypt(ciphertext, cipher, key_iv_pair) {
        None => None,
        Some(data) => {
            match String::from_utf8(data) {
                Result::Ok(string) => Some(string),
                Result::Err(_) => None
            }
        }
    }
}

pub fn run_passwords(possible_ciphertexts: &str, possible_ciphers: &str, passwords: &Vec<Vec<u8>>) -> Vec<String> {
    openssl::init_crypto();
    let mut ciphers_file = File::open(possible_ciphers).unwrap();
    let mut ciphers_string = String::new();
    ciphers_file.read_to_string(&mut ciphers_string).unwrap();
    let ciphers = ciphers_string
        .split('\n')
        .filter(|cipher| cipher.len() > 0)
        .map(String::from)
        .collect::<Vec<_>>();
    let mut salt_found = false;
    let mut salt: Vec<u8> = Vec::new();
    let ciphertexts_dir = Path::new(possible_ciphertexts);
    let ciphertexts = fs::read_dir(ciphertexts_dir).unwrap().filter_map(|entry| {
        let entry = entry.unwrap();
        if fs::metadata(&entry.path()).unwrap().is_file() {
            let binary = utils::read_binary_file(&entry.path());
            assert_eq!(&binary[0..8], b"Salted__");
            if salt_found {
                assert_eq!(binary[8..16].to_vec(), salt);
            } else {
                salt_found = true;
                salt = binary[8..16].to_vec();
            }
            return Some(binary[16..].to_vec());
        }
        None
    }).collect::<Vec<_>>();
    let passwords = passwords.clone().iter().map(|pass| pass.clone())
        .map(|mut pass| { pass.extend(salt.iter().clone()); return pass; })
        .collect::<Vec<_>>();
    let mut result = vec![];
    for password in passwords.iter() {
        let mut threads = vec![];
        for cipher in ciphers.iter() {
            let possible_key = openssl::get_key_iv_pair(openssl::get_cipher_by_name(cipher).unwrap(), password);
            match possible_key {
                Some(key_iv_pair) => {
                    for ciphertext in ciphertexts.iter() {
                        let cipher = cipher.clone();
                        let ciphertext = ciphertext.clone();
                        threads.push(thread::spawn(move || {
                            check_data(&ciphertext, openssl::get_cipher_by_name(&cipher).unwrap(), &key_iv_pair)
                        }));
                    }
                }
                None => println!("key creation failed")
            }
        }
        for thread in threads {
            match thread.join().unwrap() {
                Some(string) => result.push(string),
                None => continue
            }
        }
    }
    result
}
