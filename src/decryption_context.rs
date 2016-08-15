use std::io::Read;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::vec::Vec;
use std::sync::Mutex;

extern crate md5;
extern crate crossbeam;

use utils;
use openssl;

#[derive(RustcEncodable)]
pub struct CipherResult {
    pub ciphertext: String,
    pub cipher: String,
    pub string: String
}

pub struct DecryptionContext {
    ciphertexts: Vec<HashedData>,
    ciphers: Vec<String>,
    salt: Vec<u8>
}

struct HashedData {
    hash: String,
    data: Vec<u8>
}

impl DecryptionContext {
    pub fn new(possible_ciphertexts: &String, possible_ciphers: &String) -> DecryptionContext {
        openssl::init_crypto();
        let mut ciphers_file = File::open(possible_ciphers).unwrap();
        let mut ciphers_string = String::new();
        ciphers_file.read_to_string(&mut ciphers_string).unwrap();
        let ciphers = ciphers_string
            .split('\n')
            .filter(|cipher| cipher.len() > 0)
            .map(String::from)
            .collect::<Vec<_>>();
        let mut salt = Vec::new();
        let mut salt_found = false;
        let ciphertexts_dir = Path::new(possible_ciphertexts);
        let ciphertexts_full = fs::read_dir(ciphertexts_dir).unwrap().filter_map(|entry| {
            let entry = entry.unwrap();
            if fs::metadata(&entry.path()).unwrap().is_file() {
                return Some(utils::read_binary_file(&entry.path()));
            }
            None
        }).collect::<Vec<_>>();
        let mut ciphertexts: Vec<HashedData> = Vec::new();
        for ciphertext in ciphertexts_full {
            assert_eq!(&ciphertext[0..8], b"Salted__");
            if salt_found {
                assert_eq!(salt, ciphertext[8..16].to_vec());
            } else {
                salt = ciphertext[8..16].to_vec();
                salt_found = true;
            }
            ciphertexts.push(HashedData {
                data: ciphertext[16..].to_vec(),
                hash: md5::compute(&ciphertext[..]).iter()
                                   .map(|n| format!("{:x}", n))
                                   .collect::<Vec<_>>()
                                   .concat()
            });
        }
        DecryptionContext {
            ciphertexts: ciphertexts,
            ciphers: ciphers,
            salt: salt
        }
    }

    pub fn decrypt<F>(&self, password: Vec<u8>, callback: F)
        where F: Fn(CipherResult) {
        let mut password = password.clone();
        password.extend(self.salt.iter().cloned());
        for cipher_name in self.ciphers.iter() {
            let cipher = match openssl::get_cipher_by_name(cipher_name) {
                Some(cipher) => cipher,
                None => continue
            };
            let possible_key = openssl::get_key_iv_pair(cipher, &password);
            match possible_key {
                Some(key_iv_pair) => {
                    for ciphertext in self.ciphertexts.iter() {
                        openssl::decrypt(&ciphertext.data, cipher, &key_iv_pair)
                            .and_then(|data| {
                                if data.iter().filter(|n| **n == 0).count() < data.len() / 2 {
                                    return Some(data);
                                }
                                None
                            })
                            .and_then(|data| String::from_utf8(data).ok())
                            .and_then(|string| -> Option<String> {
                                callback(CipherResult {
                                    ciphertext: ciphertext.hash.clone(),
                                    cipher: cipher_name.clone(),
                                    string: string.clone()
                                });
                                None
                            });
                    }
                }
                None => {}
            }
        }
    }

    pub fn decrypt_and_collect(&self, password: Vec<u8>) -> Vec<CipherResult> {
        let results = Mutex::new(vec![]);
        self.decrypt(password, |result| results.lock().unwrap().push(result));
        return results.into_inner().unwrap();
    }

    pub fn run_passwords<T>(&self, passwords: T) where T: IntoIterator<Item=Vec<u8>> {
        crossbeam::scope(move |scope| {
            for password in passwords {
                let password = password.clone();
                scope.spawn(move || {
                    self.decrypt(password, |result: CipherResult| {
                        println!("Cipher {} generates UTF-8 string!\n{}", result.cipher, result.string);
                    });
                });
            }
        });
    }
}
