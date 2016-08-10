use std::io::Read;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::vec::Vec;
use std::thread;

use utils;
use openssl;

#[derive(RustcEncodable)]
pub struct CipherResult {
  pub cipher: String,
  pub string: String
}

pub struct DecryptionContext {
  ciphertexts: Vec<Vec<u8>>,
  ciphers: Vec<String>,
  salt: Vec<u8>
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
    let mut ciphertexts = Vec::new();
    for ciphertext in ciphertexts_full {
      assert_eq!(&ciphertext[0..8], b"Salted__");
      if salt_found {
        assert_eq!(salt, ciphertext[8..16].to_vec());
      } else {
        salt = ciphertext[8..16].to_vec();
        salt_found = true;
      }
      ciphertexts.push(ciphertext[16..].to_vec());
    }
    DecryptionContext {
      ciphertexts: ciphertexts,
      ciphers: ciphers,
      salt: salt
    }
  }

  pub fn decrypt<T>(&self, passwords: T) -> Vec<CipherResult> where T: IntoIterator<Item=Vec<u8>> {
    let passwords = passwords.into_iter().map(|pass| pass.clone())
      .map(|mut pass| { pass.extend(self.salt.iter().clone()); return pass; })
      .collect::<Vec<_>>();
    let mut result = vec![];
    for password in passwords.iter() {
      for cipher_name in self.ciphers.iter() {
        let cipher = match openssl::get_cipher_by_name(cipher_name) {
          Some(cipher) => cipher,
          None => continue
        };
        let mut threads = vec![];
        let possible_key = openssl::get_key_iv_pair(cipher, password);
        match possible_key {
          Some(key_iv_pair) => {
            for ciphertext in self.ciphertexts.iter() {
              unsafe {
                let cipher_box = Box::from_raw(cipher);
                let ciphertext = ciphertext.clone();
                threads.push(thread::spawn(move || {
                  match openssl::decrypt(&ciphertext, Box::into_raw(cipher_box), &key_iv_pair) {
                    None => None,
                    Some(data) => {
                      match String::from_utf8(data) {
                        Result::Ok(string) => Some(string),
                        Result::Err(_) => None
                      }
                    }
                  }
                }));
              }
            }
          }
          None => {}
        }
        for thread in threads {
          match thread.join() {
            Ok(res) => match res {
              Some(string) => result.push(CipherResult { cipher: cipher_name.clone(), string: string }),
              None => {}
            },
            Err(_) => {}
          }
        }
      }
    }
    result
  }
}
