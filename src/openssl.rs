extern crate libc;
use self::libc::c_int;

use std::ptr;
use std::ffi::CString;

use openssl_ffi;

#[derive(Copy)]
pub struct KeyIvPair {
    pub key: [u8; openssl_ffi::EVP_MAX_KEY_LENGTH],
    pub iv: [u8; openssl_ffi::EVP_MAX_IV_LENGTH]
}

impl Clone for KeyIvPair {
    fn clone(&self) -> KeyIvPair { *self }
}

pub fn init_crypto() {
    unsafe {
        if openssl_ffi::OPENSSL_add_all_algorithms_noconf() != 1 {
            panic!("Failed to init crypto");
        }
    }
}

pub fn get_cipher_by_name(name: &String) -> Option<*const openssl_ffi::EVP_CIPHER> {
    unsafe {
        let ptr = openssl_ffi::EVP_get_cipherbyname(CString::new(name.clone()).unwrap().as_ptr() as *const u8);
        if ptr.is_null() {
            return None;
        }
        return Some(ptr);
    }
}

pub fn get_key_iv_pair(cipher: *const openssl_ffi::EVP_CIPHER, data: &Vec<u8>) -> Option<KeyIvPair> {
    unsafe {
        let mut key: [u8; openssl_ffi::EVP_MAX_KEY_LENGTH] = [0; openssl_ffi::EVP_MAX_KEY_LENGTH];
        let mut iv: [u8; openssl_ffi::EVP_MAX_IV_LENGTH] = [0; openssl_ffi::EVP_MAX_IV_LENGTH];
        if openssl_ffi::EVP_BytesToKey(cipher, openssl_ffi::EVP_md5(), ptr::null(), data.as_ptr(), data.len() as c_int, 1, key.as_mut_ptr(), iv.as_mut_ptr()) == 0 {
            return None;
        }
        return Some(KeyIvPair { key: key, iv: iv });
    }
}

pub fn decrypt(ciphertext: &Vec<u8>, cipher: *const openssl_ffi::EVP_CIPHER, key_iv_pair: &KeyIvPair) -> Option<Vec<u8>> {
    unsafe {
        let ctx: *mut openssl_ffi::EVP_CIPHER_CTX = openssl_ffi::EVP_CIPHER_CTX_new();
        if openssl_ffi::EVP_DecryptInit_ex(ctx, cipher, ptr::null(), key_iv_pair.key.as_ptr(), key_iv_pair.iv.as_ptr()) != 1 {
            return None;
        }
        if ctx.is_null() {
            return None;
        }
        let mut len = 0;
        let mut out: [u8; 1028] = [0; 1028];
        if openssl_ffi::EVP_DecryptUpdate(ctx, out.as_mut_ptr(), &mut len, ciphertext.as_ptr(), ciphertext.len() as i32) != 1 {
            return None;
        }
        if len > 1028 {
            panic!("OpenSSL overwrote output, memory corrupted!");
        }
        let mut outl = 0;
        if openssl_ffi::EVP_DecryptFinal_ex(ctx, out.as_mut_ptr().offset(len as isize), &mut outl) != 1 {
            return None;
        }
        len += outl;
        if len > 1028 {
            panic!("OpenSSL overwrote output, memory corrupted!");
        }
        openssl_ffi::EVP_CIPHER_CTX_free(ctx);
        return Some(Vec::from(&out[0..((len + 1) as usize)]));
    }
}
