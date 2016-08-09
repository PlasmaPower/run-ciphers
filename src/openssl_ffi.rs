extern crate libc;
use self::libc::{c_int, c_void, c_ulong};

pub const EVP_MAX_KEY_LENGTH: usize = 64;
pub const EVP_MAX_IV_LENGTH: usize = 16;
pub const EVP_MAX_BLOCK_LENGTH: usize = 32;

#[repr(C)]
pub struct EVP_CIPHER {
    // replica from crypto/include/internal/evp_int.h
    pub nid: c_int,
    pub block_size: c_int,
    pub key_len: c_int,
    pub iv_len: c_int,
    pub flags: u32,
    // a lot of these function pointers are dependent on other structures
    // we don't need them, so I've just pretended they're void pointers
    init: *mut c_void,
    do_cipher: *mut c_void,
    cleanup: *mut c_void,
    ctx_size: c_int,
    set_asn1_parameters: *mut c_void,
    get_asn1_parameters: *mut c_void,
    ctrl: *mut c_void,
    app_data: *mut c_void
}

#[repr(C)]
pub struct EVP_CIPHER_CTX {
    // replica from crypto/evp/evp_locl.h
    cipher: *const EVP_CIPHER,
    engine: *mut c_void,
    encrypt: c_int,
    buf_length: c_int,
    oiv: [u8; EVP_MAX_IV_LENGTH],
    iv: [u8; EVP_MAX_IV_LENGTH],
    buf: [u8; EVP_MAX_BLOCK_LENGTH],
    num: c_int,
    app_data: *mut c_void,
    key_len: c_int,
    flags: c_ulong,
    cipher_data: *mut c_void,
    final_used: c_int,
    block_mask: c_int,
    final_block: [u8; EVP_MAX_BLOCK_LENGTH]
}

#[repr(C)]
pub struct EVP_MD {
    // similar to EVP_CIPHER, see above comments
    type_num: c_int,
    pkey_type: c_int,
    md_size: c_int,
    flags: c_ulong,
    init: *mut c_void,
    update: *mut c_void,
    finalize: *mut c_void,
    copy: *mut c_void,
    cleanup: *mut c_void,
    block_size: c_int,
    ctx_size: c_int
}

#[link(name = "crypto")]
extern {
    pub fn OPENSSL_add_all_algorithms_noconf() -> c_int;
    pub fn EVP_get_cipherbyname(name: *const u8) -> *mut EVP_CIPHER;
    pub fn EVP_md5() -> *const EVP_MD;
    pub fn EVP_BytesToKey(cipher: *const EVP_CIPHER, md: *const EVP_MD, salt: *const u8, data: *const u8, datal: c_int, count: c_int, key: *mut u8, iv: *mut u8) -> c_int;
    pub fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    pub fn EVP_DecryptInit_ex(ctx: *const EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, engine: *const c_void, key: *const u8, iv: *const u8) -> c_int;
    pub fn EVP_DecryptUpdate(ctx: *const EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, input: *const u8, inputl: c_int) -> c_int;
    pub fn EVP_DecryptFinal_ex(ctx: *const EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int;
    pub fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);
}
