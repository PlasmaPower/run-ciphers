use std::path::Path;
use std::io::{self, Read, Write};
use std::fs::{File, OpenOptions};

use std::cell::RefCell;
use std::ops::Deref;

extern crate clap;
use clap::{Arg, App, AppSettings, SubCommand};

extern crate hyper;
use hyper::header;
use hyper::server::{Server, Request, Response};
use hyper::uri::RequestUri;
use hyper::status::StatusCode;

extern crate rustc_serialize;
use rustc_serialize::json;

mod openssl;
mod openssl_ffi;
mod utils;
mod decryption_context;

use decryption_context::DecryptionContext;

#[derive(RustcEncodable)]
pub struct LogEntry {
    query: String,
    result: Vec<decryption_context::CipherResult>
}

fn main() {
    let matches = App::new("Run Ciphers")
        .version("1.0")
        .author("vmzcg")
        .about("Runs given passwords on various ciphers and ciphertexts")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg(Arg::with_name("possible-ciphers")
             .short("c")
             .long("possible-ciphers")
             .value_name("FILE")
             .default_value("possible-ciphers")
             .help("Sets a custom possible ciphers list"))
        .arg(Arg::with_name("possible-ciphertexts")
             .short("t")
             .long("possible-ciphertexts")
             .value_name("DIRECTORY")
             .default_value("possible-ciphertexts")
             .help("Sets a custom possible ciphertexts directory"))
        .subcommand(SubCommand::with_name("files")
                    .about("reads passwords from files")
                    .arg(Arg::with_name("file")
                         .required(true)
                         .multiple(true)
                         .value_name("FILES")
                         .help("Read passwords from this file")))
        .subcommand(SubCommand::with_name("args")
                    .about("reads passwords from arguments")
                    .arg(Arg::with_name("password")
                         .required(true)
                         .multiple(true)
                         .value_name("PASSWORDS")
                         .help("Set passwords")))
        .subcommand(SubCommand::with_name("stdin")
                    .about("reads passwords from stdin"))
        .subcommand(SubCommand::with_name("http")
                    .about("starts an HTTP server")
                    .arg(Arg::with_name("listen-address")
                         .short("a")
                         .long("listen-address")
                         .value_name("ADDRESS")
                         .default_value("0.0.0.0:80")
                         .help("Listen on this address"))
                    .arg(Arg::with_name("log-file")
                         .short("l")
                         .long("log-file")
                         .value_name("FILE")
                         .help("Log tried passwords and results to this file")))
        .get_matches();

    let possible_ciphertexts = String::from(matches.value_of("possible-ciphertexts").unwrap());
    let possible_ciphers = String::from(matches.value_of("possible-ciphers").unwrap());
    let decryption_context = DecryptionContext::new(&possible_ciphertexts, &possible_ciphers);
    if let Some(matches) = matches.subcommand_matches("files") {
        let passwords = matches.values_of("file").unwrap()
            .map(|arg| utils::read_binary_file(&Path::new(arg)));
        for res in decryption_context.decrypt(passwords) {
            println!("Cipher {} generates UTF-8 string!\n{}", res.cipher, res.string);
        }
    } else if let Some(matches) = matches.subcommand_matches("args") {
        let passwords = matches.values_of("password").unwrap().map(|string| Vec::from(string.as_bytes()));
        for res in decryption_context.decrypt(passwords) {
            println!("Cipher {} generates UTF-8 string!\n{}", res.cipher, res.string);
        }
    } else if matches.subcommand_matches("stdin").is_some() {
        let mut stdin_str: String = String::new();
        io::stdin().read_to_string(&mut stdin_str).unwrap();
        let passwords = stdin_str.split("\n").filter(|str| str.len() > 0).map(|str| Vec::from(str.as_bytes()));
        for res in decryption_context.decrypt(passwords) {
            println!("Cipher {} generates UTF-8 string!\n{}", res.cipher, res.string);
        }
    } else if let Some(matches) = matches.subcommand_matches("http") {
        let log_file_match = matches.value_of("log-file").map(|s| String::from(s));
        thread_local!(static LOG_FILE: RefCell<Option<Result<RefCell<File>, io::Error>>> = RefCell::new(None));
        Server::http(matches.value_of("listen-address").unwrap()).unwrap().handle_threads(move |req: Request, mut res: Response| {
            res.headers_mut().set(header::AccessControlAllowOrigin::Any);
            match req.uri {
                RequestUri::AbsolutePath(string) => {
                    if !string.starts_with('/') {
                        *res.status_mut() = StatusCode::BadRequest;
                        let _ = res.send(b"Invalid path.");
                        return;
                    }
                    let query = String::from(&string[1..]);
                    let result = decryption_context.decrypt(vec![query.as_bytes().iter().map(|n| n.clone()).collect()]);
                    match json::encode(&result) {
                        Ok(str) => {
                            if let Some(ref log_file_path) = log_file_match {
                                LOG_FILE.with(|log_file_cache| {
                                    let mut log_file = log_file_cache.borrow_mut();
                                    if log_file.is_none() {
                                        let new_log_file = Some(OpenOptions::new()
                                                                .create(true)
                                                                .write(true)
                                                                .append(true)
                                                                .open(log_file_path).map(|f| RefCell::new(f)));
                                        *log_file = new_log_file;
                                    }
                                    if let &Some(Ok(ref file)) = log_file.deref() {
                                        if let Ok(mut entry) = json::encode(&LogEntry { query: query, result: result }) {
                                            entry.push('\0');
                                            let _ = file.borrow_mut().write(entry.as_bytes());
                                            let _ = file.borrow_mut().flush();
                                        }
                                    }
                                });
                            }
                            res.headers_mut().set(header::ContentType::json());
                            let _ = res.send(str.as_bytes());
                        },
                        Err(_) => {
                            *res.status_mut() = StatusCode::InternalServerError;
                            let _ = res.send(b"Unable to encode result as JSON.");
                        }
                    }
                },
                _ => {
                    *res.status_mut() = StatusCode::BadRequest;
                    let _ = res.send(b"Invalid path.");
                }
            }
        }, 4).unwrap();
    }
}
