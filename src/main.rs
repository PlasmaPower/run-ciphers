use std::path::Path;
use std::io::{self, Read};
use std::panic;

extern crate clap;
use clap::{Arg, App, AppSettings, SubCommand};

extern crate hyper;
use hyper::server::{Server, Request, Response};
use hyper::uri::RequestUri;
use hyper::status::StatusCode;

extern crate rustc_serialize;
use rustc_serialize::json;

mod openssl;
mod openssl_ffi;
mod utils;
mod run_passwords;

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
                         .help("Listen on this address")))
        .get_matches();

    let possible_ciphertexts = String::from(matches.value_of("possible-ciphertexts").unwrap());
    let possible_ciphers = String::from(matches.value_of("possible-ciphers").unwrap());
    macro_rules! run_passwords {
        ($passwords: expr) => (run_passwords::run_passwords(&possible_ciphertexts, &possible_ciphers, Box::new($passwords)));
    }
    if let Some(matches) = matches.subcommand_matches("files") {
        let passwords = matches.values_of("file").unwrap()
            .map(|arg| utils::read_binary_file(&Path::new(arg)));
        for res in run_passwords!(passwords) {
            println!("Cipher {} generates UTF-8 string!\n{}", res.cipher, res.string);
        }
    } else if let Some(matches) = matches.subcommand_matches("args") {
        let passwords = matches.values_of("password").unwrap().map(|string| Vec::from(string.as_bytes()));
        for res in run_passwords!(passwords) {
            println!("Cipher {} generates UTF-8 string!\n{}", res.cipher, res.string);
        }
    } else if matches.subcommand_matches("stdin").is_some() {
        let mut stdin_str: String = String::new();
        io::stdin().read_to_string(&mut stdin_str).unwrap();
        let passwords = stdin_str.split("\n").filter(|str| str.len() > 0).map(|str| Vec::from(str.as_bytes()));
        for res in run_passwords!(passwords) {
            println!("Cipher {} generates UTF-8 string!\n{}", res.cipher, res.string);
        }
    } else if let Some(matches) = matches.subcommand_matches("http") {
        Server::http(matches.value_of("listen-address").unwrap()).unwrap().handle_threads(move |req: Request, mut res: Response| {
            match req.uri {
                RequestUri::AbsolutePath(string) => {
                    if !string.starts_with('/') {
                        *res.status_mut() = StatusCode::BadRequest;
                        res.send(b"Invalid path.").unwrap();
                        return;
                    }
                    match panic::catch_unwind(|| run_passwords!(vec![string[1..].as_bytes().iter().map(|n| n.clone()).collect()])) {
                        Ok(result) => match json::encode(&result) {
                            Ok(string) => res.send(string.as_bytes()).unwrap(),
                            Err(_) => {
                                *res.status_mut() = StatusCode::InternalServerError;
                                res.send(b"Internal server error.").unwrap();
                            }
                        },
                        Err(_) => {
                            *res.status_mut() = StatusCode::InternalServerError;
                            res.send(b"Internal server error.").unwrap();
                        }
                    }
                },
                _ => {
                    *res.status_mut() = StatusCode::BadRequest;
                    res.send(b"Invalid path.").unwrap();
                }
            }
        }, 4).unwrap();
    }
}
