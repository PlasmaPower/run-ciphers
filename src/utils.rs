use std::fs::File;
use std::path::Path;
use std::io::Read;

pub fn read_binary_file(path: &Path) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    return buf;
}
