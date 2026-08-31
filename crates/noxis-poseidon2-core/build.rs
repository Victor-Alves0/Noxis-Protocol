use std::{env, fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

const EXPECTED_LENGTH: usize = 7_596;
const EXPECTED_SHA256: [u8; 32] = [
    0x48, 0xf6, 0xc2, 0x5b, 0x02, 0xa6, 0x40, 0xc0, 0x6e, 0x3b, 0xbc, 0x8f, 0xc4, 0x97, 0x04, 0x63,
    0x4f, 0x25, 0x4c, 0xd0, 0xa7, 0x71, 0x61, 0xa5, 0x9b, 0x28, 0x3e, 0x53, 0x02, 0xa3, 0x90, 0xb0,
];
const BABYBEAR_MODULUS: u32 = 2_013_265_921;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let fixture = manifest_dir
        .join("../noxis-tree-params/fixtures/poseidon2_babybear_p24_candidate_v1.base64");
    println!("cargo:rerun-if-changed={}", fixture.display());

    let compact: String = fs::read_to_string(&fixture)
        .expect("read frozen P24 fixture")
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let payload = STANDARD.decode(compact).expect("decode frozen P24 fixture");
    assert_eq!(
        payload.len(),
        EXPECTED_LENGTH,
        "unexpected P24 fixture length"
    );
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    assert_eq!(digest, EXPECTED_SHA256, "unexpected P24 fixture checksum");

    let mut generated = String::from("pub const P24_PARAMETERS: [u32; 1899] = [\n");
    for bytes in payload.chunks_exact(4) {
        let value = u32::from_le_bytes(bytes.try_into().expect("fixed chunks"));
        assert!(value < BABYBEAR_MODULUS, "non-canonical P24 field element");
        generated.push_str(&format!("    {value},\n"));
    }
    generated.push_str("];\n");

    let output =
        PathBuf::from(env::var("OUT_DIR").expect("output directory")).join("parameters.rs");
    fs::write(output, generated).expect("write generated P24 parameters");
}
