use base64::Engine;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotResponse {
    pub status_code: u16,
    pub content_type: &'static str,
    pub body: String,
}

pub(crate) fn pkcs8_rsa_pem(rng: &mut DecoyRng) -> String {
    // Deliberately non-functional RSA parameters: parsable PKCS#8 framing,
    // but no key pair that can authenticate to a provider.
    let version = [0u8];
    let modulus = random_positive(rng, 256);
    let exponent = [0x01, 0x00, 0x01];
    let private_exponent = random_positive(rng, 256);
    let prime_one = random_positive(rng, 128);
    let prime_two = random_positive(rng, 128);
    let exponent_one = random_positive(rng, 128);
    let exponent_two = random_positive(rng, 128);
    let coefficient = random_positive(rng, 128);
    let mut rsa = Vec::new();
    rsa.extend(der(0x02, &version));
    rsa.extend(der(0x02, &modulus));
    rsa.extend(der(0x02, &exponent));
    rsa.extend(der(0x02, &private_exponent));
    rsa.extend(der(0x02, &prime_one));
    rsa.extend(der(0x02, &prime_two));
    rsa.extend(der(0x02, &exponent_one));
    rsa.extend(der(0x02, &exponent_two));
    rsa.extend(der(0x02, &coefficient));
    let rsa = der(0x30, &rsa);
    let algorithm_oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let mut algorithm = Vec::new();
    algorithm.extend_from_slice(&algorithm_oid);
    algorithm.extend_from_slice(&[0x05, 0x00]);
    let algorithm = der(0x30, &algorithm);
    let mut outer = Vec::new();
    outer.extend(der(0x02, &version));
    outer.extend(algorithm);
    outer.extend(der(0x04, &rsa));
    let pkcs8 = der(0x30, &outer);
    let encoded = base64::engine::general_purpose::STANDARD.encode(pkcs8);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut bytes = Vec::new();
    let mut value = length;
    while value > 0 {
        bytes.insert(0, (value & 0xff) as u8);
        value >>= 8;
    }
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(0x80 | bytes.len() as u8);
    out.extend(bytes);
    out
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    out.extend(der_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn random_positive(rng: &mut DecoyRng, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes);
    bytes[0] = (bytes[0] | 0x01) & 0x7f;
    bytes
}

static DECOY_NONCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct DecoyRng {
    state: u64,
}

impl DecoyRng {
    pub(crate) fn new() -> Self {
        let counter = DECOY_NONCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0);
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(counter);
        hasher.write_u64(nanos);
        hasher.write_u64(u64::from(std::process::id()));
        Self {
            state: hasher.finish(),
        }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    pub(crate) fn fill(&mut self, buffer: &mut [u8]) {
        for chunk in buffer.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let length = chunk.len();
            chunk.copy_from_slice(&bytes[..length]);
        }
    }

    pub(crate) fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }
}
