pub mod permit;
pub mod pretty;
pub mod transaction;
pub mod viewing_keys;

use sha2::{Digest, Sha256};

pub const SHA256_HASH_SIZE: usize = 32;

pub fn sha_256(data: &[u8]) -> [u8; SHA256_HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_slice());
    result
}
