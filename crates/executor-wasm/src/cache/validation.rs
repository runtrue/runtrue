use runtrue_model::ContentDigest;
use sha2::{Digest as _, Sha256};
use std::hash::{Hash as _, Hasher};
use wasmtime::Engine;

pub(crate) fn engine_compatibility_digest(engine: &Engine) -> ContentDigest {
    let mut hasher = Sha256HashWriter::default();
    engine.precompile_compatibility_hash().hash(&mut hasher);
    ContentDigest::sha256(hasher.into_bytes())
}

#[derive(Default)]
struct Sha256HashWriter(Sha256);

impl Sha256HashWriter {
    fn into_bytes(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl Hasher for Sha256HashWriter {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}
