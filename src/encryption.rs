use anyhow::Result;
use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use futures::stream::Stream;
use hkdf::Hkdf;
use rand::{RngCore, thread_rng};
use sha2::Sha256;
use slatedb::{WriteBatch, config::WriteOptions};
use std::ops::RangeBounds;
use std::pin::Pin;
use std::sync::Arc;

const NONCE_SIZE: usize = 12;
const COMPRESSION_LEVEL: i32 = 3;

pub struct EncryptionManager {
    cipher: ChaCha20Poly1305,
}

impl EncryptionManager {
    pub fn new(master_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, master_key);

        let mut encryption_key = [0u8; 32];

        hk.expand(b"zerofs-v1-encryption", &mut encryption_key)
            .expect("valid length");

        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&encryption_key)),
        }
    }

    pub fn encrypt(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Compress chunks only
        let data = if key.starts_with("chunk:") && plaintext.len() > 100 {
            zstd::encode_all(plaintext, COMPRESSION_LEVEL)?
        } else {
            plaintext.to_vec()
        };

        let ciphertext = self
            .cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Format: [nonce][ciphertext]
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, key: &str, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE {
            return Err(anyhow::anyhow!("Invalid ciphertext: too short"));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let decrypted = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        // Decompress chunks
        if key.starts_with("chunk:") && !decrypted.is_empty() {
            // Check if data was compressed (zstd magic number)
            if decrypted.len() >= 4 && decrypted[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
                zstd::decode_all(&decrypted[..])
                    .map_err(|e| anyhow::anyhow!("Decompression failed: {}", e))
            } else {
                Ok(decrypted)
            }
        } else {
            Ok(decrypted)
        }
    }
}

// Encrypted WriteBatch wrapper
pub struct EncryptedWriteBatch {
    inner: WriteBatch,
    encryptor: Arc<EncryptionManager>,
}

impl EncryptedWriteBatch {
    pub fn new(encryptor: Arc<EncryptionManager>) -> Self {
        Self {
            inner: WriteBatch::new(),
            encryptor,
        }
    }

    pub fn put_bytes(&mut self, key: &bytes::Bytes, value: &[u8]) -> Result<()> {
        let key_str =
            std::str::from_utf8(key).map_err(|e| anyhow::anyhow!("Invalid UTF8 in key: {}", e))?;
        let encrypted = self.encryptor.encrypt(key_str, value)?;
        self.inner.put(key, &encrypted);
        Ok(())
    }

    pub fn delete_bytes(&mut self, key: &bytes::Bytes) {
        self.inner.delete(key);
    }

    pub fn into_inner(self) -> WriteBatch {
        self.inner
    }
}

// Encrypted DB wrapper
pub struct EncryptedDb {
    inner: Arc<slatedb::Db>,
    encryptor: Arc<EncryptionManager>,
}

impl EncryptedDb {
    pub fn new(db: Arc<slatedb::Db>, encryptor: Arc<EncryptionManager>) -> Self {
        Self {
            inner: db,
            encryptor,
        }
    }

    pub async fn get_bytes(&self, key: &bytes::Bytes) -> Result<Option<bytes::Bytes>> {
        match self.inner.get(key).await? {
            Some(encrypted) => {
                let key_str = std::str::from_utf8(key)
                    .map_err(|e| anyhow::anyhow!("Invalid UTF8 in key: {}", e))?;
                let decrypted = self.encryptor.decrypt(key_str, &encrypted)?;
                Ok(Some(bytes::Bytes::from(decrypted)))
            }
            None => Ok(None),
        }
    }

    pub async fn scan<R: RangeBounds<Bytes> + Clone + Send + Sync + 'static>(
        &self,
        range: R,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<(Bytes, Bytes)>> + Send + '_>>> {
        let encryptor = self.encryptor.clone();
        let iter = self.inner.scan(range).await?;

        Ok(Box::pin(futures::stream::unfold(
            (iter, encryptor),
            |(mut iter, encryptor)| async move {
                match iter.next().await {
                    Ok(Some(kv)) => {
                        let key = kv.key;
                        let encrypted_value = kv.value;
                        let key_str = match std::str::from_utf8(&key) {
                            Ok(s) => s,
                            Err(e) => {
                                return Some((
                                    Err(anyhow::anyhow!("Invalid UTF-8 in key: {}", e)),
                                    (iter, encryptor),
                                ));
                            }
                        };
                        match encryptor.decrypt(key_str, &encrypted_value) {
                            Ok(decrypted) => {
                                Some((Ok((key, Bytes::from(decrypted))), (iter, encryptor)))
                            }
                            Err(e) => Some((
                                Err(anyhow::anyhow!(
                                    "Decryption failed for key {}: {}",
                                    key_str,
                                    e
                                )),
                                (iter, encryptor),
                            )),
                        }
                    }
                    Ok(None) => None,
                    Err(e) => Some((
                        Err(anyhow::anyhow!("Iterator error: {}", e)),
                        (iter, encryptor),
                    )),
                }
            },
        )))
    }

    pub async fn write_with_options(
        &self,
        batch: EncryptedWriteBatch,
        options: &WriteOptions,
    ) -> Result<()> {
        self.inner
            .write_with_options(batch.into_inner(), options)
            .await?;
        Ok(())
    }

    pub fn new_write_batch(&self) -> EncryptedWriteBatch {
        EncryptedWriteBatch::new(self.encryptor.clone())
    }

    pub async fn put_with_options(
        &self,
        key: &bytes::Bytes,
        value: &[u8],
        put_options: &slatedb::config::PutOptions,
        write_options: &WriteOptions,
    ) -> Result<()> {
        let key_str =
            std::str::from_utf8(key).map_err(|e| anyhow::anyhow!("Invalid UTF8 in key: {}", e))?;
        let encrypted = self.encryptor.encrypt(key_str, value)?;
        self.inner
            .put_with_options(key, &encrypted, put_options, write_options)
            .await?;
        Ok(())
    }
}
