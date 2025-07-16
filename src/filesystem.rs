use crate::cache::{DirEntryCache, MetadataCache, SmallFileCache};
use crate::encryption::{EncryptedDb, EncryptionManager};
use crate::lock_manager::LockManager;
use bytes::Bytes;
use nfsserve::nfs::nfsstat3;
use object_store::aws::{AmazonS3Builder, S3ConditionalPut};
use slatedb::config::ObjectStoreCacheOptions;
use slatedb::db_cache::foyer::{FoyerCache, FoyerCacheOptions};
use slatedb::object_store::{ObjectStore, path::Path};
use slatedb::{
    DbBuilder,
    config::{PutOptions, WriteOptions},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::inode::{DirectoryInode, Inode, InodeId};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
fn get_current_uid_gid() -> (u32, u32) {
    unsafe { (libc::getuid(), libc::getgid()) }
}

#[cfg(not(unix))]
fn get_current_uid_gid() -> (u32, u32) {
    (0, 0)
}

pub fn get_current_time() -> (u64, u32) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs(), now.subsec_nanos())
}

pub const CHUNK_SIZE: usize = 64 * 1024;
pub const LOCK_SHARD_COUNT: usize = 1024 * 100;

#[derive(Clone)]
pub struct SlateDbFs {
    pub db: Arc<EncryptedDb>,
    pub lock_manager: Arc<LockManager>,
    pub next_inode_id: Arc<AtomicU64>,
    pub metadata_cache: Arc<MetadataCache>,
    pub small_file_cache: Arc<SmallFileCache>,
    pub dir_entry_cache: Arc<DirEntryCache>,
}

// Struct for temporary unencrypted access (only for key management)
// Only use for initial key setup and password changes
pub struct DangerousUnencryptedSlateDbFs {
    pub db: Arc<slatedb::Db>,
}

#[derive(Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket_name: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
    pub allow_http: bool,
}

#[derive(Clone)]
pub struct CacheConfig {
    pub root_folder: String,
    pub max_cache_size_gb: f64,
}

impl SlateDbFs {
    pub async fn new_with_s3(
        s3_config: S3Config,
        cache_config: CacheConfig,
        db_path: String,
        encryption_key: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&s3_config.bucket_name)
            .with_region(&s3_config.region)
            .with_allow_http(s3_config.allow_http)
            .with_conditional_put(S3ConditionalPut::ETagMatch);

        if !s3_config.access_key_id.is_empty() {
            builder = builder.with_access_key_id(&s3_config.access_key_id);
        }

        if !s3_config.secret_access_key.is_empty() {
            builder = builder.with_secret_access_key(s3_config.secret_access_key);
        }

        if !s3_config.endpoint.is_empty() {
            builder = builder.with_endpoint(&s3_config.endpoint);
        }

        let object_store = builder.build()?;
        let object_store: Arc<dyn ObjectStore> = Arc::new(object_store);

        let cache_size_bytes = (cache_config.max_cache_size_gb * 1_000_000_000.0) as usize;

        let settings = slatedb::config::Settings {
            object_store_cache_options: ObjectStoreCacheOptions {
                root_folder: Some(cache_config.root_folder.into()),
                max_cache_size_bytes: Some(cache_size_bytes),
                ..Default::default()
            },
            compactor_options: Some(slatedb::config::CompactorOptions {
                max_concurrent_compactions: 16,
                ..Default::default()
            }),
            compression_codec: None, // Disable compression - we handle it in encryption layer
            ..Default::default()
        };

        let cache = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
            max_capacity: 10_000u64,
        }));

        let db_path = Path::from(db_path);
        let slatedb = Arc::new(
            DbBuilder::new(db_path, object_store)
                .with_settings(settings)
                .with_block_cache(cache)
                .build()
                .await?,
        );

        let encryptor = Arc::new(EncryptionManager::new(&encryption_key));
        let db = Arc::new(EncryptedDb::new(slatedb.clone(), encryptor));

        let counter_key = Self::counter_key();
        let next_inode_id = match db.get_bytes(&counter_key).await? {
            Some(data) => {
                let bytes: [u8; 8] = data[..8].try_into().map_err(|_| "Invalid counter data")?;
                u64::from_le_bytes(bytes)
            }
            None => 1,
        };

        let root_inode_key = Self::inode_key(0);
        if db.get_bytes(&root_inode_key).await?.is_none() {
            let (uid, gid) = get_current_uid_gid();
            let (now_sec, now_nsec) = get_current_time();
            let root_dir = DirectoryInode {
                mtime: now_sec,
                mtime_nsec: now_nsec,
                ctime: now_sec,
                ctime_nsec: now_nsec,
                atime: now_sec,
                atime_nsec: now_nsec,
                mode: 0o1777,
                uid,
                gid,
                entry_count: 0,
                parent: 0,
                nlink: 2, // . and ..
            };
            let serialized = bincode::serialize(&Inode::Directory(root_dir))?;
            db.put_with_options(
                &root_inode_key,
                &serialized,
                &PutOptions::default(),
                &WriteOptions {
                    await_durable: false,
                },
            )
            .await?;
        }

        let lock_manager = Arc::new(LockManager::new(LOCK_SHARD_COUNT));
        let metadata_cache = Arc::new(MetadataCache::new(10_000)); // 10k metadata entries
        let small_file_cache = Arc::new(SmallFileCache::new(100 * 1024 * 1024)); // 100MB for small files
        let dir_entry_cache = Arc::new(DirEntryCache::new(50_000)); // 50k directory entries

        let fs = Self {
            db: db.clone(),
            lock_manager,
            next_inode_id: Arc::new(AtomicU64::new(next_inode_id)),
            metadata_cache,
            small_file_cache,
            dir_entry_cache,
        };

        Ok(fs)
    }

    pub fn inode_key(inode_id: InodeId) -> Bytes {
        Bytes::from(format!("inode:{inode_id}"))
    }

    pub fn chunk_key_by_index(inode_id: InodeId, chunk_index: usize) -> Bytes {
        Bytes::from(format!("chunk:{inode_id}/{chunk_index}"))
    }

    pub fn counter_key() -> Bytes {
        Bytes::from("system:next_inode_id")
    }

    pub fn dir_entry_key(dir_inode_id: InodeId, name: &str) -> Bytes {
        Bytes::from(format!("direntry:{dir_inode_id}/{name}"))
    }

    pub fn dir_scan_key(dir_inode_id: InodeId, entry_inode_id: InodeId, name: &str) -> Bytes {
        Bytes::from(format!(
            "dirscan:{dir_inode_id}/{entry_inode_id:020}/{name}",
        ))
    }

    pub fn dir_scan_prefix(dir_inode_id: InodeId) -> String {
        format!("dirscan:{dir_inode_id}/")
    }

    pub async fn allocate_inode(&self) -> Result<InodeId, nfsstat3> {
        let id = self.next_inode_id.fetch_add(1, Ordering::SeqCst);
        Ok(id)
    }

    pub async fn load_inode(&self, inode_id: InodeId) -> Result<Inode, nfsstat3> {
        if let Some(cached_inode) = self.metadata_cache.get(&inode_id) {
            return Ok((*cached_inode).clone());
        }

        let key = Self::inode_key(inode_id);
        let data = self
            .db
            .get_bytes(&key)
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .ok_or(nfsstat3::NFS3ERR_NOENT)?;

        let inode: Inode = bincode::deserialize(&data).map_err(|_| nfsstat3::NFS3ERR_IO)?;

        self.metadata_cache
            .insert(inode_id, Arc::new(inode.clone()));

        Ok(inode)
    }

    pub async fn save_inode(&self, inode_id: InodeId, inode: &Inode) -> Result<(), nfsstat3> {
        let key = Self::inode_key(inode_id);
        let data = bincode::serialize(inode).map_err(|_| nfsstat3::NFS3ERR_IO)?;

        self.db
            .put_with_options(
                &key,
                &data,
                &PutOptions::default(),
                &WriteOptions {
                    await_durable: false,
                },
            )
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;

        self.metadata_cache.remove(&inode_id);

        if let Inode::File(file) = inode {
            if file.size <= crate::cache::SMALL_FILE_THRESHOLD_BYTES {
                self.small_file_cache.remove(&inode_id);
            }
        }

        Ok(())
    }

    #[cfg(test)]
    pub async fn new_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        // Use a fixed test key for in-memory tests
        let test_key = [0u8; 32];
        Self::new_in_memory_with_encryption(test_key).await
    }

    #[cfg(test)]
    pub async fn new_in_memory_with_encryption(
        encryption_key: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let object_store = slatedb::object_store::memory::InMemory::new();
        let object_store: Arc<dyn ObjectStore> = Arc::new(object_store);

        let settings = slatedb::config::Settings {
            compression_codec: None, // Disable compression - we handle it in encryption layer
            compactor_options: Some(slatedb::config::CompactorOptions {
                max_concurrent_compactions: 32,
                ..Default::default()
            }),
            ..Default::default()
        };

        let cache = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
            max_capacity: 500_000,
        }));

        let db_path = Path::from("test_slatedb");
        let slatedb = Arc::new(
            DbBuilder::new(db_path, object_store)
                .with_settings(settings)
                .with_block_cache(cache)
                .build()
                .await?,
        );

        let encryptor = Arc::new(EncryptionManager::new(&encryption_key));
        let db = Arc::new(EncryptedDb::new(slatedb.clone(), encryptor));

        let next_inode_id = 1;

        let root_inode_key = Self::inode_key(0);
        if db.get_bytes(&root_inode_key).await?.is_none() {
            let (uid, gid) = get_current_uid_gid();
            let (now_sec, now_nsec) = get_current_time();
            let root_dir = DirectoryInode {
                mtime: now_sec,
                mtime_nsec: now_nsec,
                ctime: now_sec,
                ctime_nsec: now_nsec,
                atime: now_sec,
                atime_nsec: now_nsec,
                mode: 0o1777,
                uid,
                gid,
                entry_count: 0,
                parent: 0,
                nlink: 2, // . and ..
            };
            let serialized = bincode::serialize(&Inode::Directory(root_dir))?;
            db.put_with_options(
                &root_inode_key,
                &serialized,
                &PutOptions::default(),
                &WriteOptions {
                    await_durable: false,
                },
            )
            .await?;
        }

        let lock_manager = Arc::new(LockManager::new(LOCK_SHARD_COUNT));
        let metadata_cache = Arc::new(MetadataCache::new(10_000)); // 10k metadata entries
        let small_file_cache = Arc::new(SmallFileCache::new(100 * 1024 * 1024)); // 100MB for small files
        let dir_entry_cache = Arc::new(DirEntryCache::new(50_000)); // 50k directory entries

        let fs = Self {
            db: db.clone(),
            lock_manager,
            next_inode_id: Arc::new(AtomicU64::new(next_inode_id)),
            metadata_cache,
            small_file_cache,
            dir_entry_cache,
        };

        Ok(fs)
    }
}

impl SlateDbFs {
    /// DANGEROUS: Creates an unencrypted database connection. Only use for key management!
    pub async fn dangerous_new_with_s3_unencrypted_for_key_management_only(
        s3_config: S3Config,
        cache_config: CacheConfig,
        db_path: String,
    ) -> Result<DangerousUnencryptedSlateDbFs, Box<dyn std::error::Error>> {
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&s3_config.bucket_name)
            .with_region(&s3_config.region)
            .with_access_key_id(&s3_config.access_key_id)
            .with_secret_access_key(&s3_config.secret_access_key)
            .with_allow_http(s3_config.allow_http)
            .with_conditional_put(S3ConditionalPut::ETagMatch);

        if !s3_config.endpoint.is_empty() {
            builder = builder.with_endpoint(&s3_config.endpoint);
        }

        let object_store = builder.build()?;
        let object_store: Arc<dyn ObjectStore> = Arc::new(object_store);

        let cache_size_bytes = (cache_config.max_cache_size_gb * 1_000_000_000.0) as usize;

        let settings = slatedb::config::Settings {
            object_store_cache_options: ObjectStoreCacheOptions {
                root_folder: Some(cache_config.root_folder.into()),
                max_cache_size_bytes: Some(cache_size_bytes),
                ..Default::default()
            },
            compactor_options: Some(slatedb::config::CompactorOptions {
                max_concurrent_compactions: 16,
                ..Default::default()
            }),
            compression_codec: None, // Disable compression - we handle it in encryption layer
            ..Default::default()
        };

        let cache = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
            max_capacity: cache_size_bytes as u64,
        }));

        let slatedb = Arc::new(
            DbBuilder::new(Path::from(db_path), object_store)
                .with_settings(settings)
                .with_block_cache(cache)
                .build()
                .await?,
        );

        Ok(DangerousUnencryptedSlateDbFs { db: slatedb })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::FileInode;

    #[tokio::test]
    async fn test_create_filesystem() {
        let fs = SlateDbFs::new_in_memory().await.unwrap();

        let root_inode = fs.load_inode(0).await.unwrap();
        match root_inode {
            Inode::Directory(dir) => {
                assert_eq!(dir.mode, 0o1777);
                let (expected_uid, expected_gid) = get_current_uid_gid();
                assert_eq!(dir.uid, expected_uid);
                assert_eq!(dir.gid, expected_gid);
                assert_eq!(dir.entry_count, 0);
            }
            _ => panic!("Root should be a directory"),
        }
    }

    #[tokio::test]
    async fn test_allocate_inode() {
        let fs = SlateDbFs::new_in_memory().await.unwrap();

        let inode1 = fs.allocate_inode().await.unwrap();
        let inode2 = fs.allocate_inode().await.unwrap();
        let inode3 = fs.allocate_inode().await.unwrap();

        assert_ne!(inode1, 0);
        assert_ne!(inode2, 0);
        assert_ne!(inode3, 0);
        assert_ne!(inode1, inode2);
        assert_ne!(inode2, inode3);
        assert_ne!(inode1, inode3);
    }

    #[tokio::test]
    async fn test_save_and_load_inode() {
        let fs = SlateDbFs::new_in_memory().await.unwrap();

        let file_inode = FileInode {
            size: 1024,
            mtime: 1234567890,
            mtime_nsec: 123456789,
            ctime: 1234567891,
            ctime_nsec: 234567890,
            atime: 1234567892,
            atime_nsec: 345678901,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            parent: 0,
            nlink: 1,
        };

        let inode = Inode::File(file_inode.clone());
        let inode_id = fs.allocate_inode().await.unwrap();

        fs.save_inode(inode_id, &inode).await.unwrap();

        let loaded_inode = fs.load_inode(inode_id).await.unwrap();
        match loaded_inode {
            Inode::File(f) => {
                assert_eq!(f.size, file_inode.size);
                assert_eq!(f.mtime, file_inode.mtime);
                assert_eq!(f.ctime, file_inode.ctime);
                assert_eq!(f.mode, file_inode.mode);
                assert_eq!(f.uid, file_inode.uid);
                assert_eq!(f.gid, file_inode.gid);
            }
            _ => panic!("Expected File inode"),
        }
    }

    #[tokio::test]
    async fn test_inode_key_generation() {
        assert_eq!(SlateDbFs::inode_key(0), Bytes::from("inode:0"));
        assert_eq!(SlateDbFs::inode_key(42), Bytes::from("inode:42"));
        assert_eq!(SlateDbFs::inode_key(999), Bytes::from("inode:999"));
    }

    #[tokio::test]
    async fn test_chunk_key_generation() {
        assert_eq!(
            SlateDbFs::chunk_key_by_index(1, 0),
            Bytes::from("chunk:1/0")
        );
        assert_eq!(
            SlateDbFs::chunk_key_by_index(42, 10),
            Bytes::from("chunk:42/10")
        );
        assert_eq!(
            SlateDbFs::chunk_key_by_index(999, 999),
            Bytes::from("chunk:999/999")
        );
    }

    #[tokio::test]
    async fn test_load_nonexistent_inode() {
        let fs = SlateDbFs::new_in_memory().await.unwrap();

        let result = fs.load_inode(999).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));
    }
}
