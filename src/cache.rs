use crate::inode::{Inode, InodeId};
use foyer::{Cache, CacheBuilder};
use std::sync::Arc;

pub const SMALL_FILE_THRESHOLD_BYTES: u64 = 512 * 1024; // 512KB

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct DirEntryCacheKey {
    pub dir_id: InodeId,
    pub name: String,
}

#[derive(Clone)]
pub struct MetadataCache {
    cache: Arc<Cache<InodeId, Arc<Inode>>>,
}

#[derive(Clone)]
pub struct SmallFileCache {
    cache: Arc<Cache<InodeId, Arc<Vec<u8>>>>,
}

#[derive(Clone)]
pub struct DirEntryCache {
    cache: Arc<Cache<DirEntryCacheKey, InodeId>>,
}

impl MetadataCache {
    pub fn new(capacity: usize) -> Self {
        let cache = CacheBuilder::new(capacity).with_shards(64).build();

        Self {
            cache: Arc::new(cache),
        }
    }

    pub fn get(&self, inode_id: &InodeId) -> Option<Arc<Inode>> {
        self.cache.get(inode_id).map(|entry| entry.value().clone())
    }

    pub fn insert(&self, inode_id: InodeId, inode: Arc<Inode>) {
        self.cache.insert(inode_id, inode);
    }

    pub fn remove(&self, inode_id: &InodeId) {
        self.cache.remove(inode_id);
    }
}

impl SmallFileCache {
    pub fn new(capacity_bytes: usize) -> Self {
        let cache = CacheBuilder::new(capacity_bytes)
            .with_shards(64)
            .with_weighter(|_key: &InodeId, value: &Arc<Vec<u8>>| value.capacity())
            .build();

        Self {
            cache: Arc::new(cache),
        }
    }

    pub fn get(&self, inode_id: &InodeId) -> Option<Arc<Vec<u8>>> {
        self.cache.get(inode_id).map(|entry| entry.value().clone())
    }

    pub fn insert(&self, inode_id: InodeId, data: Vec<u8>) {
        // Only cache files under the threshold
        if data.len() <= SMALL_FILE_THRESHOLD_BYTES as usize {
            self.cache.insert(inode_id, Arc::new(data));
        }
    }

    pub fn remove(&self, inode_id: &InodeId) {
        self.cache.remove(inode_id);
    }
}

impl DirEntryCache {
    pub fn new(capacity: usize) -> Self {
        let cache = CacheBuilder::new(capacity).with_shards(64).build();

        Self {
            cache: Arc::new(cache),
        }
    }

    pub fn get(&self, dir_id: InodeId, name: &str) -> Option<InodeId> {
        let key = DirEntryCacheKey {
            dir_id,
            name: name.to_string(),
        };
        self.cache.get(&key).map(|entry| *entry.value())
    }

    pub fn insert(&self, dir_id: InodeId, name: String, inode_id: InodeId) {
        let key = DirEntryCacheKey { dir_id, name };
        self.cache.insert(key, inode_id);
    }

    pub fn remove(&self, dir_id: InodeId, name: &str) {
        let key = DirEntryCacheKey {
            dir_id,
            name: name.to_string(),
        };
        self.cache.remove(&key);
    }
}
