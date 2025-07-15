use crate::inode::InodeId;
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Clone)]
pub struct LockManager {
    locks: Arc<Vec<Arc<RwLock<()>>>>,
    shard_count: usize,
}

/// Guards that automatically release locks when dropped
pub enum LockGuard<'a> {
    Read { _guard: RwLockReadGuard<'a, ()> },
    Write { _guard: RwLockWriteGuard<'a, ()> },
}

/// Holds multiple lock guards, ensuring they're released in reverse order
pub struct MultiLockGuard<'a> {
    _guards: Vec<LockGuard<'a>>,
}

impl LockManager {
    pub fn new(shard_count: usize) -> Self {
        let locks = (0..shard_count)
            .map(|_| Arc::new(RwLock::new(())))
            .collect();

        Self {
            locks: Arc::new(locks),
            shard_count,
        }
    }

    /// Get the lock for a given inode ID
    fn get_lock(&self, inode_id: InodeId) -> &RwLock<()> {
        let shard = (inode_id as usize) % self.shard_count;
        &self.locks[shard]
    }

    /// Acquire a single lock for reading
    pub async fn acquire_read(&self, inode_id: InodeId) -> LockGuard<'_> {
        let lock = self.get_lock(inode_id);
        LockGuard::Read {
            _guard: lock.read().await,
        }
    }

    /// Acquire a single lock for writing
    pub async fn acquire_write(&self, inode_id: InodeId) -> LockGuard<'_> {
        let lock = self.get_lock(inode_id);
        LockGuard::Write {
            _guard: lock.write().await,
        }
    }

    /// Acquire multiple write locks with automatic ordering to prevent deadlocks.
    pub async fn acquire_multiple_write<'a>(
        &'a self,
        mut inode_ids: Vec<InodeId>,
    ) -> MultiLockGuard<'a> {
        // Sort by inode ID to ensure consistent ordering
        inode_ids.sort();
        inode_ids.dedup();

        // Acquire one lock per inode
        let mut guards = Vec::with_capacity(inode_ids.len());

        for inode_id in inode_ids {
            let lock = self.get_lock(inode_id);
            guards.push(LockGuard::Write {
                _guard: lock.write().await,
            });
        }

        MultiLockGuard { _guards: guards }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_single_lock_acquisition() {
        let manager = LockManager::new(1024);

        let guard1 = manager.acquire_write(1).await;
        assert!(matches!(guard1, LockGuard::Write { .. }));
        drop(guard1);

        let guard2 = manager.acquire_read(1).await;
        assert!(matches!(guard2, LockGuard::Read { .. }));
    }

    #[tokio::test]
    async fn test_multiple_lock_ordering() {
        let manager = LockManager::new(1024);

        let guard1 = manager.acquire_multiple_write(vec![3, 1, 2]).await;
        drop(guard1);

        let _guard2 = manager.acquire_multiple_write(vec![2, 3, 1]).await;
    }

    #[tokio::test]
    async fn test_shard_collision_behavior() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let manager = Arc::new(LockManager::new(1)); // Only one shard

        let _guard1 = manager.acquire_write(0).await;

        let manager2 = manager.clone();
        let acquired = Arc::new(AtomicBool::new(false));
        let acquired2 = acquired.clone();

        let handle = tokio::spawn(async move {
            let _guard = manager2.acquire_write(1).await;
            acquired2.store(true, Ordering::SeqCst);
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert!(
            !acquired.load(Ordering::SeqCst),
            "Should be blocked due to shard collision"
        );

        drop(_guard1);

        handle.await.unwrap();

        assert!(
            acquired.load(Ordering::SeqCst),
            "Should have acquired after first lock released"
        );
    }
}
