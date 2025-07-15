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

/// A guard for a shard lock that tracks how many inodes it represents
struct ShardLockGuard<'a> {
    shard: usize,
    inode_count: usize,
    _guard: LockGuard<'a>,
}

/// Holds multiple lock guards and tracks which inodes are locked
pub struct MultiLockGuard<'a> {
    guards: Vec<ShardLockGuard<'a>>,
    locked_inodes: Vec<InodeId>,
}

impl<'a> MultiLockGuard<'a> {
    /// Check if a specific inode is locked by this guard
    pub fn has_locked(&self, inode_id: InodeId) -> bool {
        self.locked_inodes.binary_search(&inode_id).is_ok()
    }

    /// Get the list of locked inodes
    pub fn locked_inodes(&self) -> &[InodeId] {
        &self.locked_inodes
    }

    /// Get the number of unique shards locked
    pub fn shard_count(&self) -> usize {
        self.guards.len()
    }

    /// Get total number of inodes represented across all shards
    pub fn total_inode_count(&self) -> usize {
        self.guards.iter().map(|g| g.inode_count).sum()
    }

    /// Debug information about which shards are locked and their inode counts
    pub fn shard_info(&self) -> Vec<(usize, usize)> {
        self.guards
            .iter()
            .map(|g| (g.shard, g.inode_count))
            .collect()
    }
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

        let locked_inodes = inode_ids.clone();

        let mut shard_to_inodes: Vec<(usize, Vec<InodeId>)> = Vec::new();

        for inode_id in inode_ids {
            let shard = (inode_id as usize) % self.shard_count;

            if let Some((_, inodes)) = shard_to_inodes.iter_mut().find(|(s, _)| *s == shard) {
                inodes.push(inode_id);
            } else {
                shard_to_inodes.push((shard, vec![inode_id]));
            }
        }

        // Sort by shard to ensure consistent ordering
        shard_to_inodes.sort_by_key(|(shard, _)| *shard);

        let mut guards = Vec::with_capacity(shard_to_inodes.len());

        for (shard, inodes) in shard_to_inodes {
            let lock = &self.locks[shard];
            let guard = LockGuard::Write {
                _guard: lock.write().await,
            };

            guards.push(ShardLockGuard {
                shard,
                inode_count: inodes.len(),
                _guard: guard,
            });
        }

        MultiLockGuard {
            guards,
            locked_inodes,
        }
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

    #[tokio::test]
    async fn test_no_self_deadlock_same_shard() {
        let manager = LockManager::new(4); // Small shard count

        // Inodes 0, 4, 8 all map to shard 0
        // Without shard grouping, this would deadlock trying to acquire the same lock 3 times
        // With shard grouping, we only acquire shard 0's lock once
        let _guard = manager.acquire_multiple_write(vec![0, 4, 8]).await;

        // Should complete successfully
        assert!(
            true,
            "Successfully acquired multiple inodes mapping to same shard"
        );
    }

    #[tokio::test]
    async fn test_lock_tracking() {
        let manager = LockManager::new(4);

        // Lock inodes 0, 1, 4, 5
        let guard = manager.acquire_multiple_write(vec![0, 1, 4, 5]).await;

        // Verify all inodes are tracked as locked
        assert!(guard.has_locked(0));
        assert!(guard.has_locked(1));
        assert!(guard.has_locked(4));
        assert!(guard.has_locked(5));

        // Verify inodes we didn't lock are not tracked
        assert!(!guard.has_locked(2));
        assert!(!guard.has_locked(3));

        // Verify the locked_inodes list
        assert_eq!(guard.locked_inodes(), &[0, 1, 4, 5]);

        // Verify shard tracking
        assert_eq!(guard.shard_count(), 2); // Shards 0 and 1
        assert_eq!(guard.total_inode_count(), 4); // 4 inodes total

        // Verify shard info: inodes 0,4 map to shard 0; inodes 1,5 map to shard 1
        let shard_info = guard.shard_info();
        assert_eq!(shard_info.len(), 2);
        // Should have 2 inodes in each shard
        assert!(shard_info.iter().all(|(_, count)| *count == 2));
    }
}
