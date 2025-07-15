use nfsserve::nfs::{fileid3, nfsstat3};
use nfsserve::vfs::AuthContext;
use slatedb::{WriteBatch, config::WriteOptions};

use crate::filesystem::{CHUNK_SIZE, SlateDbFs, get_current_time};
use crate::inode::Inode;
use crate::permissions::{
    AccessMode, Credentials, check_access, check_sticky_bit_delete,
};
use super::common::validate_filename;

impl SlateDbFs {
    pub async fn process_remove(
        &self,
        auth: &AuthContext,
        dirid: fileid3,
        filename: &[u8],
    ) -> Result<(), nfsstat3> {
        validate_filename(filename)?;

        let name = String::from_utf8_lossy(filename).to_string();
        let creds = Credentials::from_auth_context(auth);

        let dir_lock = self.get_inode_lock(dirid);
        let _dir_guard = dir_lock.write().await;

        let dir_inode = self.load_inode(dirid).await?;
        check_access(&dir_inode, &creds, AccessMode::Write)?;
        check_access(&dir_inode, &creds, AccessMode::Execute)?;

        let is_dir = matches!(dir_inode, Inode::Directory(_));
        if !is_dir {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        }

        let entry_key = Self::dir_entry_key(dirid, &name);
        let entry_data = self
            .db
            .get(&entry_key)
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .ok_or(nfsstat3::NFS3ERR_NOENT)?;

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&entry_data[..8]);
        let file_id = u64::from_le_bytes(bytes);

        drop(_dir_guard);

        let mut inodes_to_lock = vec![dirid, file_id];
        inodes_to_lock.sort();
        inodes_to_lock.dedup(); // In case dirid == file_id somehow

        let locks: Vec<_> = inodes_to_lock
            .iter()
            .map(|&id| self.get_inode_lock(id))
            .collect();

        let mut _guards = Vec::new();
        for lock in &locks {
            _guards.push(lock.write().await);
        }

        // Re-verify the entry still exists after acquiring locks
        let entry_data = self
            .db
            .get(&entry_key)
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .ok_or(nfsstat3::NFS3ERR_NOENT)?;

        let mut verify_bytes = [0u8; 8];
        verify_bytes.copy_from_slice(&entry_data[..8]);
        let verify_file_id = u64::from_le_bytes(verify_bytes);

        if verify_file_id != file_id {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }

        // Re-load inodes after acquiring locks
        let dir_inode = self.load_inode(dirid).await?;
        let mut file_inode = self.load_inode(file_id).await?;

        check_sticky_bit_delete(&dir_inode, &file_inode, &creds)?;

        let mut dir_inode = self.load_inode(dirid).await?;

        match &mut dir_inode {
            Inode::Directory(dir) => {
                let mut batch = WriteBatch::new();

                match &mut file_inode {
                    Inode::File(file) => {
                        // Check if this is the last hard link
                        if file.nlink > 1 {
                            // Just decrement the link count, don't delete the file
                            file.nlink -= 1;
                            let (now_sec, now_nsec) = get_current_time();
                            file.ctime = now_sec;
                            file.ctime_nsec = now_nsec;

                            let inode_key = Self::inode_key(file_id);
                            let inode_data = bincode::serialize(&file_inode)
                                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
                            batch.put(inode_key, &inode_data);
                        } else {
                            // Last link, delete all data chunks
                            let total_chunks = file.size.div_ceil(CHUNK_SIZE as u64) as usize;
                            for chunk_idx in 0..total_chunks {
                                let chunk_key = Self::chunk_key_by_index(file_id, chunk_idx);
                                batch.delete(chunk_key);
                            }
                            // Delete the inode
                            let inode_key = Self::inode_key(file_id);
                            batch.delete(inode_key);
                        }
                    }
                    Inode::Directory(subdir) => {
                        if subdir.entry_count > 0 {
                            return Err(nfsstat3::NFS3ERR_NOTEMPTY);
                        }
                        // Delete the directory inode
                        let inode_key = Self::inode_key(file_id);
                        batch.delete(inode_key);
                    }
                    Inode::Symlink(_) => {
                        // Delete the symlink inode
                        let inode_key = Self::inode_key(file_id);
                        batch.delete(inode_key);
                    }
                    Inode::Fifo(special)
                    | Inode::Socket(special)
                    | Inode::CharDevice(special)
                    | Inode::BlockDevice(special) => {
                        // Check if this is the last hard link
                        if special.nlink > 1 {
                            // Just decrement the link count, don't delete the inode
                            special.nlink -= 1;
                            let (now_sec, now_nsec) = get_current_time();
                            special.ctime = now_sec;
                            special.ctime_nsec = now_nsec;

                            let inode_key = Self::inode_key(file_id);
                            let inode_data = bincode::serialize(&file_inode)
                                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
                            batch.put(inode_key, &inode_data);
                        } else {
                            // Last link, delete the inode
                            let inode_key = Self::inode_key(file_id);
                            batch.delete(inode_key);
                        }
                    }
                }

                batch.delete(entry_key);

                let scan_key = Self::dir_scan_key(dirid, file_id, &name);
                batch.delete(scan_key);

                dir.entry_count = dir.entry_count.saturating_sub(1);
                let (now_sec, now_nsec) = get_current_time();
                dir.mtime = now_sec;
                dir.mtime_nsec = now_nsec;
                dir.ctime = now_sec;
                dir.ctime_nsec = now_nsec;

                let dir_key = Self::inode_key(dirid);
                let dir_data = bincode::serialize(&dir_inode).map_err(|_| nfsstat3::NFS3ERR_IO)?;
                batch.put(dir_key, &dir_data);

                self.db
                    .write_with_options(
                        batch,
                        &WriteOptions {
                            await_durable: false,
                        },
                    )
                    .await
                    .map_err(|_| nfsstat3::NFS3ERR_IO)?;

                Ok(())
            }
            _ => Err(nfsstat3::NFS3ERR_NOTDIR),
        }
    }
}