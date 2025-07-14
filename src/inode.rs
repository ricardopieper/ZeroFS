use nfsserve::nfs::{fattr3, ftype3, nfstime3, specdata3};
use serde::{Deserialize, Serialize};

pub type InodeId = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInode {
    pub size: u64,
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub ctime: u64,
    pub ctime_nsec: u32,
    pub atime: u64,
    pub atime_nsec: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub parent: InodeId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryInode {
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub ctime: u64,
    pub ctime_nsec: u32,
    pub atime: u64,
    pub atime_nsec: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub entry_count: u64,
    pub parent: InodeId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymlinkInode {
    pub target: Vec<u8>,
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub ctime: u64,
    pub ctime_nsec: u32,
    pub atime: u64,
    pub atime_nsec: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub parent: InodeId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Inode {
    File(FileInode),
    Directory(DirectoryInode),
    Symlink(SymlinkInode),
}

impl Inode {
    pub fn to_fattr3(&self, inode_id: InodeId) -> fattr3 {
        match self {
            Inode::File(file) => fattr3 {
                ftype: ftype3::NF3REG,
                mode: file.mode,
                nlink: 1,
                uid: file.uid,
                gid: file.gid,
                size: file.size,
                used: file.size,
                rdev: specdata3 {
                    specdata1: 0,
                    specdata2: 0,
                },
                fsid: 0,
                fileid: inode_id,
                atime: nfstime3 {
                    seconds: (file.atime & 0xFFFFFFFF) as u32,
                    nseconds: file.atime_nsec,
                },
                mtime: nfstime3 {
                    seconds: (file.mtime & 0xFFFFFFFF) as u32,
                    nseconds: file.mtime_nsec,
                },
                ctime: nfstime3 {
                    seconds: (file.ctime & 0xFFFFFFFF) as u32,
                    nseconds: file.ctime_nsec,
                },
            },
            Inode::Directory(dir) => fattr3 {
                ftype: ftype3::NF3DIR,
                mode: dir.mode,
                nlink: 2,
                uid: dir.uid,
                gid: dir.gid,
                size: 4096,
                used: 4096,
                rdev: specdata3 {
                    specdata1: 0,
                    specdata2: 0,
                },
                fsid: 0,
                fileid: inode_id,
                atime: nfstime3 {
                    seconds: (dir.atime & 0xFFFFFFFF) as u32,
                    nseconds: dir.atime_nsec,
                },
                mtime: nfstime3 {
                    seconds: (dir.mtime & 0xFFFFFFFF) as u32,
                    nseconds: dir.mtime_nsec,
                },
                ctime: nfstime3 {
                    seconds: (dir.ctime & 0xFFFFFFFF) as u32,
                    nseconds: dir.ctime_nsec,
                },
            },
            Inode::Symlink(symlink) => fattr3 {
                ftype: ftype3::NF3LNK,
                mode: symlink.mode,
                nlink: 1,
                uid: symlink.uid,
                gid: symlink.gid,
                size: symlink.target.len() as u64,
                used: symlink.target.len() as u64,
                rdev: specdata3 {
                    specdata1: 0,
                    specdata2: 0,
                },
                fsid: 0,
                fileid: inode_id,
                atime: nfstime3 {
                    seconds: (symlink.atime & 0xFFFFFFFF) as u32,
                    nseconds: symlink.atime_nsec,
                },
                mtime: nfstime3 {
                    seconds: (symlink.mtime & 0xFFFFFFFF) as u32,
                    nseconds: symlink.mtime_nsec,
                },
                ctime: nfstime3 {
                    seconds: (symlink.ctime & 0xFFFFFFFF) as u32,
                    nseconds: symlink.ctime_nsec,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_inode_to_fattr3() {
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
        };

        let inode = Inode::File(file_inode);
        let fattr = inode.to_fattr3(42);

        assert!(matches!(fattr.ftype, ftype3::NF3REG));
        assert_eq!(fattr.mode, 0o644);
        assert_eq!(fattr.size, 1024);
        assert_eq!(fattr.uid, 1000);
        assert_eq!(fattr.gid, 1000);
        assert_eq!(fattr.fileid, 42);
        assert_eq!(fattr.mtime.seconds, 1234567890);
        assert_eq!(fattr.ctime.seconds, 1234567891);
    }

    #[test]
    fn test_directory_inode_to_fattr3() {
        let dir_inode = DirectoryInode {
            mtime: 1234567890,
            mtime_nsec: 123456789,
            ctime: 1234567891,
            ctime_nsec: 234567890,
            atime: 1234567892,
            atime_nsec: 345678901,
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            entry_count: 2,
            parent: 0,
        };

        let inode = Inode::Directory(dir_inode);
        let fattr = inode.to_fattr3(1);

        assert!(matches!(fattr.ftype, ftype3::NF3DIR));
        assert_eq!(fattr.mode, 0o755);
        assert_eq!(fattr.size, 4096);
        assert_eq!(fattr.uid, 1000);
        assert_eq!(fattr.gid, 1000);
        assert_eq!(fattr.fileid, 1);
        assert_eq!(fattr.nlink, 2);
    }

    #[test]
    fn test_symlink_inode_to_fattr3() {
        let symlink_inode = SymlinkInode {
            target: b"/path/to/target".to_vec(),
            mtime: 1234567890,
            mtime_nsec: 123456789,
            ctime: 1234567891,
            ctime_nsec: 234567890,
            atime: 1234567892,
            atime_nsec: 345678901,
            mode: 0o777,
            uid: 1000,
            gid: 1000,
            parent: 0,
        };

        let inode = Inode::Symlink(symlink_inode.clone());
        let fattr = inode.to_fattr3(99);

        assert!(matches!(fattr.ftype, ftype3::NF3LNK));
        assert_eq!(fattr.mode, 0o777);
        assert_eq!(fattr.size, symlink_inode.target.len() as u64);
        assert_eq!(fattr.uid, 1000);
        assert_eq!(fattr.gid, 1000);
        assert_eq!(fattr.fileid, 99);
        assert_eq!(fattr.nlink, 1);
    }

    #[test]
    fn test_inode_serialization() {
        let file_inode = FileInode {
            size: 2048,
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
        };

        let inode = Inode::File(file_inode.clone());

        let serialized = bincode::serialize(&inode).unwrap();
        let deserialized: Inode = bincode::deserialize(&serialized).unwrap();

        match deserialized {
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
}
