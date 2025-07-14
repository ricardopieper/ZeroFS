#[cfg(test)]
mod tests {
    use crate::filesystem::SlateDbFs;
    use crate::test_helpers::test_helpers::filename;
    use nfsserve::nfs::*;
    use nfsserve::vfs::NFSFileSystem;

    async fn create_test_fs() -> SlateDbFs {
        SlateDbFs::new_in_memory().await.unwrap()
    }

    #[allow(dead_code)]
    async fn stat(fs: &SlateDbFs, id: fileid3) -> Result<fattr3, nfsstat3> {
        fs.getattr(id).await
    }

    #[tokio::test]
    async fn test_chmod_basic() {
        let fs = create_test_fs().await;

        let (file_id, _) = fs
            .create(0, &filename(b"test.txt"), sattr3::default())
            .await
            .unwrap();

        let setattr = sattr3 {
            mode: set_mode3::mode(0o644),
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };

        let fattr = fs.setattr(file_id, setattr).await.unwrap();
        assert_eq!(fattr.mode & 0o777, 0o644);

        let setattr = sattr3 {
            mode: set_mode3::mode(0o7755),
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };

        let fattr = fs.setattr(file_id, setattr).await.unwrap();
        assert_eq!(fattr.mode & 0o7777, 0o7755);
    }

    #[tokio::test]
    async fn test_mkdir_permissions() {
        let fs = create_test_fs().await;

        let (dir_id, fattr) = fs.mkdir(0, &filename(b"testdir")).await.unwrap();
        assert!(matches!(fattr.ftype, ftype3::NF3DIR));

        assert_eq!(fattr.mode & 0o777, 0o755);

        let setattr = sattr3 {
            mode: set_mode3::Void,
            uid: set_uid3::Void,
            gid: set_gid3::gid(100),
            size: set_size3::Void,
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };
        fs.setattr(dir_id, setattr).await.unwrap();

        let setattr = sattr3 {
            mode: set_mode3::mode(0o2755),
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };
        fs.setattr(dir_id, setattr).await.unwrap();

        let parent_fattr = fs.getattr(dir_id).await.unwrap();
        assert_eq!(
            parent_fattr.mode & 0o2000,
            0o2000,
            "Parent should have setgid bit set"
        );
        assert_eq!(parent_fattr.gid, 100, "Parent should have gid 100");

        let (_subdir_id, subdir_fattr) = fs.mkdir(dir_id, &filename(b"subdir")).await.unwrap();
        assert_eq!(subdir_fattr.gid, 100);
        assert_eq!(subdir_fattr.mode & 0o2000, 0o2000);
    }

    #[tokio::test]
    async fn test_rename_directory_cycles() {
        let fs = create_test_fs().await;

        let (a_id, _) = fs.mkdir(0, &filename(b"a")).await.unwrap();
        let (b_id, _) = fs.mkdir(a_id, &filename(b"b")).await.unwrap();
        let (c_id, _) = fs.mkdir(b_id, &filename(b"c")).await.unwrap();

        let result = fs.rename(0, &filename(b"a"), b_id, &filename(b"a")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));

        let result = fs.rename(0, &filename(b"a"), c_id, &filename(b"a")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));

        let result = fs.rename(a_id, &filename(b"."), 0, &filename(b"dot")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));

        let result = fs
            .rename(a_id, &filename(b".."), 0, &filename(b"dotdot"))
            .await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));
    }

    #[tokio::test]
    async fn test_rename_atomic_replacement() {
        let fs = create_test_fs().await;

        let (file1_id, _) = fs
            .create(0, &filename(b"file1"), sattr3::default())
            .await
            .unwrap();
        let (file2_id, _) = fs
            .create(0, &filename(b"file2"), sattr3::default())
            .await
            .unwrap();

        fs.write(file1_id, 0, b"content1").await.unwrap();
        fs.write(file2_id, 0, b"content2").await.unwrap();

        fs.rename(0, &filename(b"file1"), 0, &filename(b"file2"))
            .await
            .unwrap();

        let result = fs.lookup(0, &filename(b"file1")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));

        let found_id = fs.lookup(0, &filename(b"file2")).await.unwrap();
        assert_eq!(found_id, file1_id);

        let (data, _) = fs.read(found_id, 0, 100).await.unwrap();
        assert_eq!(data, b"content1");

        let result = fs.getattr(file2_id).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));
    }

    #[tokio::test]
    async fn test_rmdir_permissions() {
        let fs = create_test_fs().await;

        let (parent_id, _) = fs.mkdir(0, &filename(b"parent")).await.unwrap();

        let setattr = sattr3 {
            mode: set_mode3::mode(0o1777),
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };
        fs.setattr(parent_id, setattr).await.unwrap();

        let (_subdir_id, _) = fs.mkdir(parent_id, &filename(b"subdir")).await.unwrap();

        fs.remove(parent_id, &filename(b"subdir")).await.unwrap();

        let result = fs.lookup(parent_id, &filename(b"subdir")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));
    }

    #[tokio::test]
    async fn test_rmdir_non_empty() {
        let fs = create_test_fs().await;

        let (dir_id, _) = fs.mkdir(0, &filename(b"dir")).await.unwrap();
        let (_file_id, _) = fs
            .create(dir_id, &filename(b"file"), sattr3::default())
            .await
            .unwrap();

        let result = fs.remove(0, &filename(b"dir")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOTEMPTY)));

        fs.remove(dir_id, &filename(b"file")).await.unwrap();

        // Now removing directory should succeed
        fs.remove(0, &filename(b"dir")).await.unwrap();
    }

    #[tokio::test]
    async fn test_symlink_creation() {
        let fs = create_test_fs().await;

        let target = nfspath3 {
            0: b"/path/to/target".to_vec(),
        };
        let attr = sattr3::default();

        let (link_id, fattr) = fs
            .symlink(0, &filename(b"mylink"), &target, &attr)
            .await
            .unwrap();
        assert!(matches!(fattr.ftype, ftype3::NF3LNK));

        let read_target = fs.readlink(link_id).await.unwrap();
        assert_eq!(read_target.0, target.0);

        assert_eq!(fattr.size, target.0.len() as u64);
    }

    #[tokio::test]
    async fn test_truncate_file() {
        let fs = create_test_fs().await;

        let (file_id, _) = fs
            .create(0, &filename(b"test.txt"), sattr3::default())
            .await
            .unwrap();
        fs.write(file_id, 0, b"Hello, World!").await.unwrap();

        let fattr = fs.getattr(file_id).await.unwrap();
        assert_eq!(fattr.size, 13);

        // Truncate to 5 bytes
        let setattr = sattr3 {
            mode: set_mode3::Void,
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::size(5),
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };

        let fattr = fs.setattr(file_id, setattr).await.unwrap();
        assert_eq!(fattr.size, 5);

        let (data, _) = fs.read(file_id, 0, 10).await.unwrap();
        assert_eq!(data, b"Hello");

        let setattr = sattr3 {
            mode: set_mode3::Void,
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::size(10),
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };

        let fattr = fs.setattr(file_id, setattr).await.unwrap();
        assert_eq!(fattr.size, 10);

        let (data, _) = fs.read(file_id, 0, 10).await.unwrap();
        assert_eq!(data.len(), 10);
        assert_eq!(&data[0..5], b"Hello");
        assert_eq!(&data[5..10], &[0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn test_unlink_with_sticky_bit() {
        let fs = create_test_fs().await;

        let (tmp_id, _) = fs.mkdir(0, &filename(b"tmp")).await.unwrap();

        let setattr = sattr3 {
            mode: set_mode3::mode(0o1777),
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };
        fs.setattr(tmp_id, setattr).await.unwrap();

        let (_file_id, _) = fs
            .create(tmp_id, &filename(b"file"), sattr3::default())
            .await
            .unwrap();

        fs.remove(tmp_id, &filename(b"file")).await.unwrap();

        let result = fs.lookup(tmp_id, &filename(b"file")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));
    }

    #[tokio::test]
    async fn test_utimensat_timestamps() {
        let fs = create_test_fs().await;

        let (file_id, _initial_fattr) = fs
            .create(0, &filename(b"test.txt"), sattr3::default())
            .await
            .unwrap();

        let new_atime = nfstime3 {
            seconds: 1234567890,
            nseconds: 123456789,
        };
        let new_mtime = nfstime3 {
            seconds: 1234567891,
            nseconds: 987654321,
        };

        let setattr = sattr3 {
            mode: set_mode3::Void,
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::SET_TO_CLIENT_TIME(new_atime),
            mtime: set_mtime::SET_TO_CLIENT_TIME(new_mtime),
        };

        let fattr = fs.setattr(file_id, setattr).await.unwrap();

        assert_eq!(fattr.atime.seconds, new_atime.seconds);
        assert_eq!(fattr.atime.nseconds, new_atime.nseconds);
        assert_eq!(fattr.mtime.seconds, new_mtime.seconds);
        assert_eq!(fattr.mtime.nseconds, new_mtime.nseconds);

        let setattr = sattr3 {
            mode: set_mode3::Void,
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::SET_TO_SERVER_TIME,
            mtime: set_mtime::SET_TO_SERVER_TIME,
        };

        let before = std::time::SystemTime::now();
        let fattr = fs.setattr(file_id, setattr).await.unwrap();
        let after = std::time::SystemTime::now();

        let before_secs = before
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let after_secs = after
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        assert!(fattr.atime.seconds >= before_secs && fattr.atime.seconds <= after_secs);
        assert!(fattr.mtime.seconds >= before_secs && fattr.mtime.seconds <= after_secs);
    }

    #[tokio::test]
    async fn test_create_exclusive() {
        let fs = create_test_fs().await;

        let file_id = fs
            .create_exclusive(0, &filename(b"exclusive.txt"))
            .await
            .unwrap();
        assert!(file_id > 0);

        let result = fs.create_exclusive(0, &filename(b"exclusive.txt")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_EXIST)));

        let result = fs
            .create(0, &filename(b"exclusive.txt"), sattr3::default())
            .await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_EXIST)));
    }

    #[tokio::test]
    async fn test_readdir_pagination() {
        let fs = create_test_fs().await;

        let (dir_id, _) = fs.mkdir(0, &filename(b"testdir")).await.unwrap();

        for i in 0..10 {
            let name = format!("file{:02}", i);
            fs.create(dir_id, &filename(name.as_bytes()), sattr3::default())
                .await
                .unwrap();
        }

        let mut all_entries = Vec::new();
        let mut start_after = 0;

        loop {
            let result = fs.readdir(dir_id, start_after, 5).await.unwrap();

            for entry in &result.entries {
                let name = String::from_utf8_lossy(&entry.name.0);
                if name != "." && name != ".." {
                    all_entries.push(name.to_string());
                }
            }

            if result.end {
                break;
            }

            start_after = result.entries.last().unwrap().fileid;
        }

        assert_eq!(all_entries.len(), 10);

        all_entries.sort();
        for i in 0..10 {
            assert_eq!(all_entries[i], format!("file{:02}", i));
        }
    }

    #[tokio::test]
    async fn test_cross_directory_rename() {
        let fs = create_test_fs().await;

        let (dir1_id, _) = fs.mkdir(0, &filename(b"dir1")).await.unwrap();
        let (dir2_id, _) = fs.mkdir(0, &filename(b"dir2")).await.unwrap();

        let (file_id, _) = fs
            .create(dir1_id, &filename(b"file.txt"), sattr3::default())
            .await
            .unwrap();
        fs.write(file_id, 0, b"test content").await.unwrap();

        fs.rename(
            dir1_id,
            &filename(b"file.txt"),
            dir2_id,
            &filename(b"file.txt"),
        )
        .await
        .unwrap();

        let result = fs.lookup(dir1_id, &filename(b"file.txt")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));

        let found_id = fs.lookup(dir2_id, &filename(b"file.txt")).await.unwrap();
        assert_eq!(found_id, file_id);

        let (data, _) = fs.read(found_id, 0, 100).await.unwrap();
        assert_eq!(data, b"test content");

        let _dir1_attr = fs.getattr(dir1_id).await.unwrap();
        let _dir2_attr = fs.getattr(dir2_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_write_and_read_large_file() {
        let fs = create_test_fs().await;

        let (file_id, _) = fs
            .create(0, &filename(b"large.txt"), sattr3::default())
            .await
            .unwrap();

        let chunk_size = 64 * 1024;
        let test_data: Vec<u8> = (0..chunk_size * 2 + 1000)
            .map(|i| (i % 256) as u8)
            .collect();

        fs.write(file_id, 0, &test_data).await.unwrap();

        let (data1, _) = fs.read(file_id, 0, chunk_size as u32).await.unwrap();
        let (data2, _) = fs
            .read(file_id, chunk_size as u64, chunk_size as u32)
            .await
            .unwrap();
        let (data3, eof) = fs
            .read(file_id, (chunk_size * 2) as u64, 2000)
            .await
            .unwrap();

        assert_eq!(data1.len(), chunk_size);
        assert_eq!(data2.len(), chunk_size);
        assert_eq!(data3.len(), 1000);
        assert!(eof);

        assert_eq!(&data1[..], &test_data[..chunk_size]);
        assert_eq!(&data2[..], &test_data[chunk_size..chunk_size * 2]);
        assert_eq!(&data3[..], &test_data[chunk_size * 2..]);
    }

    #[tokio::test]
    async fn test_ctime_updates_on_chmod() {
        let fs = create_test_fs().await;

        let (file_id, initial_attr) = fs
            .create(0, &filename(b"test.txt"), sattr3::default())
            .await
            .unwrap();
        let initial_ctime = initial_attr.ctime;

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let setattr = sattr3 {
            mode: set_mode3::mode(0o755),
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };

        let new_attr = fs.setattr(file_id, setattr).await.unwrap();

        // ctime should be updated
        assert!(
            new_attr.ctime.seconds > initial_ctime.seconds
                || (new_attr.ctime.seconds == initial_ctime.seconds
                    && new_attr.ctime.nseconds > initial_ctime.nseconds)
        );
    }

    #[tokio::test]
    async fn test_ctime_updates_on_truncate() {
        let fs = create_test_fs().await;

        let (file_id, _) = fs
            .create(0, &filename(b"test.txt"), sattr3::default())
            .await
            .unwrap();
        fs.write(file_id, 0, b"Hello, World!").await.unwrap();

        let initial_attr = fs.getattr(file_id).await.unwrap();
        let initial_ctime = initial_attr.ctime;
        let initial_mtime = initial_attr.mtime;

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Truncate the file
        let setattr = sattr3 {
            mode: set_mode3::Void,
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::size(5),
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };

        let new_attr = fs.setattr(file_id, setattr).await.unwrap();

        assert!(
            new_attr.ctime.seconds > initial_ctime.seconds
                || (new_attr.ctime.seconds == initial_ctime.seconds
                    && new_attr.ctime.nseconds > initial_ctime.nseconds)
        );
        assert!(
            new_attr.mtime.seconds > initial_mtime.seconds
                || (new_attr.mtime.seconds == initial_mtime.seconds
                    && new_attr.mtime.nseconds > initial_mtime.nseconds)
        );
        assert_eq!(new_attr.size, 5);
    }

    #[tokio::test]
    async fn test_umask_file_creation() {
        let fs = create_test_fs().await;

        let attr = sattr3 {
            mode: set_mode3::mode(0o666),
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };

        let (_, fattr) = fs.create(0, &filename(b"test.txt"), attr).await.unwrap();

        assert!(
            fattr.mode & 0o777 <= 0o666,
            "Mode should not exceed requested permissions"
        );
    }

    #[tokio::test]
    async fn test_symlink_permissions() {
        let fs = create_test_fs().await;

        let (link_id, fattr) = fs
            .symlink(
                0,
                &filename(b"mylink"),
                &nfspath3 {
                    0: b"/target/path".to_vec(),
                },
                &sattr3::default(),
            )
            .await
            .unwrap();

        assert!(matches!(fattr.ftype, ftype3::NF3LNK));
        assert_eq!(fattr.mode & 0o170000, 0o120000);

        let target = fs.readlink(link_id).await.unwrap();
        assert_eq!(target.0, b"/target/path");
    }

    #[tokio::test]
    async fn test_write_extends_file() {
        let fs = create_test_fs().await;

        let (file_id, _) = fs
            .create(0, &filename(b"test.txt"), sattr3::default())
            .await
            .unwrap();

        fs.write(file_id, 100, b"Hello").await.unwrap();

        let attr = fs.getattr(file_id).await.unwrap();
        assert_eq!(attr.size, 105); // 100 + 5 bytes

        let (data, _) = fs.read(file_id, 0, 100).await.unwrap();
        assert_eq!(data.len(), 100);
        assert!(data.iter().all(|&b| b == 0));

        let (data, _) = fs.read(file_id, 100, 5).await.unwrap();
        assert_eq!(data, b"Hello");
    }

    #[tokio::test]
    async fn test_rename_over_existing_file() {
        let fs = create_test_fs().await;

        let (src_id, _) = fs
            .create(0, &filename(b"source.txt"), sattr3::default())
            .await
            .unwrap();
        fs.write(src_id, 0, b"source content").await.unwrap();

        let (_target_id, _) = fs
            .create(0, &filename(b"target.txt"), sattr3::default())
            .await
            .unwrap();
        fs.write(_target_id, 0, b"target content").await.unwrap();

        fs.rename(0, &filename(b"source.txt"), 0, &filename(b"target.txt"))
            .await
            .unwrap();

        let result = fs.lookup(0, &filename(b"source.txt")).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));

        let new_id = fs.lookup(0, &filename(b"target.txt")).await.unwrap();
        assert_eq!(new_id, src_id);

        let (data, _) = fs.read(new_id, 0, 100).await.unwrap();
        assert_eq!(data, b"source content");
    }

    #[tokio::test]
    async fn test_directory_permissions() {
        let fs = create_test_fs().await;

        let (dir_id, initial_attr) = fs.mkdir(0, &filename(b"testdir")).await.unwrap();

        assert!(
            initial_attr.mode & !0o777 == 0,
            "Mode should not have bits set outside permission mask"
        );

        let setattr = sattr3 {
            mode: set_mode3::mode(0o700),
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };

        let new_attr = fs.setattr(dir_id, setattr).await.unwrap();
        assert_eq!(new_attr.mode & 0o777, 0o700);
    }

    #[tokio::test]
    async fn test_file_extension_with_truncate() {
        let fs = create_test_fs().await;

        let (file_id, _) = fs
            .create(0, &filename(b"test.txt"), sattr3::default())
            .await
            .unwrap();
        fs.write(file_id, 0, b"Hello, World!").await.unwrap();

        let setattr = sattr3 {
            mode: set_mode3::Void,
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::size(100),
            atime: set_atime::DONT_CHANGE,
            mtime: set_mtime::DONT_CHANGE,
        };

        let attr_after = fs.setattr(file_id, setattr).await.unwrap();
        assert_eq!(attr_after.size, 100);

        let (data, _) = fs.read(file_id, 0, 13).await.unwrap();
        assert_eq!(data, b"Hello, World!");

        let (data, _) = fs.read(file_id, 13, 87).await.unwrap();
        assert_eq!(data.len(), 87);
        assert!(data.iter().all(|&b| b == 0));

        let (data, _) = fs.read(file_id, 0, 13).await.unwrap();
        assert_eq!(data, b"Hello, World!");
    }

    #[tokio::test]
    async fn test_dot_and_dotdot_entries() {
        let fs = create_test_fs().await;

        let (a_id, _) = fs.mkdir(0, &filename(b"a")).await.unwrap();
        let (b_id, _) = fs.mkdir(a_id, &filename(b"b")).await.unwrap();

        let result = fs.readdir(0, 0, 10).await.unwrap();
        let dot = result.entries.iter().find(|e| e.name.0 == b".").unwrap();
        let dotdot = result.entries.iter().find(|e| e.name.0 == b"..").unwrap();
        assert_eq!(dot.fileid, 0, "Root's . should point to itself");
        assert_eq!(dotdot.fileid, 0, "Root's .. should point to itself");

        let result = fs.readdir(a_id, 0, 10).await.unwrap();
        let dot = result.entries.iter().find(|e| e.name.0 == b".").unwrap();
        let dotdot = result.entries.iter().find(|e| e.name.0 == b"..").unwrap();
        assert_eq!(dot.fileid, a_id, "Directory a's . should point to itself");
        assert_eq!(dotdot.fileid, 0, "Directory a's .. should point to root");

        let result = fs.readdir(b_id, 0, 10).await.unwrap();
        let dot = result.entries.iter().find(|e| e.name.0 == b".").unwrap();
        let dotdot = result.entries.iter().find(|e| e.name.0 == b"..").unwrap();
        assert_eq!(dot.fileid, b_id, "Directory b's . should point to itself");
        assert_eq!(
            dotdot.fileid, a_id,
            "Directory b's .. should point to directory a"
        );
    }

    #[tokio::test]
    async fn test_parent_directory_ctime_updates() {
        let fs = create_test_fs().await;

        let parent_attr_before = fs.getattr(0).await.unwrap();
        let ctime_before = parent_attr_before.ctime.seconds;
        let mtime_before = parent_attr_before.mtime.seconds;

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let (_file_id, _) = fs
            .create(0, &filename(b"test.txt"), sattr3::default())
            .await
            .unwrap();

        let parent_attr_after = fs.getattr(0).await.unwrap();
        assert!(
            parent_attr_after.ctime.seconds >= ctime_before,
            "Parent directory ctime should be updated after creating a file"
        );
        assert!(
            parent_attr_after.mtime.seconds >= mtime_before,
            "Parent directory mtime should be updated after creating a file"
        );

        let ctime_before = parent_attr_after.ctime.seconds;
        let mtime_before2 = parent_attr_after.mtime.seconds;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let (_dir_id, _) = fs.mkdir(0, &filename(b"testdir")).await.unwrap();

        let parent_attr_final = fs.getattr(0).await.unwrap();
        assert!(
            parent_attr_final.ctime.seconds >= ctime_before,
            "Parent directory ctime should be updated after creating a directory"
        );
        assert!(
            parent_attr_final.mtime.seconds >= mtime_before2,
            "Parent directory mtime should be updated after creating a directory"
        );
    }

    #[tokio::test]
    async fn test_special_timestamp_values() {
        let fs = create_test_fs().await;

        let (file_id, initial_attr) = fs
            .create(0, &filename(b"test.txt"), sattr3::default())
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Set timestamps to server time
        let setattr = sattr3 {
            mode: set_mode3::Void,
            uid: set_uid3::Void,
            gid: set_gid3::Void,
            size: set_size3::Void,
            atime: set_atime::SET_TO_SERVER_TIME,
            mtime: set_mtime::SET_TO_SERVER_TIME,
        };

        let new_attr = fs.setattr(file_id, setattr).await.unwrap();

        assert!(
            new_attr.atime.seconds > initial_attr.atime.seconds
                || (new_attr.atime.seconds == initial_attr.atime.seconds
                    && new_attr.atime.nseconds > initial_attr.atime.nseconds)
        );
        assert!(
            new_attr.mtime.seconds > initial_attr.mtime.seconds
                || (new_attr.mtime.seconds == initial_attr.mtime.seconds
                    && new_attr.mtime.nseconds > initial_attr.mtime.nseconds)
        );
    }

    #[tokio::test]
    async fn test_parent_directory_tracking() {
        let fs = create_test_fs().await;

        let (dir1_id, _) = fs.mkdir(0, &filename(b"dir1")).await.unwrap();
        let (dir2_id, _) = fs.mkdir(dir1_id, &filename(b"dir2")).await.unwrap();
        let (dir3_id, _) = fs.mkdir(dir2_id, &filename(b"dir3")).await.unwrap();

        let (file_id, _) = fs
            .create(dir3_id, &filename(b"file.txt"), sattr3::default())
            .await
            .unwrap();

        let result = fs
            .rename(0, &filename(b"dir1"), dir2_id, &filename(b"moved_dir1"))
            .await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));

        let result = fs
            .rename(0, &filename(b"dir1"), dir3_id, &filename(b"moved_dir1"))
            .await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_INVAL)));

        fs.rename(dir2_id, &filename(b"dir3"), 0, &filename(b"moved_dir3"))
            .await
            .unwrap();

        let found_id = fs.lookup(0, &filename(b"moved_dir3")).await.unwrap();
        assert_eq!(found_id, dir3_id);
        let found_file = fs.lookup(dir3_id, &filename(b"file.txt")).await.unwrap();
        assert_eq!(found_file, file_id);
    }
}
