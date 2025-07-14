# ZeroFS - A SlateDB-based NFS Server

ZeroFS is an NFS server implementation that uses SlateDB as its storage backend, offering a fundamentally different approach compared to typical S3FS implementations.

<p align="center">
  <img src="assets/readme_storage_explanation.png" alt="Storage Architecture" width="500"/>
</p>

## Demo

<p align="center">
  <a href="https://asciinema.org/a/idv3T3klsE6FzKqve2vSGav92" target="_blank"><img src="https://asciinema.org/a/idv3T3klsE6FzKqve2vSGav92.svg" /></a>
</p>

## Configuration

### Required Environment Variables

- `SLATEDB_CACHE_DIR`: Directory path for caching data (required)
- `SLATEDB_CACHE_SIZE_GB`: Cache size in gigabytes (required, must be a positive number)

### Optional Environment Variables

- `AWS_ENDPOINT_URL`: S3-compatible endpoint URL
- `AWS_S3_BUCKET`: S3 bucket name (default: "slatedb")
- `AWS_ACCESS_KEY_ID`: AWS access key ID
- `AWS_SECRET_ACCESS_KEY`: AWS secret access key
- `AWS_DEFAULT_REGION`: AWS region (default: "us-east-1")
- `AWS_ALLOW_HTTP`: Allow HTTP connections (default: "false")

## Mounting the Filesystem

### macOS
```bash
mount -t nfs -o nolocks,vers=3,tcp,port=2049,mountport=2049,soft 127.0.0.1:/ mnt
```

### Linux
```bash
mount -t nfs -o vers=3,tcp,port=2049,mountport=2049,soft 127.0.0.1:/ /mnt
```

## Key Differences from S3FS

### 1. **Storage Architecture**

**S3FS:**
- Maps filesystem operations directly to S3 object operations
- Each file is typically stored as a single S3 object
- Directories are often represented as zero-byte objects with trailing slashes
- Metadata stored in S3 object headers or separate metadata objects

**ZeroFS:**
- Uses SlateDB, a log-structured merge-tree (LSM) database
- Files are chunked into 64KB blocks for efficient partial reads/writes
- Inodes and file data stored as key-value pairs
- Metadata is first-class data in the database

### 2. **Performance Characteristics**

**S3FS:**
- High latency for small file operations (S3 API overhead)
- Poor performance for partial file updates (must rewrite entire object)
- Directory listings can be slow (S3 LIST operations)
- No real atomic operations across multiple files

**ZeroFS:**
- Optimized for small, random I/O operations
- Efficient partial file updates through chunking
- Fast directory operations using B-tree indexes
- Atomic batch operations through SlateDB's WriteBatch

### 3. **Data Layout**

**S3FS Layout:**
```
s3://bucket/
├── file1.txt (complete file as single object)
├── dir1/ (zero-byte marker)
├── dir1/file2.txt (complete file)
└── .metadata/ (optional metadata storage)
```

**ZeroFS Layout (in SlateDB):**
```
Key-Value Store:
├── inode:0 → {type: directory, entries: {...}}
├── inode:1 → {type: file, size: 1024, ...}
├── chunk:1/0 → [first 64KB of file data]
├── chunk:1/1 → [second 64KB of file data]
└── next_inode_id → 2
```

### 5. **Cost Model**

**S3FS:**
- Costs scale with number of API requests
- Full file rewrites expensive for small changes
- LIST operations can be costly for large directories

**ZeroFS:**
- Costs amortized through SlateDB's compaction
- Efficient small updates reduce write amplification
- Predictable costs through batching

## Future Enhancements

- [ ] Hard link support
- [ ] Snapshot capabilities using SlateDB's checkpoints

## Conclusion

ZeroFS represents a different philosophy from S3FS implementations. While S3FS tries to make object storage look like a filesystem, ZeroFS uses a database-native approach that better matches filesystem semantics. This results in better performance for typical filesystem workloads at the cost of direct S3 compatibility.
