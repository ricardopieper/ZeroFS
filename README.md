# ZeroFS - The S3FS That Doesn't Suck

ZeroFS makes S3 storage feel like a real filesystem. Built on [SlateDB](https://github.com/slatedb/slatedb), it's fast enough to compile code on and works with the NFS client already built into your OS. No FUSE drivers, no kernel modules, just mount and go.

<p align="center">
  <img src="assets/readme_storage_explanation.png" alt="Storage Architecture" width="500"/>
</p>

## Demo

### Ubuntu Running on ZeroFS

Watch Ubuntu boot from ZeroFS:

<p align="center">
<a href="https://asciinema.org/a/728172" target="_blank"><img src="https://asciinema.org/a/728172.svg" /></a>
</p>

### Self-Hosting ZeroFS

ZeroFS can self-host! Here's a demo showing Rust's toolchain building ZeroFS while running on ZeroFS:

<p align="center">
<a href="https://asciinema.org/a/728101" target="_blank"><img src="https://asciinema.org/a/728101.svg" /></a>
</p>

## Configuration

### Required Environment Variables

- `SLATEDB_CACHE_DIR`: Directory path for caching data (required)
- `SLATEDB_CACHE_SIZE_GB`: Cache size in gigabytes (required, must be a positive number)
- `ZEROFS_ENCRYPTION_PASSWORD`: Password for filesystem encryption (required)

### Optional Environment Variables

- `AWS_ENDPOINT_URL`: S3-compatible endpoint URL
- `AWS_S3_BUCKET`: S3 bucket name (default: "slatedb")
- `AWS_ACCESS_KEY_ID`: AWS access key ID
- `AWS_SECRET_ACCESS_KEY`: AWS secret access key
- `AWS_DEFAULT_REGION`: AWS region (default: "us-east-1")
- `AWS_ALLOW_HTTP`: Allow HTTP connections (default: "false")


### Using IMDS

If you have an IAM role attached to your instance, and you want to use it instead of passing the access key ID and secret key, just leave the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY variables empty.

### Encryption

Encryption is always enabled in ZeroFS. All file data is encrypted using ChaCha20-Poly1305 authenticated encryption with zstd compression. A password is required to start the filesystem:

```bash
# Start ZeroFS with encryption password
ZEROFS_ENCRYPTION_PASSWORD='your-secure-password' zerofs /path/to/db
```

#### Password Management

On first run, ZeroFS generates a 256-bit data encryption key (DEK) and encrypts it with a key derived from your password using Argon2id. The encrypted key is stored in the database, so you need the same password for subsequent runs.

To change your password:

```bash
# Change the encryption password
ZEROFS_ENCRYPTION_PASSWORD='current-password' \
ZEROFS_NEW_PASSWORD='new-password' \
zerofs /path/to/db
```

The program will change the password and exit. Then you can use the new password for future runs.

#### What's Encrypted vs What's Not

**Encrypted:**
- All file contents (in 64KB chunks)
- File metadata values (permissions, timestamps, etc.)

**Not Encrypted:**
- Key structure (inode IDs, directory entry names)
- Database structure (LSM tree levels, bloom filters)

This design is intentional. Encrypting keys would severely impact performance as LSM trees need to compare and sort keys during compaction. The key structure reveals filesystem hierarchy but not file contents.

This should be fine for most use-cases but if you need to hide directory structure and filenames, you can layer a filename-encrypting filesystem like gocryptfs on top of ZeroFS.

## Mounting the Filesystem

### macOS
```bash
mount -t nfs -o nolocks,vers=3,tcp,port=2049,mountport=2049,soft 127.0.0.1:/ mnt
```

### Linux
```bash
mount -t nfs -o vers=3,nolock,tcp,port=2049,mountport=2049,soft 127.0.0.1:/ /mnt
```

## Why NFS?

We chose NFS because it's supported everywhere - macOS, Linux, Windows, BSD - without requiring any additional software. The client-side kernel implementation is highly optimized, while our server can remain in userspace with full control over the storage backend.

NFS's network-first design is a natural fit for remote object storage. The protocol handles disconnections, retries, and caching in ways that have been refined over decades of production use. Multi-client access, load balancing, and high availability are built into the ecosystem.

With FUSE, we'd need to write both the filesystem implementation and a custom client driver to handle S3's network characteristics properly - latency, retries, caching strategies. NFS lets us focus on what matters: building a great filesystem. The networking, caching, and client-side concerns are handled by battle-tested NFS implementations in every OS kernel.

For developers, this means you can mount ZeroFS using standard OS tools, monitor it with existing infrastructure, and debug issues with familiar utilities. It just works.

## Compatibility

ZeroFS passes all tests in the [pjdfstest_nfs](https://github.com/Barre/pjdfstest_nfs) test suite - 8,662 tests covering POSIX filesystem operations including file operations, permissions, ownership, and more.

## Performance Benchmarks

### SQLite Performance

ZeroFS delivers excellent performance for database workloads. Here are SQLite benchmark results running on ZeroFS:

```
SQLite:     version 3.25.2
Date:       Wed Jul 16 12:08:22 2025
CPU:        8 * AMD EPYC-Rome Processor
CPUCache:   512 KB
Keys:       16 bytes each
Values:     100 bytes each
Entries:    1000000
RawSize:    110.6 MB (estimated)
------------------------------------------------
fillseq      :      19.426 micros/op;
readseq      :       0.941 micros/op;
readrand100K :       1.596 micros/op;
```

These microsecond-level latencies are 4-5 orders of magnitude faster than raw S3 operations (which typically have 50-300ms latency). This performance is achieved through:

- Multi-layered cache: Memory block cache, metadata cache, and configurable disk cache
- Compression: Reduces data transfer and increases effective cache capacity
- Parallel prefetching: Overlaps S3 requests to hide latency
- Buffering through WAL + memtables: Batches writes to minimize S3 operations

<p align="center">
  <a href="https://asciinema.org/a/ovxTV0zTpjE1xcxn5CXehCTTN" target="_blank">View SQLite Benchmark Demo</a>
</p>

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

- [ ] Snapshot capabilities using SlateDB's checkpoints
