use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{Read, Seek, Write},
    os::unix::fs::MetadataExt,
    os::unix::fs::OpenOptionsExt,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{Error, ErrorCode, Result};

#[derive(Clone, Debug)]
pub struct ArtifactStore {
    root: PathBuf,
    verified: Arc<Mutex<HashMap<String, ArtifactFingerprint>>>,
    verification_hits: Arc<AtomicU64>,
    verification_misses: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactFingerprint {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactFile {
    pub uri: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactInventory {
    pub files: Vec<ArtifactFile>,
    pub invalid_entries: Vec<String>,
}

impl From<&std::fs::Metadata> for ArtifactFingerprint {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

impl ArtifactStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let digest_root = root.join("sha256");
        std::fs::create_dir_all(&digest_root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&digest_root, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root: std::fs::canonicalize(root)?,
            verified: Arc::new(Mutex::new(HashMap::new())),
            verification_hits: Arc::new(AtomicU64::new(0)),
            verification_misses: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn cleanup_temporary_publications(&self) -> Result<()> {
        // 2026-08-30: Every session constructed a store and removed temporary
        // files, racing with publications from other sessions. Cleanup is now
        // explicit and only called while the daemon-wide storage lock is held.
        for entry in std::fs::read_dir(self.root.join("sha256"))? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".gdb-ai-artifact-"))
            {
                std::fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    pub fn put(&self, bytes: &[u8]) -> Result<String> {
        let uri = Self::uri(bytes);
        self.put_prehashed(&uri, bytes)?;
        Ok(uri)
    }

    pub(crate) fn put_prehashed(&self, uri: &str, bytes: &[u8]) -> Result<()> {
        let digest = artifact_digest(uri)?;
        debug_assert_eq!(uri, Self::uri(bytes));
        let directory = self.root.join("sha256");
        let path = directory.join(digest);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                // 2026-08-30: Re-registering shared evidence rewrote and
                // synced an identical temporary file. Reuse the verified
                // immutable digest path without repeating publication I/O.
                let (_, size) = self.get_range(uri, 0, 0)?;
                if size != bytes.len() as u64 {
                    return Err(Error::new(
                        ErrorCode::Internal,
                        "artifact digest path contains unexpected data",
                    ));
                }
                return Ok(());
            }
            Ok(_) => {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "artifact path is not a regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let temporary = directory.join(format!(".gdb-ai-artifact-{}", Ulid::new()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);

            match std::fs::hard_link(&temporary, &path) {
                Ok(()) => {
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                        .open(&directory)?
                        .sync_all()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // 2026-08-28: Treating any existing digest path as valid let a
                    // symlink or pre-created corrupt file escape content addressing.
                    let existing = read_artifact_file(&path, bytes.len())?;
                    if existing != bytes {
                        return Err(Error::new(
                            ErrorCode::Internal,
                            "artifact digest path contains unexpected data",
                        ));
                    }
                }
                Err(error) => return Err(error.into()),
            }
            Ok(())
        })();
        let _ = std::fs::remove_file(temporary);
        result?;
        // 2026-08-30: URI construction already hashes the complete content.
        // Remember the published file identity so its first range read does
        // not immediately scan the same artifact again.
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return Err(Error::new(
                ErrorCode::Internal,
                "artifact path is not a regular file",
            ));
        }
        self.remember_verified(digest, ArtifactFingerprint::from(&metadata))?;
        Ok(())
    }

    pub fn uri(bytes: &[u8]) -> String {
        format!("gdbai://artifact/sha256:{:x}", Sha256::digest(bytes))
    }

    pub fn get(&self, uri: &str, max_bytes: usize) -> Result<Vec<u8>> {
        let digest = artifact_digest(uri)?;
        let path = self.root.join("sha256").join(digest);
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return Err(Error::new(
                ErrorCode::Internal,
                "artifact path is not a regular file",
            ));
        }
        if metadata.len() > max_bytes as u64 {
            return Err(Error::new(
                ErrorCode::OutputLimit,
                format!("artifact is {} bytes; limit is {max_bytes}", metadata.len()),
            ));
        }
        let bytes = read_artifact_file(&path, max_bytes)?;
        if format!("{:x}", Sha256::digest(&bytes)) != digest {
            return Err(Error::new(
                ErrorCode::Internal,
                "artifact content does not match its digest",
            ));
        }
        Ok(bytes)
    }

    pub fn get_range(&self, uri: &str, offset: u64, max_bytes: usize) -> Result<(Vec<u8>, u64)> {
        let digest = artifact_digest(uri)?;
        let path = self.root.join("sha256").join(digest);
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || offset > metadata.len() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "artifact offset is outside the file",
            ));
        }

        let fingerprint = ArtifactFingerprint::from(&metadata);
        let verified = self
            .verified
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "artifact verification cache poisoned"))?
            .get(digest)
            .copied()
            == Some(fingerprint);
        // 2026-08-29: Cached range verification fixed paging cost but exposed
        // no evidence that the cache was effective or repeatedly missing.
        if verified {
            self.verification_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.verification_misses.fetch_add(1, Ordering::Relaxed);
            // 2026-08-29: Rehashing the complete artifact for every range made
            // sequential paging O(n^2). Reuse verification while the file
            // identity and timestamps are unchanged.
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let length = file.read(&mut buffer)?;
                if length == 0 {
                    break;
                }
                hasher.update(&buffer[..length]);
            }
            if ArtifactFingerprint::from(&file.metadata()?) != fingerprint
                || format!("{:x}", hasher.finalize()) != digest
            {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "artifact content does not match its digest",
                ));
            }
            self.remember_verified(digest, fingerprint)?;
        }
        file.seek(std::io::SeekFrom::Start(offset))?;
        let length = (metadata.len() - offset).min(max_bytes as u64) as usize;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)?;
        if ArtifactFingerprint::from(&file.metadata()?) != fingerprint {
            self.verified
                .lock()
                .map_err(|_| {
                    Error::new(ErrorCode::Internal, "artifact verification cache poisoned")
                })?
                .remove(digest);
            return Err(Error::new(
                ErrorCode::Internal,
                "artifact changed while it was being read",
            ));
        }
        Ok((bytes, metadata.len()))
    }

    pub fn verification_counts(&self) -> (u64, u64) {
        (
            self.verification_hits.load(Ordering::Relaxed),
            self.verification_misses.load(Ordering::Relaxed),
        )
    }

    fn remember_verified(&self, digest: &str, fingerprint: ArtifactFingerprint) -> Result<()> {
        let mut verified = self
            .verified
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "artifact verification cache poisoned"))?;
        // ponytail: Clear this small cache instead of adding an LRU. Add one
        // only if more than 1024 concurrently paged artifacts matter.
        if verified.len() >= 1024 {
            verified.clear();
        }
        verified.insert(digest.to_owned(), fingerprint);
        Ok(())
    }

    pub fn inventory(&self) -> Result<ArtifactInventory> {
        let mut files = Vec::new();
        let mut invalid_entries = Vec::new();
        for entry in std::fs::read_dir(self.root.join("sha256"))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let file_type = entry.file_type()?;
            if name.len() != 64
                || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
                || name.bytes().any(|byte| byte.is_ascii_uppercase())
                || !file_type.is_file()
            {
                invalid_entries.push(name);
                continue;
            }
            files.push(ArtifactFile {
                uri: format!("gdbai://artifact/sha256:{name}"),
                size: entry.metadata()?.len(),
            });
        }
        files.sort_by(|left, right| left.uri.cmp(&right.uri));
        invalid_entries.sort();
        Ok(ArtifactInventory {
            files,
            invalid_entries,
        })
    }

    pub fn verify(&self, uri: &str) -> Result<()> {
        self.get_range(uri, 0, 0).map(|_| ())
    }

    pub fn remove(&self, uri: &str) -> Result<()> {
        let digest = artifact_digest(uri)?;
        let path = self.root.join("sha256").join(digest);
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return Err(Error::new(
                ErrorCode::Internal,
                "artifact path is not a regular file",
            ));
        }
        std::fs::remove_file(path)?;
        self.verified
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "artifact verification cache poisoned"))?
            .remove(digest);
        Ok(())
    }

    pub fn remove_if_exists(&self, uri: &str) -> Result<bool> {
        let digest = artifact_digest(uri)?;
        let path = self.root.join("sha256").join(digest);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                std::fs::remove_file(path)?;
                self.verified
                    .lock()
                    .map_err(|_| {
                        Error::new(ErrorCode::Internal, "artifact verification cache poisoned")
                    })?
                    .remove(digest);
                Ok(true)
            }
            Ok(_) => Err(Error::new(
                ErrorCode::Internal,
                "artifact path is not a regular file",
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

fn artifact_digest(uri: &str) -> Result<&str> {
    uri.strip_prefix("gdbai://artifact/sha256:")
        .filter(|digest| {
            digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                && !digest.bytes().any(|byte| byte.is_ascii_uppercase())
        })
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "invalid artifact URI"))
}

fn read_artifact_file(path: &std::path::Path, maximum: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(Error::new(
            ErrorCode::OutputLimit,
            "artifact exceeds the permitted size",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn artifacts_are_content_addressed_and_bounded() {
        let directory = tempdir().unwrap();
        let store = ArtifactStore::new(directory.path()).unwrap();
        let uri = store.put(b"evidence").unwrap();
        assert_eq!(store.put(b"evidence").unwrap(), uri);
        assert_eq!(store.get(&uri, 8).unwrap(), b"evidence");
        assert_eq!(store.get_range(&uri, 2, 3).unwrap(), (b"ide".to_vec(), 8));
        assert!(matches!(
            store.get(&uri, 7),
            Err(Error {
                code: ErrorCode::OutputLimit,
                ..
            })
        ));

        let outside = directory.path().join("outside");
        std::fs::write(&outside, b"escape").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"escape"));
        std::os::unix::fs::symlink(&outside, store.root.join("sha256").join(&digest)).unwrap();
        assert!(
            store
                .get(&format!("gdbai://artifact/sha256:{digest}"), 64)
                .is_err()
        );
    }

    #[test]
    fn range_verification_is_reused_until_the_file_changes() {
        let directory = tempdir().unwrap();
        let store = ArtifactStore::new(directory.path()).unwrap();
        let uri = store.put(&vec![b'a'; 128 * 1024]).unwrap();
        let digest = uri.strip_prefix("gdbai://artifact/sha256:").unwrap();

        assert_eq!(store.get_range(&uri, 0, 16).unwrap().0, vec![b'a'; 16]);
        assert_eq!(
            store.get_range(&uri, 64 * 1024, 16).unwrap().0,
            vec![b'a'; 16]
        );
        assert_eq!(store.verification_counts(), (2, 0));
        assert!(store.verified.lock().unwrap().contains_key(digest));

        std::fs::write(store.root.join("sha256").join(digest), b"corrupt").unwrap();
        assert!(matches!(
            store.get_range(&uri, 0, 4),
            Err(Error {
                code: ErrorCode::Internal,
                ..
            })
        ));
    }

    #[test]
    fn repeated_put_reuses_the_verified_publication() {
        let directory = tempdir().unwrap();
        let store = ArtifactStore::new(directory.path()).unwrap();
        let uri = store.put(b"shared evidence").unwrap();

        assert_eq!(store.put(b"shared evidence").unwrap(), uri);
        assert_eq!(store.verification_counts(), (1, 0));
        assert_eq!(store.inventory().unwrap().files.len(), 1);
    }

    #[test]
    fn concurrent_writers_publish_one_complete_artifact() {
        let directory = tempdir().unwrap();
        let store = ArtifactStore::new(directory.path()).unwrap();
        let bytes = vec![0x5a; 128 * 1024];
        let writers = (0..100)
            .map(|_| {
                let store = store.clone();
                let bytes = bytes.clone();
                std::thread::spawn(move || store.put(&bytes).unwrap())
            })
            .collect::<Vec<_>>();
        let uris = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect::<Vec<_>>();

        assert!(uris.iter().all(|uri| uri == &uris[0]));
        assert_eq!(store.get(&uris[0], bytes.len()).unwrap(), bytes);
        assert_eq!(store.inventory().unwrap().files.len(), 1);
    }

    #[test]
    fn explicit_cleanup_preserves_live_temporary_publications() {
        let directory = tempdir().unwrap();
        let store = ArtifactStore::new(directory.path()).unwrap();
        let temporary = store.root.join("sha256/.gdb-ai-artifact-interrupted");
        std::fs::write(&temporary, b"partial").unwrap();

        ArtifactStore::new(directory.path()).unwrap();
        assert!(temporary.exists());
        store.cleanup_temporary_publications().unwrap();

        assert!(!temporary.exists());
    }

    #[test]
    fn artifact_uris_are_canonical_lowercase() {
        let uri = ArtifactStore::uri(b"canonical");
        assert!(artifact_digest(&uri).is_ok());
        assert!(artifact_digest(&uri.to_ascii_uppercase()).is_err());
    }
}
