use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{Read, Seek, Write},
    os::unix::fs::MetadataExt,
    os::unix::fs::OpenOptionsExt,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256};

use crate::{Error, ErrorCode, Result};

#[derive(Clone, Debug)]
pub struct ArtifactStore {
    root: PathBuf,
    verified: Arc<Mutex<HashMap<String, ArtifactFingerprint>>>,
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
        std::fs::create_dir_all(root.join("sha256"))?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(root.join("sha256"), std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root: std::fs::canonicalize(root)?,
            verified: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<String> {
        let uri = Self::uri(bytes);
        let digest = uri.strip_prefix("gdbai://artifact/sha256:").unwrap();
        let path = self.root.join("sha256").join(digest);
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
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
        Ok(uri)
    }

    pub fn uri(bytes: &[u8]) -> String {
        format!("gdbai://artifact/sha256:{:x}", Sha256::digest(bytes))
    }

    pub fn get(&self, uri: &str, max_bytes: usize) -> Result<Vec<u8>> {
        let digest = uri
            .strip_prefix("gdbai://artifact/sha256:")
            .filter(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "invalid artifact URI"))?;
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
        let digest = uri
            .strip_prefix("gdbai://artifact/sha256:")
            .filter(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "invalid artifact URI"))?;
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
        if !verified {
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
            let mut verified = self.verified.lock().map_err(|_| {
                Error::new(ErrorCode::Internal, "artifact verification cache poisoned")
            })?;
            // ponytail: Clear this small cache instead of adding an LRU. Add
            // one only if more than 1024 concurrently paged artifacts matter.
            if verified.len() >= 1024 {
                verified.clear();
            }
            verified.insert(digest.to_owned(), fingerprint);
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
}
