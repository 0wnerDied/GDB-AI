use std::{fs::OpenOptions, io::Write, path::PathBuf};

use sha2::{Digest, Sha256};

use crate::{Error, ErrorCode, Result};

#[derive(Clone, Debug)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("sha256"))?;
        Ok(Self { root })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<String> {
        let digest = format!("{:x}", Sha256::digest(bytes));
        let path = self.root.join("sha256").join(&digest);
        match OpenOptions::new().create_new(true).write(true).open(path) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        Ok(format!("gdbai://artifact/sha256:{digest}"))
    }

    pub fn get(&self, uri: &str, max_bytes: usize) -> Result<Vec<u8>> {
        let digest = uri
            .strip_prefix("gdbai://artifact/sha256:")
            .filter(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "invalid artifact URI"))?;
        let bytes = std::fs::read(self.root.join("sha256").join(digest))?;
        if bytes.len() > max_bytes {
            return Err(Error::new(
                ErrorCode::OutputLimit,
                format!("artifact is {} bytes; limit is {max_bytes}", bytes.len()),
            ));
        }
        Ok(bytes)
    }
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
        assert!(matches!(
            store.get(&uri, 7),
            Err(Error {
                code: ErrorCode::OutputLimit,
                ..
            })
        ));
    }
}
