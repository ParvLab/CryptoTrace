use crate::error::{CryptoTraceError, Result};
use crate::types::{SanitizedInput, SourceType};
use std::path::{Path, PathBuf};

const DEFAULT_MAX_FILE_SIZE: usize = 50 * 1024 * 1024; // 50MB
const DEFAULT_MAX_STRING_SIZE: usize = 10 * 1024 * 1024; // 10MB

pub struct InputGuard {
    max_file_size: usize,
    max_string_size: usize,
    allowed_base_dir: Option<PathBuf>,
}

impl InputGuard {
    pub fn new() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_string_size: DEFAULT_MAX_STRING_SIZE,
            allowed_base_dir: None,
        }
    }

    pub fn with_max_file_size(mut self, size: usize) -> Self {
        self.max_file_size = size;
        self
    }

    pub fn with_max_string_size(mut self, size: usize) -> Self {
        self.max_string_size = size;
        self
    }

    pub fn with_allowed_base_dir(mut self, dir: PathBuf) -> Self {
        self.allowed_base_dir = Some(dir);
        self
    }

    pub fn sanitize_bytes(
        &self,
        bytes: Vec<u8>,
        source_type: SourceType,
    ) -> Result<SanitizedInput> {
        let original_length = bytes.len();
        let max_size = match source_type {
            SourceType::String => self.max_string_size,
            SourceType::File | SourceType::Binary => self.max_file_size,
        };

        if original_length > max_size {
            return Err(CryptoTraceError::InputTooLarge {
                size: original_length,
                max: max_size,
            });
        }

        let has_null_bytes = bytes.contains(&0x00);

        // Reject null bytes in ALL inputs (string, file, binary)
        if has_null_bytes {
            return Err(CryptoTraceError::NullBytesInString);
        }

        Ok(SanitizedInput {
            raw_bytes: bytes,
            source_type,
            original_length,
            was_truncated: false,
            safe: true,
            has_null_bytes,
            resolved_path: None,
        })
    }

    pub fn sanitize_file(&self, path: &Path) -> Result<SanitizedInput> {
        // Resolve symlinks
        let real_path = std::fs::canonicalize(path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot resolve path: {}", e)))?;

        // Check for directory traversal / symlink escape
        if let Some(ref base) = self.allowed_base_dir {
            let base_canonical = std::fs::canonicalize(base)
                .map_err(|e| CryptoTraceError::Other(format!("Cannot resolve base dir: {}", e)))?;
            if !real_path.starts_with(&base_canonical) {
                return Err(CryptoTraceError::SymlinkEscape);
            }
        }

        let bytes = std::fs::read(&real_path)?;
        let mut result = self.sanitize_bytes(bytes, SourceType::File)?;
        result.resolved_path = Some(real_path);
        Ok(result)
    }

    pub fn sanitize_string(&self, input: &str) -> Result<SanitizedInput> {
        self.sanitize_bytes(input.as_bytes().to_vec(), SourceType::String)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sanitize_string_valid() {
        let guard = InputGuard::new();
        let result = guard.sanitize_string("hello world").unwrap();
        assert!(result.safe);
        assert!(!result.has_null_bytes);
    }

    #[test]
    fn test_sanitize_string_null_bytes() {
        let guard = InputGuard::new();
        let result = guard.sanitize_string("hello\0world");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoTraceError::NullBytesInString
        ));
    }

    #[test]
    fn test_sanitize_string_oversized() {
        let guard = InputGuard::new().with_max_string_size(10);
        let result = guard.sanitize_string("hello world this is too long");
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_file_valid() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"test data").unwrap();
        let guard = InputGuard::new();
        let result = guard.sanitize_file(file.path()).unwrap();
        assert!(result.safe);
        assert_eq!(result.original_length, 9);
    }

    #[test]
    fn test_sanitize_file_oversized() {
        let file = NamedTempFile::new().unwrap();
        let data = vec![0u8; 60 * 1024 * 1024];
        std::fs::write(file.path(), &data).unwrap();
        let guard = InputGuard::new().with_max_file_size(50 * 1024 * 1024);
        let result = guard.sanitize_file(file.path());
        assert!(result.is_err());
    }
}
