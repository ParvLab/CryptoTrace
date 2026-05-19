use cryptotrace::core::compression::{detect_compression, try_decompress};

fn make_gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn make_bzip2(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn make_zstd(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 1).unwrap()
}

fn make_brotli(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 1, 22);
    encoder.write_all(data).unwrap();
    encoder.into_inner()
}

fn make_lz4(data: &[u8]) -> Vec<u8> {
    use lz4_flex::frame::FrameEncoder;
    use std::io::Write;
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn test_gzip_detect_and_decompress() {
    let compressed = make_gzip(b"CryptoTrace accuracy test");
    let detection = detect_compression(&compressed).unwrap();
    assert_eq!(detection.format, "GZIP");
    let result = try_decompress(&compressed, "GZIP").unwrap();
    assert_eq!(result.data, b"CryptoTrace accuracy test");
}

#[test]
fn test_bzip2_detect_and_decompress() {
    let compressed = make_bzip2(b"BZ2 accuracy test");
    let detection = detect_compression(&compressed).unwrap();
    assert_eq!(detection.format, "BZ2");
    let result = try_decompress(&compressed, "BZ2").unwrap();
    assert_eq!(result.data, b"BZ2 accuracy test");
}

#[test]
fn test_zstd_detect_and_decompress() {
    let compressed = make_zstd(b"Zstd accuracy test");
    let detection = detect_compression(&compressed).unwrap();
    assert_eq!(detection.format, "Zstd");
    let result = try_decompress(&compressed, "Zstd").unwrap();
    assert_eq!(result.data, b"Zstd accuracy test");
}

#[test]
fn test_brotli_decompress() {
    let compressed = make_brotli(b"Brotli accuracy test");
    // Brotli has no reliable magic bytes, so detection won't match via magic
    let detection = detect_compression(&compressed);
    assert!(detection.is_none(), "Brotli has no magic bytes");
    // But decompression should work
    let result = try_decompress(&compressed, "Brotli").unwrap();
    assert_eq!(result.data, b"Brotli accuracy test");
}

#[test]
fn test_lz4_detect_and_decompress() {
    let compressed = make_lz4(b"LZ4 accuracy test");
    let detection = detect_compression(&compressed).unwrap();
    assert_eq!(detection.format, "LZ4");
    let result = try_decompress(&compressed, "LZ4").unwrap();
    assert_eq!(result.data, b"LZ4 accuracy test");
}

#[test]
fn test_negative_no_false_positive() {
    let result = detect_compression(b"hello world plaintext");
    assert!(result.is_none());
}
