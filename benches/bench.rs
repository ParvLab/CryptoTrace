use criterion::{Criterion, black_box, criterion_group, criterion_main};
use cryptotrace::analyzers::file::analyze_bytes;
use cryptotrace::types::SourceType;

fn bench_analyze_plaintext(c: &mut Criterion) {
    let data = b"The quick brown fox jumps over the lazy dog";
    c.bench_function("analyze_plaintext", |b| {
        b.iter(|| analyze_bytes(black_box(data), SourceType::String))
    });
}

fn bench_analyze_md5(c: &mut Criterion) {
    let data = b"5f4dcc3b5aa765d61d8327deb882cf99";
    c.bench_function("analyze_md5_hash", |b| {
        b.iter(|| analyze_bytes(black_box(data), SourceType::String))
    });
}

fn bench_analyze_base64(c: &mut Criterion) {
    let data = b"SGVsbG8gQ3J5cHRvVHJhY2Uh";
    c.bench_function("analyze_base64", |b| {
        b.iter(|| analyze_bytes(black_box(data), SourceType::String))
    });
}

fn bench_analyze_large_data(c: &mut Criterion) {
    let data = vec![b'A'; 1024 * 1024]; // 1 MB
    c.bench_function("analyze_1mb_plaintext", |b| {
        b.iter(|| analyze_bytes(black_box(&data), SourceType::Binary))
    });
}

fn bench_analyze_high_entropy(c: &mut Criterion) {
    use rand::Rng;
    let mut rng = rand::rng();
    let data: Vec<u8> = (0..65536).map(|_| rng.random()).collect();
    c.bench_function("analyze_64kb_random", |b| {
        b.iter(|| analyze_bytes(black_box(&data), SourceType::Binary))
    });
}

criterion_group!(
    benches,
    bench_analyze_plaintext,
    bench_analyze_md5,
    bench_analyze_base64,
    bench_analyze_large_data,
    bench_analyze_high_entropy,
);

criterion_main!(benches);
