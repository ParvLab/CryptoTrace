#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cryptotrace::analyzers::file::analyze_bytes(data, cryptotrace::types::SourceType::Binary);
});
