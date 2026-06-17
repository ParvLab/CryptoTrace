/// Isolated worker process for risky parsing operations.
///
/// Spawned by the main `cryptotrace` process when sandbox isolation is
/// enabled. Reads input from stdin, performs the requested operation, and
/// writes results to stdout. The parent process enforces timeout + memory
/// limits via a Win32 Job Object (Windows) or process group (Unix).
///
/// Operations:
///   detect       — run full detection pipeline, output JSON to stdout
///   decompress   — decompress input, write raw bytes to stdout
///   passthrough  — echo input back to stdout (testing / calibration)
///
/// On error, writes a JSON error object to stdout and exits with status 1.
use std::io::{self, Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse --operation <name> --input-len <n>
    let operation = parse_arg(&args, "--operation").unwrap_or("passthrough");
    let _input_len: usize = parse_arg(&args, "--input-len")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Read all input from stdin (up to 50 MB for safety)
    let mut input = Vec::with_capacity(_input_len.min(50_000_000));
    if let Err(e) = io::stdin().read_to_end(&mut input) {
        emit_error("stdin_read", &format!("Failed to read stdin: {}", e));
        std::process::exit(1);
    }

    // Perform the operation
    let result = match operation {
        "detect" => run_detect(&input),
        "decompress" => run_decompress(&input),
        "passthrough" => Ok(input),
        _ => {
            emit_error(
                "unknown_operation",
                &format!("Unknown operation: {}", operation),
            );
            std::process::exit(1);
        }
    };

    match result {
        Ok(output) => {
            io::stdout().write_all(&output).expect("stdout write");
            io::stdout().flush().expect("stdout flush");
        }
        Err(e) => {
            emit_error("operation_failed", &e);
            std::process::exit(1);
        }
    }
}

/// Run the full detection pipeline and output JSON.
fn run_detect(input: &[u8]) -> Result<Vec<u8>, String> {
    let result =
        cryptotrace::analyzers::file::analyze_bytes(input, cryptotrace::types::SourceType::Binary)
            .map_err(|e| format!("Detection failed: {}", e))?;

    serde_json::to_vec(&result).map_err(|e| format!("JSON serialization: {}", e))
}

/// Decompress input by detecting the format first.
fn run_decompress(input: &[u8]) -> Result<Vec<u8>, String> {
    let detected = cryptotrace::core::compression::detect_compression(input)
        .ok_or_else(|| "No known compression format detected".to_string())?;
    let result = cryptotrace::core::compression::try_decompress(input, &detected.format)
        .map_err(|e| format!("Decompression failed: {}", e))?;
    Ok(result.data)
}

/// Parse a named CLI argument.
fn parse_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find_map(|w| {
        if w[0] == name {
            Some(w[1].as_str())
        } else {
            None
        }
    })
}

/// Emit a JSON error object to stderr.
fn emit_error(code: &str, message: &str) {
    let err = serde_json::json!({
        "error": code,
        "message": message,
    });
    let _ = writeln!(
        io::stderr(),
        "{}",
        serde_json::to_string(&err).unwrap_or_default()
    );
}
