use serde::Serialize;
use serde_json::json;

pub enum Format {
    Json,
    Text,
}

pub fn print_success<T: Serialize>(format: &Format, command: &str, data: &T) {
    match format {
        Format::Json => {
            let output = json!({
                "ok": true,
                "command": command,
                "data": data,
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        Format::Text => {
            // Text mode: pretty-print the data
            println!("{}", serde_json::to_string_pretty(data).unwrap());
        }
    }
}

/// Emit a single NDJSON event line to stdout (for streaming commands).
pub fn ndjson_event(event: serde_json::Value) {
    use std::io::Write;
    let line = serde_json::to_string(&event).unwrap();
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{}", line);
    let _ = handle.flush();
}

pub fn print_error(format: &Format, error: &anyhow::Error) {
    match format {
        Format::Json => {
            let output = json!({
                "ok": false,
                "error": {
                    "code": "GENERAL_ERROR",
                    "message": format!("{}", error),
                    "retryable": false,
                }
            });
            eprintln!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        Format::Text => {
            eprintln!("Error: {}", error);
        }
    }
}
