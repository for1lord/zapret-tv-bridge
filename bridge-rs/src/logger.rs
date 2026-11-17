//! Size-bounded log file rotation and structured event logging.
//!
//! Keeps on-disk log files (`tv_proxy.log`, `tv_bridge_live.log`, `tg_proxy.log`)
//! capped at `DEFAULT_MAX_LOG_BYTES` (2 MB), rotating full files into `<name>.old`.

use parking_lot::Mutex;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum size of a single log file before rotation (2 MB).
pub const DEFAULT_MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

/// Standard runtime log files monitored by the housekeeping loop.
pub const WATCHED_LOG_FILES: &[&str] = &["tv_proxy.log", "tv_bridge_live.log", "tg_proxy.log"];

static LOG_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Builds the `<filename>.old` backup path for a given log file.
pub fn rotated_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".old");
    PathBuf::from(os)
}

/// Rotates `path` into `<path>.old` (overwriting any previous `.old` file) when
/// its size reaches or exceeds `max_bytes`.
///
/// Falls back to copy + in-place truncation if another process holds an open
/// shared handle on Windows (e.g. external `tgwsproxy.exe` or shell redirection).
pub fn rotate_log_file(path: &Path, max_bytes: u64) -> io::Result<bool> {
    let meta = match fs::metadata(path) {
        Ok(m) if m.is_file() => m,
        _ => return Ok(false),
    };

    if meta.len() < max_bytes {
        return Ok(false);
    }

    let _guard = LOG_WRITE_LOCK.lock();
    // Re-check under lock to avoid double rotation
    let current_len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if current_len < max_bytes {
        return Ok(false);
    }

    let old_path = rotated_path(path);
    let _ = fs::remove_file(&old_path);

    if fs::rename(path, &old_path).is_ok() {
        // Touch a fresh empty log file so readers/tailers find it immediately
        let _ = OpenOptions::new().create(true).append(true).open(path);
        return Ok(true);
    }

    // Fallback when file handle is held open by a child process or redirection
    fs::copy(path, &old_path)?;
    if let Ok(file) = OpenOptions::new().write(true).open(path) {
        let _ = file.set_len(0);
    }
    Ok(true)
}

/// Checks and rotates all standard bridge log files in `base_dir`.
/// Returns the number of files that were rotated.
pub fn rotate_all_logs(base_dir: &Path, max_bytes: u64) -> usize {
    let mut rotated = 0;
    for name in WATCHED_LOG_FILES {
        let p = base_dir.join(name);
        if let Ok(true) = rotate_log_file(&p, max_bytes) {
            rotated += 1;
        }
    }
    rotated
}

/// Appends a timestamped line to `tv_proxy.log`, rotating at 2 MB automatically.
pub fn append_daemon_log(base_dir: &Path, line: &str) {
    let log_path = base_dir.join("tv_proxy.log");
    let _ = rotate_log_file(&log_path, DEFAULT_MAX_LOG_BYTES);

    let _guard = LOG_WRITE_LOCK.lock();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(file, "[{secs}] {line}");
    }
}

/// Returns true when verbose per-connection debug output is explicitly enabled.
#[inline]
pub fn verbose_logging_enabled() -> bool {
    static VERBOSE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *VERBOSE.get_or_init(|| {
        std::env::var("BRIDGE_VERBOSE")
            .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_rotation_creates_and_overwrites_old() {
        let dir = std::env::temp_dir().join(format!("zprt_log_rot_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("tv_proxy.log");
        let old_path = rotated_path(&log_path);

        // Below threshold -> no rotation
        fs::write(&log_path, vec![b'A'; 512]).unwrap();
        assert!(!rotate_log_file(&log_path, 1024).unwrap());
        assert!(!old_path.exists());

        // Exceeds threshold -> rotates into .old
        fs::write(&log_path, vec![b'B'; 1500]).unwrap();
        assert!(rotate_log_file(&log_path, 1024).unwrap());
        assert!(old_path.exists());
        assert_eq!(fs::metadata(&old_path).unwrap().len(), 1500);
        assert_eq!(fs::metadata(&log_path).unwrap().len(), 0);

        // Second rotation overwrites .old with newer data
        fs::write(&log_path, vec![b'C'; 2048]).unwrap();
        assert!(rotate_log_file(&log_path, 1024).unwrap());
        let old_bytes = fs::read(&old_path).unwrap();
        assert_eq!(old_bytes.len(), 2048);
        assert!(old_bytes.iter().all(|&b| b == b'C'));

        let _ = fs::remove_dir_all(&dir);
    }
}
