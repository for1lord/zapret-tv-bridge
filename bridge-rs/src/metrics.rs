use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Lock-free proxy performance and connection metrics.
pub struct ProxyMetrics {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub bytes_client_to_remote: AtomicU64,
    pub bytes_remote_to_client: AtomicU64,
    pub errors_count: AtomicU64,
}

impl Default for ProxyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyMetrics {
    /// Creates a new `ProxyMetrics` instance with all counters initialized to zero.
    pub fn new() -> Self {
        Self {
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            bytes_client_to_remote: AtomicU64::new(0),
            bytes_remote_to_client: AtomicU64::new(0),
            errors_count: AtomicU64::new(0),
        }
    }

    /// Increments upstream client-to-remote bytes transferred.
    #[inline]
    pub fn add_bytes_up(&self, bytes: u64) {
        self.bytes_client_to_remote.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increments downstream remote-to-client bytes transferred.
    #[inline]
    pub fn add_bytes_down(&self, bytes: u64) {
        self.bytes_remote_to_client.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increments the count of proxy errors encountered.
    #[inline]
    pub fn inc_errors(&self) {
        self.errors_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Obtains an RAII connection guard that increments `active_connections`
    /// and `total_connections` on creation, and decrements `active_connections` on drop.
    pub fn connection_guard(self: &Arc<Self>) -> ConnectionGuard {
        ConnectionGuard::new(Arc::clone(self))
    }

    /// Alias for `connection_guard`.
    pub fn enter_connection(self: &Arc<Self>) -> ConnectionGuard {
        self.connection_guard()
    }

    /// Takes a point-in-time snapshot of all metric values.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            bytes_client_to_remote: self.bytes_client_to_remote.load(Ordering::Relaxed),
            bytes_remote_to_client: self.bytes_remote_to_client.load(Ordering::Relaxed),
            errors_count: self.errors_count.load(Ordering::Relaxed),
        }
    }
}

/// RAII guard that manages the lifetime of an active connection counter.
///
/// Increments `active_connections` and `total_connections` when created,
/// and automatically decrements `active_connections` when dropped.
pub struct ConnectionGuard {
    metrics: Arc<ProxyMetrics>,
}

impl ConnectionGuard {
    /// Creates a new `ConnectionGuard` tracking a connection.
    pub fn new(metrics: Arc<ProxyMetrics>) -> Self {
        metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        metrics.total_connections.fetch_add(1, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Point-in-time telemetry snapshot suitable for serialization and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct MetricsSnapshot {
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_client_to_remote: u64,
    pub bytes_remote_to_client: u64,
    pub errors_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_counters() {
        let metrics = Arc::new(ProxyMetrics::new());
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.bytes_client_to_remote.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.bytes_remote_to_client.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.errors_count.load(Ordering::Relaxed), 0);

        metrics.add_bytes_up(1024);
        metrics.add_bytes_down(4096);
        metrics.inc_errors();

        let snap = metrics.snapshot();
        assert_eq!(snap.bytes_client_to_remote, 1024);
        assert_eq!(snap.bytes_remote_to_client, 4096);
        assert_eq!(snap.errors_count, 1);
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.total_connections, 0);
    }

    #[test]
    fn test_raii_connection_guard() {
        let metrics = Arc::new(ProxyMetrics::new());
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 0);

        {
            let guard1 = metrics.connection_guard();
            assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 1);
            assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 1);

            {
                let guard2 = metrics.enter_connection();
                assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 2);
                assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 2);
                drop(guard2);
            }

            assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 1);
            assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 2);
            drop(guard1);
        }

        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_snapshot_serialization() {
        let metrics = Arc::new(ProxyMetrics::new());
        metrics.add_bytes_up(500);
        metrics.add_bytes_down(1500);
        metrics.inc_errors();

        let snap = metrics.snapshot();
        let json_str = serde_json::to_string(&snap).expect("Serialization failed");
        let deserialized: MetricsSnapshot = serde_json::from_str(&json_str).expect("Deserialization failed");

        assert_eq!(snap, deserialized);
        assert_eq!(deserialized.bytes_client_to_remote, 500);
        assert_eq!(deserialized.bytes_remote_to_client, 1500);
        assert_eq!(deserialized.errors_count, 1);
    }
}
