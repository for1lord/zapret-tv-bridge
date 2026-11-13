use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use memmap2::Mmap;
use parking_lot::{Mutex, RwLock};

pub const MAGIC: u32 = 0x5A505254; // "ZPRT"
pub const FORMAT_VERSION: u16 = 2;
pub const HEADER_SIZE: u16 = 64;
pub const BUCKET_TABLE_ENTRIES: usize = 256;
pub const BUCKET_TABLE_SIZE: usize = BUCKET_TABLE_ENTRIES * std::mem::size_of::<BucketEntry>(); // 2048
pub const PAYLOAD_OFFSET: u32 = (HEADER_SIZE as u32) + (BUCKET_TABLE_SIZE as u32); // 2112

static COMPILE_LOCK: Mutex<()> = Mutex::new(());

/// 64-byte aligned binary format v2 header for routing rules cache.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryHeaderV2 {
    /// Magic signature: 0x5A505254 ("ZPRT")
    pub magic: u32,
    /// Format version (2)
    pub version: u16,
    /// Header size in bytes (64)
    pub header_size: u16,
    /// Unix timestamp in seconds of newest source file when compiled
    pub source_mtime_epoch: u64,
    /// Total count of domains across all length buckets in rules dataset
    pub total_domain_count: u32,
    /// Byte offset to the 2048-byte Bucket Index Table (64)
    pub bucket_table_offset: u32,
    /// Length of the Bucket Index Table in bytes (2048)
    pub bucket_table_len: u32,
    /// Byte offset to the contiguous ASCII domain payload (2112)
    pub payload_offset: u32,
    /// Byte length of the contiguous domain payload
    pub payload_len: u32,
    /// Byte offset where the 64-byte aligned CIDR interval tables begin
    pub cidr_table_offset: u32,
    /// Total byte length of the CIDR section
    pub cidr_table_len: u32,
    /// Count of target IPv4 CIDR intervals
    pub target_ipv4_cidr_count: u16,
    /// Count of exclude IPv4 CIDR intervals
    pub exclude_ipv4_cidr_count: u16,
    /// Count of target IPv6 CIDR intervals
    pub target_ipv6_cidr_count: u16,
    /// Count of exclude IPv6 CIDR intervals
    pub exclude_ipv6_cidr_count: u16,
    /// Count of domains in target lists (list-general, list-google, etc.)
    pub target_list_domain_count: u32,
    /// Count of domains in exclude lists (list-exclude, etc.)
    pub exclude_list_domain_count: u32,
    /// Reserved or CRC32 checksum
    pub checksum: u32,
}

impl BinaryHeaderV2 {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.header_size.to_le_bytes());
        buf[8..16].copy_from_slice(&self.source_mtime_epoch.to_le_bytes());
        buf[16..20].copy_from_slice(&self.total_domain_count.to_le_bytes());
        buf[20..24].copy_from_slice(&self.bucket_table_offset.to_le_bytes());
        buf[24..28].copy_from_slice(&self.bucket_table_len.to_le_bytes());
        buf[28..32].copy_from_slice(&self.payload_offset.to_le_bytes());
        buf[32..36].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[36..40].copy_from_slice(&self.cidr_table_offset.to_le_bytes());
        buf[40..44].copy_from_slice(&self.cidr_table_len.to_le_bytes());
        buf[44..46].copy_from_slice(&self.target_ipv4_cidr_count.to_le_bytes());
        buf[46..48].copy_from_slice(&self.exclude_ipv4_cidr_count.to_le_bytes());
        buf[48..50].copy_from_slice(&self.target_ipv6_cidr_count.to_le_bytes());
        buf[50..52].copy_from_slice(&self.exclude_ipv6_cidr_count.to_le_bytes());
        buf[52..56].copy_from_slice(&self.target_list_domain_count.to_le_bytes());
        buf[56..60].copy_from_slice(&self.exclude_list_domain_count.to_le_bytes());
        buf[60..64].copy_from_slice(&self.checksum.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 64 {
            return Err("Buffer too small for BinaryHeaderV2");
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err("Invalid magic bytes in header");
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        if version != FORMAT_VERSION {
            return Err("Unsupported binary format version");
        }
        let header_size = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        if header_size != HEADER_SIZE {
            return Err("Invalid header size");
        }
        let source_mtime_epoch = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let total_domain_count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let bucket_table_offset = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let bucket_table_len = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let payload_offset = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
        let payload_len = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let cidr_table_offset = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
        let cidr_table_len = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
        let target_ipv4_cidr_count = u16::from_le_bytes(bytes[44..46].try_into().unwrap());
        let exclude_ipv4_cidr_count = u16::from_le_bytes(bytes[46..48].try_into().unwrap());
        let target_ipv6_cidr_count = u16::from_le_bytes(bytes[48..50].try_into().unwrap());
        let exclude_ipv6_cidr_count = u16::from_le_bytes(bytes[50..52].try_into().unwrap());
        let target_list_domain_count = u32::from_le_bytes(bytes[52..56].try_into().unwrap());
        let exclude_list_domain_count = u32::from_le_bytes(bytes[56..60].try_into().unwrap());
        let checksum = u32::from_le_bytes(bytes[60..64].try_into().unwrap());

        Ok(Self {
            magic,
            version,
            header_size,
            source_mtime_epoch,
            total_domain_count,
            bucket_table_offset,
            bucket_table_len,
            payload_offset,
            payload_len,
            cidr_table_offset,
            cidr_table_len,
            target_ipv4_cidr_count,
            exclude_ipv4_cidr_count,
            target_ipv6_cidr_count,
            exclude_ipv6_cidr_count,
            target_list_domain_count,
            exclude_list_domain_count,
            checksum,
        })
    }
}

/// 8-byte entry in the 256-element direct length index table.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BucketEntry {
    /// Byte offset where the contiguous words of length L start
    pub offset: u32,
    /// Total bytes for this bucket (domain count = byte_len / L)
    pub byte_len: u32,
}

/// Closed integer interval [start, end] for IPv4 addresses.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Interval {
    pub start: u32,
    pub end: u32,
}

/// Closed integer interval [start, end] for IPv6 addresses.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Interval {
    pub start: u128,
    pub end: u128,
}

/// Parses an IPv4 CIDR string or bare IPv4 address into an `Ipv4Interval`.
pub fn parse_ipv4_cidr(line: &str) -> Result<Ipv4Interval, String> {
    let clean = line.split('#').next().unwrap_or("").trim();
    if clean.is_empty() {
        return Err("Empty line".to_string());
    }
    let (ip_part, pfx_part) = match clean.split_once('/') {
        Some((ip, pfx)) => (ip.trim(), Some(pfx.trim())),
        None => (clean, None),
    };
    let ip: Ipv4Addr = ip_part.parse().map_err(|e| format!("Invalid IPv4 {ip_part}: {e}"))?;
    let prefix_len: u8 = match pfx_part {
        Some(p) => p.parse().map_err(|e| format!("Invalid prefix {p}: {e}"))?,
        None => 32,
    };
    if prefix_len > 32 {
        return Err(format!("Prefix length {prefix_len} > 32"));
    }
    let ip_u32 = u32::from(ip);
    let mask = if prefix_len == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix_len)
    };
    let start = ip_u32 & mask;
    let end = start | (!mask);
    Ok(Ipv4Interval { start, end })
}

/// Parses an IPv6 CIDR string or bare IPv6 address into an `Ipv6Interval`.
pub fn parse_ipv6_cidr(line: &str) -> Result<Ipv6Interval, String> {
    let clean = line.split('#').next().unwrap_or("").trim();
    if clean.is_empty() {
        return Err("Empty line".to_string());
    }
    let (ip_part, pfx_part) = match clean.split_once('/') {
        Some((ip, pfx)) => (ip.trim(), Some(pfx.trim())),
        None => (clean, None),
    };
    let ip: Ipv6Addr = ip_part.parse().map_err(|e| format!("Invalid IPv6 {ip_part}: {e}"))?;
    let prefix_len: u8 = match pfx_part {
        Some(p) => p.parse().map_err(|e| format!("Invalid prefix {p}: {e}"))?,
        None => 128,
    };
    if prefix_len > 128 {
        return Err(format!("Prefix length {prefix_len} > 128"));
    }
    let ip_u128 = u128::from(ip);
    let mask = if prefix_len == 0 {
        0u128
    } else {
        u128::MAX << (128 - prefix_len)
    };
    let start = ip_u128 & mask;
    let end = start | (!mask);
    Ok(Ipv6Interval { start, end })
}

/// Merges overlapping and contiguous/adjacent IPv4 intervals.
pub fn merge_ipv4_intervals(mut intervals: Vec<Ipv4Interval>) -> Vec<Ipv4Interval> {
    if intervals.is_empty() {
        return Vec::new();
    }
    intervals.sort_unstable_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));

    let mut merged = Vec::with_capacity(intervals.len());
    let mut current = intervals[0];

    for next in intervals.into_iter().skip(1) {
        if next.start <= current.end.saturating_add(1) {
            if next.end > current.end {
                current.end = next.end;
            }
        } else {
            merged.push(current);
            current = next;
        }
    }
    merged.push(current);
    merged.shrink_to_fit();
    merged
}

/// Merges overlapping and contiguous/adjacent IPv6 intervals.
pub fn merge_ipv6_intervals(mut intervals: Vec<Ipv6Interval>) -> Vec<Ipv6Interval> {
    if intervals.is_empty() {
        return Vec::new();
    }
    intervals.sort_unstable_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));

    let mut merged = Vec::with_capacity(intervals.len());
    let mut current = intervals[0];

    for next in intervals.into_iter().skip(1) {
        if next.start <= current.end.saturating_add(1) {
            if next.end > current.end {
                current.end = next.end;
            }
        } else {
            merged.push(current);
            current = next;
        }
    }
    merged.push(current);
    merged.shrink_to_fit();
    merged
}

/// Fast O(log N) binary search check if an IPv4 address is contained in sorted disjoint intervals.
#[inline]
pub fn contains_ipv4(intervals: &[Ipv4Interval], addr: u32) -> bool {
    let mut left = 0;
    let mut right = intervals.len();

    while left < right {
        let mid = left + (right - left) / 2;
        let entry = &intervals[mid];
        if addr < entry.start {
            right = mid;
        } else if addr > entry.end {
            left = mid + 1;
        } else {
            return true;
        }
    }
    false
}

/// Fast O(log N) binary search check if an IPv6 address is contained in sorted disjoint intervals.
#[inline]
pub fn contains_ipv6(intervals: &[Ipv6Interval], addr: u128) -> bool {
    let mut left = 0;
    let mut right = intervals.len();

    while left < right {
        let mid = left + (right - left) / 2;
        let entry = &intervals[mid];
        if addr < entry.start {
            right = mid;
        } else if addr > entry.end {
            left = mid + 1;
        } else {
            return true;
        }
    }
    false
}

/// Stack-allocated RFC 1035 domain normalizer (0 heap allocations).
#[derive(Clone, Copy, Debug)]
pub struct NormalizedDomain {
    buf: [u8; 256],
    len: u8,
}

impl NormalizedDomain {
    /// Normalizes host: strips port/brackets, trims root dot, lowercases ASCII.
    #[inline]
    pub fn try_from_str(host: &str) -> Option<Self> {
        let host_part = if host.starts_with('[') {
            if let Some(bracket_end) = host.find(']') {
                &host[1..bracket_end]
            } else {
                host
            }
        } else if let Some((h, port)) = host.split_once(':') {
            if port.contains(':') {
                host
            } else {
                h
            }
        } else {
            host
        };

        let trimmed = host_part.trim_matches('.');
        let bytes = trimmed.as_bytes();
        let len = bytes.len();

        if len == 0 || len > 253 {
            return None;
        }

        let mut buf = [0u8; 256];
        for (i, &b) in bytes.iter().enumerate() {
            buf[i] = b.to_ascii_lowercase();
        }

        Some(Self {
            buf,
            len: len as u8,
        })
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    #[inline(always)]
    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.as_bytes()) }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Formats an IPv4 address into a stack buffer without heap allocation.
#[inline]
pub fn format_ipv4_stack(ip: Ipv4Addr, buf: &mut [u8; 16]) -> &str {
    let mut cursor = Cursor::new(&mut buf[..]);
    let _ = write!(cursor, "{}", ip);
    let len = cursor.position() as usize;
    unsafe { std::str::from_utf8_unchecked(&buf[..len]) }
}

/// Zero-allocation domain suffix iterator yielding sub-slices &[u8].
pub struct DomainSuffixIter<'a> {
    slice: &'a [u8],
    offset: usize,
    finished: bool,
}

impl<'a> DomainSuffixIter<'a> {
    #[inline(always)]
    pub fn new(slice: &'a [u8]) -> Self {
        Self {
            slice,
            offset: 0,
            finished: slice.is_empty(),
        }
    }
}

impl<'a> Iterator for DomainSuffixIter<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let current = &self.slice[self.offset..];
        if let Some(pos) = current.iter().position(|&b| b == b'.') {
            self.offset += pos + 1;
            Some(current)
        } else {
            self.finished = true;
            Some(current)
        }
    }
}

/// Binary search with early exit over fixed-width words in mapped slice.
#[inline(always)]
pub fn binary_search_bucket(bucket_bytes: &[u8], word_len: usize, target: &[u8]) -> bool {
    let chunk_count = bucket_bytes.len() / word_len;
    if chunk_count == 0 {
        return false;
    }
    let mut left = 0;
    let mut right = chunk_count;

    while left < right {
        let mid = left + (right - left) / 2;
        let offset = mid * word_len;
        let word = &bucket_bytes[offset..offset + word_len];
        match target.cmp(word) {
            std::cmp::Ordering::Less => right = mid,
            std::cmp::Ordering::Greater => left = mid + 1,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

/// Common routing engine contract across proxy and web modules.
pub trait RoutingEngine: Send + Sync {
    fn should_route(&self, host: &str) -> (bool, &'static str);
    fn should_route_ip(&self, ip: IpAddr) -> (bool, &'static str);
}

/// Smart routing filter with memory-mapped binary cache v2, zero-heap matching,
/// and fast CIDR subnet intervals.
pub struct SmartRouter {
    pub base_dir: PathBuf,
    pub lists_dir: PathBuf,
    mmap: Option<Mmap>,
    bucket_table: [BucketEntry; BUCKET_TABLE_ENTRIES],
    header: Option<BinaryHeaderV2>,
    target_domains: Arc<RwLock<HashSet<String>>>,
    user_domains: Arc<RwLock<HashSet<String>>>,
    exclude_domains: Arc<RwLock<HashSet<String>>>,
    auto_added_domains: Arc<RwLock<HashSet<String>>>,
    target_v4: Vec<Ipv4Interval>,
    exclude_v4: Vec<Ipv4Interval>,
    target_v6: Vec<Ipv6Interval>,
    exclude_v6: Vec<Ipv6Interval>,
    database_v4: Vec<Ipv4Interval>,
}

static RELOAD_ARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static RELOAD_NOTIFY: std::sync::LazyLock<std::sync::mpsc::Sender<()>> = std::sync::LazyLock::new(|| {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let _ = std::thread::Builder::new()
        .name("zapret-reload".into())
        .spawn(move || {
            while rx.recv().is_ok() {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                while std::time::Instant::now() < deadline {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    if rx.recv_timeout(left).is_err() {
                        break;
                    }
                }
                while rx.try_recv().is_ok() {}
                if !RELOAD_ARMED.load(std::sync::atomic::Ordering::Relaxed) {
                    continue;
                }
                restart_zapret_service();
            }
        });
    tx
});

/// Enables the debounced Zapret service restart after a new hostlist line is written.
pub fn arm_service_reload() {
    RELOAD_ARMED.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn restart_zapret_service() {
    println!("[SmartRouter] Reloading Zapret DPI service with updated hostlists...");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let _ = std::process::Command::new("sc")
            .args(["stop", "zapret"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        std::thread::sleep(std::time::Duration::from_millis(800));
        let _ = std::process::Command::new("sc")
            .args(["start", "zapret"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
}

/// Domains the bridge itself always sends through the PC.
pub const PROXY_SUFFIXES: &[&str] = &[
    "googlevideo.com",
    "youtube.com",
    "video.google.com",
    "ytimg.com",
    "ggpht.com",
    "youtu.be",
    "youtubei.googleapis.com",
    "fonts.googleapis.com",
    "jnn-pa.googleapis.com",
    "gstatic.com",
    "game.clashroyaleapp.com",
    "game.brawlstarsgame.com",
    "game.clashofclans.com",
    "game.squadbustersgame.com",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "storage.googleapis.com",
    "commondatastorage.googleapis.com",
    "instagram.com",
    "cdninstagram.com",
    "fbcdn.net",
    "facebook.com",
    "threads.net",
    "ig.me",
    "meta.com",
    "fbsbx.com",
    "twitter.com",
    "twimg.com",
    "x.com",
    "twitch.tv",
    "ttvnw.net",
    "jtvnw.net",
    "twitchcdn.net",
    "ext-twitch.tv",
    "live-video.net",
    "rutracker.org",
    "rutracker.cc",
    "rutracker.net",
    "rutor.org",
    "rutor.info",
    "rutor.is",
    "nnmclub.to",
    "flibusta.is",
    "flibusta.site",
    "pornhub.com",
    "pornhub.org",
    "pornhubpremium.com",
    "phncdn.com",
    "phprcdn.com",
    "phnstatic.com",
    "mainhub.com",
    "etahub.com",
    "aylo.com",
    "nsimg.net",
    "geekadm.net",
    "rncdn7.com",
    "trafficjunky.com",
    "trafficjunky.net",
    "xhamster.com",
    "xhcdn.com",
    "xvideos.com",
    "xv-cdn.com",
    "youporn.com",
    "ypncdn.com",
    "redtube.com",
    "redtubecdn.com",
    "eporner.com",
    "tube8.com",
    "spankwire.com",
    "hwcdn.net",
    "futanari.xxx",
    "hanime1.me",
    "hanime.tv",
    "hanime-cdn.com",
    "hanimeone.me",
    "hembed.com",
    "moeli-desu.com",
    "daradara.me",
];

/// Domains that stay off the bridge even if a broader list contains them.
pub const DIRECT_SUFFIXES: &[&str] = &[
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "gvt1.com",
    "geohide.ru",
    "dns-ai.ru",
    "chatgpt.com",
    "openai.com",
    "anthropic.com",
    "claude.ai",
    "apple.com",
    "mzstatic.com",
    "icloud.com",
    "itunes.com",
    "aaplimg.com",
    "akadns.net",
    "microsoft.com",
    "windowsupdate.com",
    "supercell.com",
    "supercellid.com",
    "clashroyale.com",
    "brawlstars.com",
    "clashofclans.com",
    "yandex.ru",
    "yandex.net",
    "vk.com",
    "vk.ru",
    "gosuslugi.ru",
    "sberbank.ru",
    "sber.ru",
    "ozon.ru",
    "wildberries.ru",
    "tinkoff.ru",
    "mail.ru",
];

/// A label with no dot matches only the full host, so a database entry `ua` does not capture every `.ua` name.
fn suffix_is_matchable(full: &[u8], suffix: &[u8]) -> bool {
    suffix.contains(&b'.') || suffix.len() == full.len()
}

fn clean_domain_name(domain: &str) -> Option<String> {
    let norm = NormalizedDomain::try_from_str(domain)?;
    let text = norm.as_str();
    if text.parse::<IpAddr>().is_ok() {
        return None;
    }
    if text.is_empty()
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(text.to_string())
}

fn shortest_static_suffix(domain: &str) -> Option<String> {
    PROXY_SUFFIXES
        .iter()
        .copied()
        .filter(|suffix| host_has_suffix(domain, suffix))
        .min_by_key(|suffix| suffix.len())
        .map(|suffix| suffix.to_string())
}

/// True when `domain` is exactly `suffix` or a subdomain of it.
#[inline]
pub fn host_has_suffix(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    domain.len() > suffix.len()
        && domain.as_bytes().get(domain.len() - suffix.len() - 1) == Some(&b'.')
        && domain.ends_with(suffix)
}

pub fn host_matches_any(domain: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|suffix| host_has_suffix(domain, suffix))
}

const BIG_LIST_BYTES: u64 = 256 * 1024;

impl SmartRouter {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        let base_dir = base_dir.as_ref().to_path_buf();
        let lists_dir = base_dir.join("lists");

        let mut router = Self {
            base_dir,
            lists_dir,
            mmap: None,
            bucket_table: [BucketEntry::default(); BUCKET_TABLE_ENTRIES],
            header: None,
            target_domains: Arc::new(RwLock::new(HashSet::new())),
            user_domains: Arc::new(RwLock::new(HashSet::new())),
            exclude_domains: Arc::new(RwLock::new(HashSet::new())),
            auto_added_domains: Arc::new(RwLock::new(HashSet::new())),
            target_v4: Vec::new(),
            exclude_v4: Vec::new(),
            target_v6: Vec::new(),
            exclude_v6: Vec::new(),
            database_v4: Vec::new(),
        };

        router.reload_lists();
        router.load_database();
        router
    }

    /// Loads domain and CIDR rules from disk list files.
    pub fn reload_lists(&mut self) {
        let mut new_target = HashSet::new();
        let mut new_user = HashSet::new();
        let mut new_exclude = HashSet::new();

        Self::load_list_file_bounded(self.lists_dir.join("list-general.txt"), &mut new_target);
        Self::load_list_file(self.lists_dir.join("list-google.txt"), &mut new_target);
        Self::load_list_file(self.lists_dir.join("list-general-user.txt"), &mut new_user);
        Self::load_list_file(self.lists_dir.join("list-exclude.txt"), &mut new_exclude);
        Self::load_list_file(self.lists_dir.join("list-exclude-user.txt"), &mut new_exclude);

        let mut target_v4 = Vec::new();
        let mut target_v6 = Vec::new();
        let mut exclude_v4 = Vec::new();
        let mut exclude_v6 = Vec::new();

        Self::load_cidr_file(self.lists_dir.join("ipset-target.txt"), &mut target_v4, &mut target_v6);
        Self::load_cidr_file(self.lists_dir.join("ipset-all.txt"), &mut target_v4, &mut target_v6);
        Self::load_cidr_file(self.lists_dir.join("ipset-exclude.txt"), &mut exclude_v4, &mut exclude_v6);
        Self::load_cidr_file(self.lists_dir.join("ipset-exclude-user.txt"), &mut exclude_v4, &mut exclude_v6);

        // Standard RFC 1918 + loopback fallbacks if exclude lists are empty
        if exclude_v4.is_empty() {
            let _ = parse_ipv4_cidr("127.0.0.0/8").map(|i| exclude_v4.push(i));
            let _ = parse_ipv4_cidr("10.0.0.0/8").map(|i| exclude_v4.push(i));
            let _ = parse_ipv4_cidr("172.16.0.0/12").map(|i| exclude_v4.push(i));
            let _ = parse_ipv4_cidr("192.168.0.0/16").map(|i| exclude_v4.push(i));
            let _ = parse_ipv4_cidr("169.254.0.0/16").map(|i| exclude_v4.push(i));
        }
        if exclude_v6.is_empty() {
            let _ = parse_ipv6_cidr("::1/128").map(|i| exclude_v6.push(i));
            let _ = parse_ipv6_cidr("fe80::/10").map(|i| exclude_v6.push(i));
            let _ = parse_ipv6_cidr("fc00::/7").map(|i| exclude_v6.push(i));
        }

        self.target_v4 = merge_ipv4_intervals(target_v4);
        self.exclude_v4 = merge_ipv4_intervals(exclude_v4);
        self.target_v6 = merge_ipv6_intervals(target_v6);
        self.exclude_v6 = merge_ipv6_intervals(exclude_v6);

        *self.target_domains.write() = new_target;
        *self.user_domains.write() = new_user;
        *self.exclude_domains.write() = new_exclude;
    }

    /// Loads a domain file unless it is the multi-megabyte anticensority list.
    /// That list is already searched through the memory-mapped binary cache.
    fn load_list_file_bounded<P: AsRef<Path>>(path: P, target: &mut HashSet<String>) {
        let path = path.as_ref();
        match fs::metadata(path) {
            Ok(meta) if meta.len() > BIG_LIST_BYTES => {
                eprintln!(
                    "[SmartRouter] {} is {:.1} MB and stays in the binary cache",
                    path.display(),
                    meta.len() as f64 / 1_048_576.0
                );
            }
            _ => Self::load_list_file(path, target),
        }
    }

    /// Loads list lines with comment stripping and wildcard normalization (*.phncdn.com -> phncdn.com).
    fn load_list_file<P: AsRef<Path>>(path: P, target: &mut HashSet<String>) {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let Ok(line) = line else {
                    continue;
                };
                let trimmed = line.split('#').next().unwrap_or("").trim().to_lowercase();
                if trimmed.is_empty() {
                    continue;
                }
                let norm = if let Some(stripped) = trimmed.strip_prefix("*.") {
                    stripped
                } else if let Some(stripped) = trimmed.strip_prefix('.') {
                    stripped
                } else {
                    &trimmed
                };
                let clean = norm.trim_matches('.');
                if !clean.is_empty() {
                    target.insert(clean.to_string());
                }
            }
        }
    }

    /// Loads CIDR entries from file into raw interval buffers.
    fn load_cidr_file<P: AsRef<Path>>(path: P, v4: &mut Vec<Ipv4Interval>, v6: &mut Vec<Ipv6Interval>) {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let Ok(line) = line else {
                    continue;
                };
                let trimmed = line.split('#').next().unwrap_or("").trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(interval) = parse_ipv4_cidr(trimmed) {
                    v4.push(interval);
                } else if let Ok(interval) = parse_ipv6_cidr(trimmed) {
                    v6.push(interval);
                }
            }
        }
    }

    /// Checks if binary cache is missing, corrupt, or stale compared to source files.
    pub fn is_compilation_needed<P: AsRef<Path>>(base_dir: P) -> bool {
        let base = base_dir.as_ref();
        let bin_path = base.join("routing_rules.bin");
        let json_path = base.join("routing_rules.json");

        if !json_path.exists() && !bin_path.exists() {
            return false;
        }

        let bin_meta = match fs::metadata(&bin_path) {
            Ok(m) => m,
            Err(_) => return true,
        };

        if bin_meta.len() < (HEADER_SIZE as u64) {
            return true;
        }

        // Validate existing binary cache header
        if let Ok(mut file) = File::open(&bin_path) {
            let mut header_buf = [0u8; 64];
            if file.read_exact(&mut header_buf).is_ok() {
                if let Ok(header) = BinaryHeaderV2::from_bytes(&header_buf) {
                    if header.magic != MAGIC
                        || header.version != FORMAT_VERSION
                        || header.header_size != HEADER_SIZE
                        || header.bucket_table_offset != 64
                        || header.bucket_table_len != 2048
                        || header.payload_offset != PAYLOAD_OFFSET
                    {
                        return true;
                    }
                } else {
                    return true;
                }
            } else {
                return true;
            }
        } else {
            return true;
        }

        let bin_mtime = bin_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        if let Ok(json_meta) = fs::metadata(&json_path) {
            if json_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH) > bin_mtime {
                return true;
            }
        }

        let lists_dir = base.join("lists");
        if let Ok(entries) = fs::read_dir(&lists_dir) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("txt") {
                    if let Ok(meta) = fs::metadata(&path) {
                        if meta.modified().unwrap_or(SystemTime::UNIX_EPOCH) > bin_mtime {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Loads binary cache into memory map, compiling under lock if missing, stale, or corrupt.
    pub fn load_database(&mut self) {
        let bin_path = self.base_dir.join("routing_rules.bin");
        let json_path = self.base_dir.join("routing_rules.json");

        if Self::is_compilation_needed(&self.base_dir) && json_path.exists() {
            let _guard = COMPILE_LOCK.lock();
            if Self::is_compilation_needed(&self.base_dir) {
                self.mmap = None; // Release active mmap handle before write/rename
                let t0 = Instant::now();
                if let Err(e) = Self::compile(&self.base_dir) {
                    eprintln!("[SmartRouter] Binary cache compilation failed: {e}");
                } else {
                    println!("[SmartRouter] Binary cache v2 built in {:.2}s", t0.elapsed().as_secs_f32());
                }
            }
        }

        if bin_path.exists() {
            let t0 = Instant::now();
            if let Ok(file) = File::open(&bin_path) {
                if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                    if let Ok(header) = BinaryHeaderV2::from_bytes(&mmap) {
                        let total_min_len = (header.cidr_table_offset + header.cidr_table_len) as usize;
                        if mmap.len() >= total_min_len {
                            // Extract 256-entry bucket index table
                            let mut bucket_table = [BucketEntry::default(); BUCKET_TABLE_ENTRIES];
                            let table_start = header.bucket_table_offset as usize;
                            for i in 0..BUCKET_TABLE_ENTRIES {
                                let offset_idx = table_start + i * 8;
                                let offset = u32::from_le_bytes(mmap[offset_idx..offset_idx + 4].try_into().unwrap());
                                let byte_len = u32::from_le_bytes(mmap[offset_idx + 4..offset_idx + 8].try_into().unwrap());
                                bucket_table[i] = BucketEntry { offset, byte_len };
                            }

                            // Extract CIDR intervals
                            let mut curr = header.cidr_table_offset as usize;
                            let mut target_v4 = Vec::with_capacity(header.target_ipv4_cidr_count as usize);
                            for _ in 0..header.target_ipv4_cidr_count {
                                let start = u32::from_le_bytes(mmap[curr..curr + 4].try_into().unwrap());
                                let end = u32::from_le_bytes(mmap[curr + 4..curr + 8].try_into().unwrap());
                                target_v4.push(Ipv4Interval { start, end });
                                curr += 8;
                            }

                            let mut exclude_v4 = Vec::with_capacity(header.exclude_ipv4_cidr_count as usize);
                            for _ in 0..header.exclude_ipv4_cidr_count {
                                let start = u32::from_le_bytes(mmap[curr..curr + 4].try_into().unwrap());
                                let end = u32::from_le_bytes(mmap[curr + 4..curr + 8].try_into().unwrap());
                                exclude_v4.push(Ipv4Interval { start, end });
                                curr += 8;
                            }

                            let mut target_v6 = Vec::with_capacity(header.target_ipv6_cidr_count as usize);
                            for _ in 0..header.target_ipv6_cidr_count {
                                let start = u128::from_le_bytes(mmap[curr..curr + 16].try_into().unwrap());
                                let end = u128::from_le_bytes(mmap[curr + 16..curr + 32].try_into().unwrap());
                                target_v6.push(Ipv6Interval { start, end });
                                curr += 32;
                            }

                            let mut exclude_v6 = Vec::with_capacity(header.exclude_ipv6_cidr_count as usize);
                            for _ in 0..header.exclude_ipv6_cidr_count {
                                let start = u128::from_le_bytes(mmap[curr..curr + 16].try_into().unwrap());
                                let end = u128::from_le_bytes(mmap[curr + 16..curr + 32].try_into().unwrap());
                                exclude_v6.push(Ipv6Interval { start, end });
                                curr += 32;
                            }

                            if !target_v4.is_empty() {
                                self.target_v4 = target_v4;
                            }
                            if !exclude_v4.is_empty() {
                                self.exclude_v4 = exclude_v4;
                            }
                            if !target_v6.is_empty() {
                                self.target_v6 = target_v6;
                            }
                            if !exclude_v6.is_empty() {
                                self.exclude_v6 = exclude_v6;
                            }

                            self.bucket_table = bucket_table;
                            self.header = Some(header);
                            self.mmap = Some(mmap);

                            // Extract standalone database IPv4 addresses from JSON if database_v4 empty
                            if self.database_v4.is_empty() && json_path.exists() {
                                self.extract_database_ips(&json_path);
                            }

                            println!(
                                "[SmartRouter] Binary cache v2 loaded via mmap: {} domains in {:.3}ms",
                                header.total_domain_count,
                                t0.elapsed().as_secs_f64() * 1000.0
                            );
                            return;
                        }
                    }
                }
            }
        }

        // Corrupt cache recovery attempt: if file exists but failed to load, recompile once
        if bin_path.exists() && json_path.exists() {
            let _guard = COMPILE_LOCK.lock();
            eprintln!("[SmartRouter] Corrupt cache detected, regenerating...");
            let _ = fs::remove_file(&bin_path);
            if Self::compile(&self.base_dir).is_ok() {
                drop(_guard);
                self.load_database();
                return;
            }
        }

        eprintln!("[SmartRouter] Warning: routing database not loaded.");
    }

    /// Extracts standalone IPv4 addresses from rules JSON for fast containment.
    fn extract_database_ips<P: AsRef<Path>>(&mut self, json_path: P) {
        if let Ok(file) = File::open(json_path) {
            let reader = BufReader::new(file);
            if let Ok(raw_map) = serde_json::from_reader::<_, BTreeMap<String, String>>(reader) {
                let mut db_ips = Vec::new();
                for (k, v) in raw_map {
                    if let Ok(word_len) = k.parse::<usize>() {
                        if (7..=15).contains(&word_len) {
                            let bytes = v.as_bytes();
                            let count = bytes.len() / word_len;
                            for i in 0..count {
                                let offset = i * word_len;
                                if let Ok(s) = std::str::from_utf8(&bytes[offset..offset + word_len]) {
                                    if let Ok(ipv4) = s.parse::<Ipv4Addr>() {
                                        let addr = u32::from(ipv4);
                                        db_ips.push(Ipv4Interval { start: addr, end: addr });
                                    }
                                }
                            }
                        }
                    }
                }
                self.database_v4 = merge_ipv4_intervals(db_ips);
            }
        }
    }

    /// Compiles rules JSON and list directory files into Format v2 binary cache with atomic replacement.
    pub fn compile<P: AsRef<Path>>(base_dir: P) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let base = base_dir.as_ref();
        let json_path = base.join("routing_rules.json");
        let bin_path = base.join("routing_rules.bin");
        Self::compile_from_sources(base, &json_path, &bin_path)
    }

    /// Compiles a standalone JSON file and optional lists into Format v2 binary cache.
    pub fn compile_json_to_bin<P: AsRef<Path>, Q: AsRef<Path>>(
        json_path: P,
        bin_path: Q,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let j = json_path.as_ref();
        let b = bin_path.as_ref();
        let base = j.parent().unwrap_or_else(|| Path::new("."));
        Self::compile_from_sources(base, j, b)
    }

    fn compile_from_sources(
        base_dir: &Path,
        json_path: &Path,
        bin_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let file = File::open(json_path)?;
        let reader = BufReader::new(file);
        let raw_map: BTreeMap<String, String> = serde_json::from_reader(reader)?;

        // Find newest source timestamp
        let mut newest_mtime = fs::metadata(json_path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        let lists_dir = base_dir.join("lists");
        let mut target_v4 = Vec::new();
        let mut target_v6 = Vec::new();
        let mut exclude_v4 = Vec::new();
        let mut exclude_v6 = Vec::new();
        let mut target_domains = HashSet::new();
        let mut exclude_domains = HashSet::new();

        if lists_dir.is_dir() {
            Self::load_cidr_file(lists_dir.join("ipset-target.txt"), &mut target_v4, &mut target_v6);
            Self::load_cidr_file(lists_dir.join("ipset-all.txt"), &mut target_v4, &mut target_v6);
            Self::load_cidr_file(lists_dir.join("ipset-exclude.txt"), &mut exclude_v4, &mut exclude_v6);
            Self::load_cidr_file(lists_dir.join("ipset-exclude-user.txt"), &mut exclude_v4, &mut exclude_v6);

            Self::load_list_file(lists_dir.join("list-general.txt"), &mut target_domains);
            Self::load_list_file(lists_dir.join("list-google.txt"), &mut target_domains);
            Self::load_list_file(lists_dir.join("list-general-user.txt"), &mut target_domains);
            Self::load_list_file(lists_dir.join("list-exclude.txt"), &mut exclude_domains);
            Self::load_list_file(lists_dir.join("list-exclude-user.txt"), &mut exclude_domains);

            if let Ok(entries) = fs::read_dir(&lists_dir) {
                for entry in entries.filter_map(Result::ok) {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(m) = meta.modified() {
                            if m > newest_mtime {
                                newest_mtime = m;
                            }
                        }
                    }
                }
            }
        }

        // Disjoint interval merging
        let target_v4 = merge_ipv4_intervals(target_v4);
        let exclude_v4 = merge_ipv4_intervals(exclude_v4);
        let target_v6 = merge_ipv6_intervals(target_v6);
        let exclude_v6 = merge_ipv6_intervals(exclude_v6);

        // Build bucket directory and sorted payloads
        let mut bucket_table = [BucketEntry::default(); BUCKET_TABLE_ENTRIES];
        let mut current_offset = PAYLOAD_OFFSET;
        let mut total_domains = 0u32;
        let mut payload_bytes = Vec::new();

        for (k, v) in raw_map {
            let word_len: usize = match k.parse() {
                Ok(l) => l,
                Err(_) => continue,
            };
            if word_len == 0 || word_len >= BUCKET_TABLE_ENTRIES {
                continue;
            }

            let raw_bytes = v.as_bytes();
            if raw_bytes.len() % word_len != 0 {
                continue;
            }

            // Ensure words in bucket are sorted
            let count = raw_bytes.len() / word_len;
            let mut words: Vec<&[u8]> = (0..count)
                .map(|i| &raw_bytes[i * word_len..(i + 1) * word_len])
                .collect();
            words.sort_unstable();

            let bucket_start = current_offset;
            let bucket_len = raw_bytes.len() as u32;

            bucket_table[word_len] = BucketEntry {
                offset: bucket_start,
                byte_len: bucket_len,
            };

            for word in words {
                payload_bytes.extend_from_slice(word);
            }

            current_offset += bucket_len;
            total_domains += count as u32;
        }

        let payload_len = payload_bytes.len() as u32;
        let unaligned_cidr_offset = PAYLOAD_OFFSET + payload_len;
        let cidr_table_offset = (unaligned_cidr_offset + 63) & !63;
        let padding_len = (cidr_table_offset - unaligned_cidr_offset) as usize;

        let cidr_table_len = ((target_v4.len() * 8)
            + (exclude_v4.len() * 8)
            + (target_v6.len() * 32)
            + (exclude_v6.len() * 32)) as u32;

        let source_mtime_epoch = newest_mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let header = BinaryHeaderV2 {
            magic: MAGIC,
            version: FORMAT_VERSION,
            header_size: HEADER_SIZE,
            source_mtime_epoch,
            total_domain_count: total_domains,
            bucket_table_offset: 64,
            bucket_table_len: 2048,
            payload_offset: PAYLOAD_OFFSET,
            payload_len,
            cidr_table_offset,
            cidr_table_len,
            target_ipv4_cidr_count: u16::try_from(target_v4.len())
                .map_err(|_| "target IPv4 CIDR count exceeds 65535")?,
            exclude_ipv4_cidr_count: u16::try_from(exclude_v4.len())
                .map_err(|_| "exclude IPv4 CIDR count exceeds 65535")?,
            target_ipv6_cidr_count: u16::try_from(target_v6.len())
                .map_err(|_| "target IPv6 CIDR count exceeds 65535")?,
            exclude_ipv6_cidr_count: u16::try_from(exclude_v6.len())
                .map_err(|_| "exclude IPv6 CIDR count exceeds 65535")?,
            target_list_domain_count: target_domains.len() as u32,
            exclude_list_domain_count: exclude_domains.len() as u32,
            checksum: 0,
        };

        // Unique temporary file staging per PID and thread
        let unique_tmp_name = format!(
            "routing_rules.bin.{:x}.tmp",
            std::time::SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let tmp_path = bin_path.with_file_name(unique_tmp_name);
        {
            let mut writer = BufWriter::new(File::create(&tmp_path)?);

            // 1. Header (64 bytes)
            writer.write_all(&header.to_bytes())?;

            // 2. Bucket Index Table (2048 bytes)
            for entry in &bucket_table {
                writer.write_all(&entry.offset.to_le_bytes())?;
                writer.write_all(&entry.byte_len.to_le_bytes())?;
            }

            // 3. Domain payload
            writer.write_all(&payload_bytes)?;

            // 4. Alignment padding
            if padding_len > 0 {
                writer.write_all(&vec![0u8; padding_len])?;
            }

            // 5. CIDR interval tables
            for iv in &target_v4 {
                writer.write_all(&iv.start.to_le_bytes())?;
                writer.write_all(&iv.end.to_le_bytes())?;
            }
            for iv in &exclude_v4 {
                writer.write_all(&iv.start.to_le_bytes())?;
                writer.write_all(&iv.end.to_le_bytes())?;
            }
            for iv in &target_v6 {
                writer.write_all(&iv.start.to_le_bytes())?;
                writer.write_all(&iv.end.to_le_bytes())?;
            }
            for iv in &exclude_v6 {
                writer.write_all(&iv.start.to_le_bytes())?;
                writer.write_all(&iv.end.to_le_bytes())?;
            }

            writer.flush()?;
            writer.get_ref().sync_all()?;
        }

        // Atomic file replacement with Windows fallback
        if bin_path.exists() {
            let _ = fs::remove_file(bin_path);
        }
        if let Err(_) = fs::rename(&tmp_path, bin_path) {
            fs::copy(&tmp_path, bin_path)?;
            let _ = fs::remove_file(&tmp_path);
        }
        Ok(())
    }

    /// Evaluates IP address routing under deterministic 4-tier priority order:
    /// Priority 1: Exclude subnets / RFC1918 / loopback -> direct ("exclude_direct")
    /// Priority 2: Target subnets -> routed ("target_routed")
    /// Priority 3: Compiled 662k database match -> routed ("database_routed")
    /// Priority 4: Default -> direct ("default_direct")
    pub fn should_route_ip(&self, ip: IpAddr) -> (bool, &'static str) {
        match ip {
            IpAddr::V4(v4) => {
                let addr = u32::from(v4);
                if contains_ipv4(&self.exclude_v4, addr) {
                    return (false, "exclude_direct");
                }
                if contains_ipv4(&self.target_v4, addr) {
                    return (true, "target_routed");
                }
                if contains_ipv4(&self.database_v4, addr) {
                    return (true, "database_routed");
                }
                // Fallback: Check if IPv4 string literal matches the 662k database in mmap
                if let Some(mmap) = &self.mmap {
                    let mut buf = [0u8; 16];
                    let ip_str = format_ipv4_stack(v4, &mut buf);
                    let len = ip_str.len();
                    if len < BUCKET_TABLE_ENTRIES {
                        let entry = self.bucket_table[len];
                        if entry.byte_len > 0 {
                            let start = entry.offset as usize;
                            let end = start + (entry.byte_len as usize);
                            if end <= mmap.len() {
                                let bucket_slice = &mmap[start..end];
                                if binary_search_bucket(bucket_slice, len, ip_str.as_bytes()) {
                                    return (true, "database_routed");
                                }
                            }
                        }
                    }
                }
                (false, "default_direct")
            }
            IpAddr::V6(v6) => {
                let addr = u128::from(v6);
                if contains_ipv6(&self.exclude_v6, addr) {
                    return (false, "exclude_direct");
                }
                if contains_ipv6(&self.target_v6, addr) {
                    return (true, "target_routed");
                }
                (false, "default_direct")
            }
        }
    }

    /// Evaluates target hostname under deterministic 4-tier priority order:
    /// Priority 1: Exclude lists, RFC 1918, loopback, domestic services -> direct ("exclude_direct")
    /// Priority 2: Target subnets, streaming fast-paths, target lists -> routed ("target_routed")
    /// Priority 3: Mmap 662k database rule match -> routed ("database_routed")
    /// Priority 4: Default fallback -> direct ("default_direct")
    pub fn should_route(&self, hostname: &str) -> (bool, &'static str) {
        // Fast-path: Check if target is an IP literal
        let candidate_ip = if hostname.starts_with('[') {
            if let Some(end) = hostname.find(']') {
                hostname[1..end].parse::<IpAddr>().ok()
            } else {
                hostname.parse::<IpAddr>().ok()
            }
        } else if let Some((h, port)) = hostname.split_once(':') {
            if !port.contains(':') {
                h.parse::<IpAddr>().ok()
            } else {
                hostname.parse::<IpAddr>().ok()
            }
        } else {
            hostname.parse::<IpAddr>().ok()
        };

        if let Some(ip) = candidate_ip {
            return self.should_route_ip(ip);
        }

        // Normalize domain via stack frame (0 heap allocations)
        let norm = match NormalizedDomain::try_from_str(hostname) {
            Some(n) => n,
            None => return (false, "default_direct"),
        };
        let domain_bytes = norm.as_bytes();
        let domain_str = norm.as_str();

        // -------------------------------------------------------------
        // Priority 1: Local, Loopback, Exclude lists, Domestic, Apple
        // -------------------------------------------------------------
        if domain_str == "localhost"
            || domain_str.ends_with(".local")
            || domain_str.ends_with(".lan")
            || domain_str.ends_with(".internal")
        {
            return (false, "exclude_direct");
        }

        // Check exclude lists (list-exclude.txt, list-exclude-user.txt)
        {
            let exc = self.exclude_domains.read();
            for sub_bytes in DomainSuffixIter::new(domain_bytes) {
                if !suffix_is_matchable(domain_bytes, sub_bytes) {
                    continue;
                }
                let sub_str = unsafe { std::str::from_utf8_unchecked(sub_bytes) };
                if exc.contains(sub_str) {
                    return (false, "exclude_direct");
                }
            }
        }

        if host_matches_any(domain_str, PROXY_SUFFIXES) {
            return (true, "target_routed");
        }
        if host_matches_any(domain_str, DIRECT_SUFFIXES) {
            return (false, "exclude_direct");
        }

        // Check target lists (list-general.txt, list-google.txt, user lists, auto-added)
        {
            let target = self.target_domains.read();
            let user = self.user_domains.read();
            let auto = self.auto_added_domains.read();
            for sub_bytes in DomainSuffixIter::new(domain_bytes) {
                if !suffix_is_matchable(domain_bytes, sub_bytes) {
                    continue;
                }
                let sub_str = unsafe { std::str::from_utf8_unchecked(sub_bytes) };
                if target.contains(sub_str) || user.contains(sub_str) || auto.contains(sub_str) {
                    return (true, "target_routed");
                }
            }
        }

        // -------------------------------------------------------------
        // Priority 3: Compiled 662k database rules via Mmap binary search
        // -------------------------------------------------------------
        if let Some(mmap) = &self.mmap {
            for sub_bytes in DomainSuffixIter::new(domain_bytes) {
                if !suffix_is_matchable(domain_bytes, sub_bytes) {
                    continue;
                }
                let sub_len = sub_bytes.len();
                if sub_len == 0 || sub_len >= BUCKET_TABLE_ENTRIES {
                    continue;
                }

                let entry = self.bucket_table[sub_len];
                if entry.byte_len == 0 {
                    continue;
                }

                let start = entry.offset as usize;
                let end = start + (entry.byte_len as usize);
                if end <= mmap.len() {
                    let bucket_slice = &mmap[start..end];
                    if binary_search_bucket(bucket_slice, sub_len, sub_bytes) {
                        return (true, "database_routed");
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // Priority 4: Default Fallback Direct
        // -------------------------------------------------------------
        (false, "default_direct")
    }

    /// Records a domain the proxy actually forwarded.
    ///
    /// `default_direct` is ignored. A name already covered by a suffix in the
    /// lists or the binary cache is ignored, so CDN hostnames do not append a
    /// new line or restart Zapret.
    pub fn observe_domain(&self, host: &str, reason: &str) {
        if reason != "target_routed" && reason != "database_routed" {
            return;
        }
        let Some(domain) = clean_domain_name(host) else {
            return;
        };
        if self.domain_persisted(&domain) {
            return;
        }
        let store = shortest_static_suffix(&domain).unwrap_or(domain);
        if self.domain_persisted(&store) {
            return;
        }
        self.auto_add_domain(&store);
    }

    fn domain_persisted(&self, domain: &str) -> bool {
        let Some(norm) = NormalizedDomain::try_from_str(domain) else {
            return true;
        };
        let bytes = norm.as_bytes();
        {
            let target = self.target_domains.read();
            let user = self.user_domains.read();
            let auto = self.auto_added_domains.read();
            let exc = self.exclude_domains.read();
            for sub in DomainSuffixIter::new(bytes) {
                if !suffix_is_matchable(bytes, sub) {
                    continue;
                }
                let sub_str = unsafe { std::str::from_utf8_unchecked(sub) };
                if exc.contains(sub_str)
                    || target.contains(sub_str)
                    || user.contains(sub_str)
                    || auto.contains(sub_str)
                {
                    return true;
                }
            }
        }
        self.mmap_has_suffix(bytes)
    }

    fn mmap_has_suffix(&self, domain_bytes: &[u8]) -> bool {
        let Some(mmap) = &self.mmap else {
            return false;
        };
        for sub_bytes in DomainSuffixIter::new(domain_bytes) {
            if !suffix_is_matchable(domain_bytes, sub_bytes) {
                continue;
            }
            let sub_len = sub_bytes.len();
            if sub_len == 0 || sub_len >= BUCKET_TABLE_ENTRIES {
                continue;
            }
            let entry = self.bucket_table[sub_len];
            if entry.byte_len == 0 {
                continue;
            }
            let start = entry.offset as usize;
            let end = start + entry.byte_len as usize;
            if end <= mmap.len() && binary_search_bucket(&mmap[start..end], sub_len, sub_bytes) {
                return true;
            }
        }
        false
    }

    /// Dynamically tracks new target domains in-memory and appends to user list file.
    pub fn auto_add_domain(&self, domain: &str) {
        let Some(domain) = clean_domain_name(domain) else {
            return;
        };
        if self.domain_persisted(&domain) {
            return;
        }
        {
            let mut auto = self.auto_added_domains.write();
            if auto.contains(&domain) {
                return;
            }
            auto.insert(domain.clone());
        }

        let user_path = self.lists_dir.join("list-general-user.txt");
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(user_path) {
            let _ = writeln!(file, "{domain}");
            println!("[SmartRouter] Domain {domain} dynamically registered for acceleration");
            if RELOAD_ARMED.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = RELOAD_NOTIFY.send(());
            }
        }
    }

    // Accessors for introspection and test assertions
    pub fn header(&self) -> Option<BinaryHeaderV2> {
        self.header
    }

    pub fn bucket_entry(&self, len: usize) -> Option<BucketEntry> {
        if len < BUCKET_TABLE_ENTRIES {
            Some(self.bucket_table[len])
        } else {
            None
        }
    }

    pub fn target_ipv4_intervals(&self) -> &[Ipv4Interval] {
        &self.target_v4
    }

    pub fn exclude_ipv4_intervals(&self) -> &[Ipv4Interval] {
        &self.exclude_v4
    }

    pub fn target_ipv6_intervals(&self) -> &[Ipv6Interval] {
        &self.target_v6
    }

    pub fn exclude_ipv6_intervals(&self) -> &[Ipv6Interval] {
        &self.exclude_v6
    }

    pub fn database_ipv4_intervals(&self) -> &[Ipv4Interval] {
        &self.database_v4
    }

    pub fn is_mapped(&self) -> bool {
        self.mmap.is_some()
    }
}

impl RoutingEngine for SmartRouter {
    fn should_route(&self, host: &str) -> (bool, &'static str) {
        self.should_route(host)
    }

    fn should_route_ip(&self, ip: IpAddr) -> (bool, &'static str) {
        self.should_route_ip(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_header_v2_layout_and_size() {
        assert_eq!(std::mem::size_of::<BinaryHeaderV2>(), 64);
        assert_eq!(std::mem::size_of::<BucketEntry>(), 8);
        assert_eq!(std::mem::size_of::<Ipv4Interval>(), 8);
        assert_eq!(std::mem::size_of::<Ipv6Interval>(), 32);

        let header = BinaryHeaderV2 {
            magic: MAGIC,
            version: FORMAT_VERSION,
            header_size: HEADER_SIZE,
            source_mtime_epoch: 1730000000,
            total_domain_count: 662819,
            bucket_table_offset: 64,
            bucket_table_len: 2048,
            payload_offset: 2112,
            payload_len: 11638699,
            cidr_table_offset: 11640832,
            cidr_table_len: 352,
            target_ipv4_cidr_count: 22,
            exclude_ipv4_cidr_count: 8,
            target_ipv6_cidr_count: 0,
            exclude_ipv6_cidr_count: 3,
            target_list_domain_count: 5504,
            exclude_list_domain_count: 132,
            checksum: 0,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 64);

        let parsed = BinaryHeaderV2::from_bytes(&bytes).expect("Failed to parse header bytes");
        assert_eq!(parsed, header);
    }

    #[test]
    fn test_zero_alloc_domain_normalization() {
        let norm = NormalizedDomain::try_from_str("Example.COM:443.").unwrap();
        assert_eq!(norm.as_str(), "example.com");

        let norm_v6 = NormalizedDomain::try_from_str("[2001:db8::1]:8080").unwrap();
        assert_eq!(norm_v6.as_str(), "2001:db8::1");

        let norm_trailing = NormalizedDomain::try_from_str("...sub.domain.org...").unwrap();
        assert_eq!(norm_trailing.as_str(), "sub.domain.org");

        assert!(NormalizedDomain::try_from_str("").is_none());
        assert!(NormalizedDomain::try_from_str(".").is_none());
    }

    #[test]
    fn test_domain_suffix_iterator() {
        let host = b"rr1.googlevideo.com";
        let suffixes: Vec<&str> = DomainSuffixIter::new(host)
            .map(|s| std::str::from_utf8(s).unwrap())
            .collect();

        assert_eq!(
            suffixes,
            vec!["rr1.googlevideo.com", "googlevideo.com", "com"]
        );
    }

    #[test]
    fn test_binary_search_bucket_early_exit() {
        let slice = b"coolgametestzone"; // 4 words of length 4: cool, game, test, zone
        assert!(binary_search_bucket(slice, 4, b"cool"));
        assert!(binary_search_bucket(slice, 4, b"game"));
        assert!(binary_search_bucket(slice, 4, b"test"));
        assert!(binary_search_bucket(slice, 4, b"zone"));
        assert!(!binary_search_bucket(slice, 4, b"aaaa"));
        assert!(!binary_search_bucket(slice, 4, b"zzzz"));
        assert!(!binary_search_bucket(slice, 4, b"fast"));
    }

    #[test]
    fn test_cidr_parsing_and_merging() {
        let c1 = parse_ipv4_cidr("104.16.0.0/13").unwrap();
        let c2 = parse_ipv4_cidr("104.24.0.0/14").unwrap();
        assert_eq!(c1.start, u32::from(Ipv4Addr::new(104, 16, 0, 0)));
        assert_eq!(c1.end, u32::from(Ipv4Addr::new(104, 23, 255, 255)));

        let merged = merge_ipv4_intervals(vec![c1, c2]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start, u32::from(Ipv4Addr::new(104, 16, 0, 0)));
        assert_eq!(merged[0].end, u32::from(Ipv4Addr::new(104, 27, 255, 255)));

        assert!(contains_ipv4(&merged, u32::from(Ipv4Addr::new(104, 20, 1, 1))));
        assert!(contains_ipv4(&merged, u32::from(Ipv4Addr::new(104, 25, 2, 2))));
        assert!(!contains_ipv4(&merged, u32::from(Ipv4Addr::new(104, 28, 0, 1))));

        // IPv6 parsing
        let v6_bare = parse_ipv6_cidr("::1").unwrap();
        assert_eq!(v6_bare.start, 1);
        assert_eq!(v6_bare.end, 1);
        assert!(contains_ipv6(&[v6_bare], 1));
        assert!(!contains_ipv6(&[v6_bare], 2));
    }

    #[test]
    fn test_compile_and_mmap_search_v2() {
        let temp_dir = std::env::temp_dir().join(format!("zprt_test_mmap_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let json_path = temp_dir.join("routing_rules.json");
        let bin_path = temp_dir.join("routing_rules.bin");

        let json_data = r#"{"4": "coolgametestzone", "3": "appnetorg"}"#;
        fs::write(&json_path, json_data).unwrap();

        SmartRouter::compile(&temp_dir).unwrap();
        assert!(bin_path.exists());

        let router = SmartRouter::new(&temp_dir);
        assert!(router.is_mapped());
        let hdr = router.header().unwrap();
        assert_eq!(hdr.version, FORMAT_VERSION);
        assert_eq!(hdr.magic, MAGIC);
        assert_eq!(hdr.total_domain_count, 7);

        // Test length 4 bucket
        let entry4 = router.bucket_entry(4).unwrap();
        assert_eq!(entry4.byte_len, 16);

        // Test length 3 bucket
        let entry3 = router.bucket_entry(3).unwrap();
        assert_eq!(entry3.byte_len, 9);

        // Test empty bucket (length 5)
        let entry5 = router.bucket_entry(5).unwrap();
        assert_eq!(entry5.byte_len, 0);

        // Lookups
        assert_eq!(router.should_route("cool"), (true, "database_routed"));
        assert_eq!(router.should_route("game"), (true, "database_routed"));
        assert_eq!(router.should_route("sub.app"), (false, "default_direct"));
        assert_eq!(router.should_route("app"), (true, "database_routed"));
        assert_eq!(router.should_route("twitch.tv"), (true, "target_routed"));
        assert_eq!(router.should_route("static-cdn.jtvnw.net"), (true, "target_routed"));
        assert_eq!(router.should_route("static.twitchcdn.net"), (true, "target_routed"));
        assert_eq!(router.should_route("video-weaver.arn03.hls.ttvnw.net"), (true, "target_routed"));
        assert_eq!(router.should_route("unknown.xyz"), (false, "default_direct"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
