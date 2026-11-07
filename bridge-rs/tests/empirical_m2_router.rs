use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use zapret_tv_bridge_rs::router::{
    BinaryHeaderV2, DomainSuffixIter, NormalizedDomain, SmartRouter, FORMAT_VERSION,
    HEADER_SIZE, MAGIC,
};

// ============================================================================
// Tracking Allocator for Empirical Hot-Path Verification
// ============================================================================

struct TrackingAllocator;

static TRACKING_ACTIVE: AtomicBool = AtomicBool::new(false);
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING_ACTIVE.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if TRACKING_ACTIVE.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        }
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if TRACKING_ACTIVE.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL_ALLOC: TrackingAllocator = TrackingAllocator;

/// Executes closure and verifies that exactly zero heap allocations occurred.
fn assert_zero_alloc<F, R>(name: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    ALLOC_COUNT.store(0, Ordering::SeqCst);
    TRACKING_ACTIVE.store(true, Ordering::SeqCst);
    let result = f();
    TRACKING_ACTIVE.store(false, Ordering::SeqCst);
    let count = ALLOC_COUNT.load(Ordering::SeqCst);
    assert_eq!(
        count, 0,
        "Zero-allocation hot-path violation in '{}': {} heap allocations occurred",
        name, count
    );
    result
}

// ============================================================================
// Challenge Suite 1: Adversarial Domain Normalization Edge Cases
// ============================================================================

#[test]
fn test_adversarial_domain_normalization_edge_cases() {
    // 1. Exactly 253-character domain (RFC 1035 maximum length boundary)
    // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253 chars
    let p1 = "a".repeat(63);
    let p2 = "b".repeat(63);
    let p3 = "c".repeat(63);
    let p4 = "d".repeat(61);
    let max_253 = format!("{}.{}.{}.{}", p1, p2, p3, p4);
    assert_eq!(max_253.len(), 253);

    let norm_253 = NormalizedDomain::try_from_str(&max_253)
        .expect("253-character domain must be accepted as valid boundary");
    assert_eq!(norm_253.len(), 253);
    assert_eq!(norm_253.as_bytes().len(), 253);
    assert_eq!(norm_253.as_str(), max_253.as_str());

    // 2. Exactly 254-character domain (overflow by 1 byte)
    let overflow_254 = format!("{}e", max_253);
    assert_eq!(overflow_254.len(), 254);
    assert!(
        NormalizedDomain::try_from_str(&overflow_254).is_none(),
        "254-character domain must be rejected (overflow)"
    );

    // 3. Large overflow (> 300 characters)
    let overflow_500 = "x".repeat(500);
    assert!(
        NormalizedDomain::try_from_str(&overflow_500).is_none(),
        "500-character domain must be rejected safely"
    );

    // 4. Leading dots stripping
    let leading_1 = NormalizedDomain::try_from_str(".example.com").expect("Single leading dot");
    assert_eq!(leading_1.as_str(), "example.com");

    let leading_many = NormalizedDomain::try_from_str(".....example.com").expect("Multiple leading dots");
    assert_eq!(leading_many.as_str(), "example.com");

    // 5. Trailing root dots stripping
    let trailing_1 = NormalizedDomain::try_from_str("example.com.").expect("Single trailing root dot");
    assert_eq!(trailing_1.as_str(), "example.com");

    let trailing_many = NormalizedDomain::try_from_str("example.com.....").expect("Multiple trailing dots");
    assert_eq!(trailing_many.as_str(), "example.com");

    // 6. Both leading and trailing dots
    let both_dots = NormalizedDomain::try_from_str("...sub.example.com...").expect("Both leading and trailing dots");
    assert_eq!(both_dots.as_str(), "sub.example.com");

    // 7. Mixed case lowercasing
    let mixed = NormalizedDomain::try_from_str("GoOgLe.CoM:443.").expect("Mixed case domain");
    assert_eq!(mixed.as_str(), "google.com");

    let mixed2 = NormalizedDomain::try_from_str("YoUtUbE.CoM").expect("Mixed case YouTube");
    assert_eq!(mixed2.as_str(), "youtube.com");

    // 8. Embedded ports stripping
    let port_std = NormalizedDomain::try_from_str("example.com:8443").expect("Standard port");
    assert_eq!(port_std.as_str(), "example.com");

    let port_sub = NormalizedDomain::try_from_str("sub.domain.org:80").expect("Subdomain port");
    assert_eq!(port_sub.as_str(), "sub.domain.org");

    // 9. Bracketed IPv6 notation and ports
    let bracket_v6_port = NormalizedDomain::try_from_str("[::1]:8080").expect("Bracketed IPv6 with port");
    assert_eq!(bracket_v6_port.as_str(), "::1");

    let bracket_v6_long = NormalizedDomain::try_from_str("[2001:db8::1]:443").expect("Long bracketed IPv6 with port");
    assert_eq!(bracket_v6_long.as_str(), "2001:db8::1");

    let bracket_bare = NormalizedDomain::try_from_str("[::1]").expect("Bracketed IPv6 bare");
    assert_eq!(bracket_bare.as_str(), "::1");

    // 10. Non-ASCII characters and malformed garbage
    assert!(NormalizedDomain::try_from_str("").is_none(), "Empty string rejected");
    assert!(NormalizedDomain::try_from_str(".").is_none(), "Single dot rejected");
    assert!(NormalizedDomain::try_from_str(".....").is_none(), "Multiple dots rejected");

    // Valid Cyrillic UTF-8 preservation (to_ascii_lowercase must not corrupt multi-byte UTF-8)
    let cyrillic = NormalizedDomain::try_from_str("новости.яндекс.рф")
        .expect("Valid UTF-8 Cyrillic domain handled");
    assert_eq!(cyrillic.as_str(), "новости.яндекс.рф");

    // Control characters must not cause panics
    let with_null = NormalizedDomain::try_from_str("\0null.com").expect("Domain with leading null byte");
    assert_eq!(with_null.as_str(), "\0null.com");

    let with_crlf = NormalizedDomain::try_from_str("foo\r\nbar.com").expect("Domain with CRLF");
    assert_eq!(with_crlf.as_str(), "foo\r\nbar.com");
}

// ============================================================================
// Challenge Suite 2: Zero-Heap Allocation on Hot Path Verification
// ============================================================================

#[test]
fn test_adversarial_zero_heap_allocation_hot_path() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        eprintln!("Skipping zero alloc test: routing_rules.json missing");
        return;
    }

    let router = SmartRouter::new(base_dir);
    assert!(router.is_mapped(), "Database must be loaded");

    // Warm up thread-local caches if any
    let _ = router.should_route("warmup.example.com");

    // 1. NormalizedDomain construction from stack buffer: 0 allocations
    assert_zero_alloc("NormalizedDomain::try_from_str", || {
        let norm = NormalizedDomain::try_from_str("ExAmPlE.CoM:8443.").unwrap();
        assert_eq!(norm.as_str(), "example.com");
    });

    // 2. DomainSuffixIter traversal over slice: 0 allocations
    let test_bytes = b"deep.sub.level.domain.org";
    assert_zero_alloc("DomainSuffixIter traversal", || {
        let mut count = 0;
        for suffix in DomainSuffixIter::new(test_bytes) {
            count += suffix.len();
        }
        assert!(count > 0);
    });

    // 3. Priority 1 Direct exclusions: 0 allocations
    assert_zero_alloc("should_route localhost", || {
        let res = router.should_route("localhost");
        assert_eq!(res, (false, "exclude_direct"));
    });
    assert_zero_alloc("should_route apple.com", || {
        let res = router.should_route("apple.com");
        assert_eq!(res, (false, "exclude_direct"));
    });
    assert_zero_alloc("should_route yandex.ru", || {
        let res = router.should_route("yandex.ru");
        assert_eq!(res, (false, "exclude_direct"));
    });
    assert_zero_alloc("should_route chatgpt.com", || {
        let res = router.should_route("chatgpt.com");
        assert_eq!(res, (false, "exclude_direct"));
    });

    // 4. Priority 2 Target list matches: 0 allocations
    assert_zero_alloc("should_route video.google.com", || {
        let res = router.should_route("video.google.com");
        assert_eq!(res, (true, "target_routed"));
    });
    assert_zero_alloc("should_route rr1---sn-vgqsknzk.googlevideo.com", || {
        let res = router.should_route("rr1---sn-vgqsknzk.googlevideo.com");
        assert_eq!(res, (true, "target_routed"));
    });
    assert_zero_alloc("should_route youtube.com:443", || {
        let res = router.should_route("youtube.com:443");
        assert_eq!(res, (true, "target_routed"));
    });
    assert_zero_alloc("should_route discord.com", || {
        let res = router.should_route("discord.com");
        assert_eq!(res, (true, "target_routed"));
    });

    // 5. Priority 4 Default unlisted direct: 0 allocations
    assert_zero_alloc("should_route unlisted domain", || {
        let res = router.should_route("unlisted-challenger-domain-999.xyz");
        assert_eq!(res, (false, "default_direct"));
    });

    // 6. IP string literals routing: 0 allocations
    assert_zero_alloc("should_route 192.168.1.1:8080", || {
        let res = router.should_route("192.168.1.1:8080");
        assert_eq!(res, (false, "exclude_direct"));
    });
    assert_zero_alloc("should_route [::1]:443", || {
        let res = router.should_route("[::1]:443");
        assert_eq!(res, (false, "exclude_direct"));
    });
    assert_zero_alloc("should_route 142.250.180.14:443", || {
        let res = router.should_route("142.250.180.14:443");
        assert_eq!(res, (true, "target_routed"));
    });
    assert_zero_alloc("should_route 8.8.8.8", || {
        let res = router.should_route("8.8.8.8");
        assert_eq!(res, (false, "default_direct"));
    });

    // 7. should_route_ip direct calls: 0 allocations
    assert_zero_alloc("should_route_ip 192.168.0.1", || {
        let res = router.should_route_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(res, (false, "exclude_direct"));
    });
    assert_zero_alloc("should_route_ip 142.250.180.14", || {
        let res = router.should_route_ip(IpAddr::V4(Ipv4Addr::new(142, 250, 180, 14)));
        assert_eq!(res, (true, "target_routed"));
    });
    assert_zero_alloc("should_route_ip fe80::1", || {
        let res = router.should_route_ip(IpAddr::V6("fe80::1".parse().unwrap()));
        assert_eq!(res, (false, "exclude_direct"));
    });

    // 8. Subsequent query for an already registered domain: 0 allocations
    // Use an isolated temporary router so we do not mutate production lists in repository
    let temp_test_dir = std::env::temp_dir().join(format!("zprt_zero_alloc_{}", std::process::id()));
    let temp_lists = temp_test_dir.join("lists");
    let _ = fs::create_dir_all(&temp_lists);
    fs::write(temp_test_dir.join("routing_rules.json"), r#"{"4": "test"}"#).unwrap();
    let temp_router = SmartRouter::new(&temp_test_dir);
    // Prime the domain in isolated router
    let _ = temp_router.should_route("test");
    assert_zero_alloc("should_route already registered domain", || {
        let res = temp_router.should_route("test");
        assert_eq!(res, (true, "target_routed"));
    });
    let _ = fs::remove_dir_all(&temp_test_dir);
}

// ============================================================================
// Challenge Suite 3: Wildcard Rules & Anti-Match Verification
// ============================================================================

#[test]
fn test_adversarial_wildcard_and_anti_match() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        return;
    }

    let router = SmartRouter::new(base_dir);

    // List contains wildcard rule: *.phncdn.com -> normalized to phncdn.com
    // 1. Valid subdomains must match target_routed
    assert_eq!(router.should_route("video.phncdn.com"), (true, "target_routed"));
    assert_eq!(router.should_route("phncdn.com"), (true, "target_routed"));
    assert_eq!(router.should_route("cdn.video.phncdn.com"), (true, "target_routed"));
    assert_eq!(router.should_route("a.b.c.d.phncdn.com"), (true, "target_routed"));

    // 2. Anti-match: Suffix/Substring false-positives MUST NOT match!
    // A domain where phncdn.com is NOT a dot-separated suffix
    assert_eq!(
        router.should_route("phncdn.com.fake.com"),
        (false, "default_direct"),
        "phncdn.com.fake.com must NOT match *.phncdn.com"
    );
    assert_eq!(
        router.should_route("notphncdn.com"),
        (false, "default_direct"),
        "notphncdn.com must NOT match phncdn.com"
    );
    assert_eq!(
        router.should_route("phncdn.com-phishing.org"),
        (false, "default_direct"),
        "phncdn.com-phishing.org must NOT match phncdn.com"
    );
    assert_eq!(
        router.should_route("fakephncdn.com"),
        (false, "default_direct"),
        "fakephncdn.com must NOT match phncdn.com"
    );
    assert_eq!(
        router.should_route("phncdn.com.ru"),
        (false, "default_direct"),
        "phncdn.com.ru must NOT match phncdn.com"
    );
}

// ============================================================================
// Challenge Suite 4: Deterministic Priority Order & Exclusions
// ============================================================================

#[test]
fn test_adversarial_priority_order_and_conflicts() {
    let test_dir = std::env::temp_dir().join(format!("zprt_priority_test_{}", std::process::id()));
    let lists_dir = test_dir.join("lists");
    let _ = fs::create_dir_all(&lists_dir);

    let json_path = test_dir.join("routing_rules.json");
    let _bin_path = test_dir.join("routing_rules.bin");
    let list_gen = lists_dir.join("list-general.txt");
    let list_exc = lists_dir.join("list-exclude.txt");

    // JSON contains 4-letter words: "excl" and "both"
    fs::write(&json_path, r#"{"4": "bothexcl"}"#).unwrap();

    // Conflicting rules:
    // "conflict-target-exc.com" is in BOTH target list and exclude list
    // "both" is in BOTH database and exclude list
    fs::write(&list_gen, "conflict-target-exc.com\npure-target.com\n").unwrap();
    fs::write(&list_exc, "conflict-target-exc.com\nboth\nparent-excluded.org\n").unwrap();

    let router = SmartRouter::new(&test_dir);
    assert!(router.is_mapped());

    // Priority 1 > Priority 2: Exclude takes precedence over Target list
    assert_eq!(
        router.should_route("conflict-target-exc.com"),
        (false, "exclude_direct"),
        "Exclude list must override Target list"
    );

    // Priority 1 > Priority 3: Exclude takes precedence over Database
    assert_eq!(
        router.should_route("both"),
        (false, "exclude_direct"),
        "Exclude list must override Database match"
    );

    // Priority 2 > Priority 3: Target list matches before database
    assert_eq!(
        router.should_route("pure-target.com"),
        (true, "target_routed")
    );

    // Subdomain inheritance of excluded parent
    assert_eq!(
        router.should_route("sub.parent-excluded.org"),
        (false, "exclude_direct"),
        "Subdomain of excluded parent must be excluded"
    );
    assert_eq!(
        router.should_route("deep.nested.sub.parent-excluded.org"),
        (false, "exclude_direct"),
        "Deep nested subdomain of excluded parent must be excluded"
    );

    // Priority 3: Standalone Database rule
    assert_eq!(
        router.should_route("excl"),
        (true, "database_routed"),
        "Uncontested database domain routes as database_routed"
    );

    // Priority 4: Default Direct fallback
    assert_eq!(
        router.should_route("unlisted-random-service.xyz"),
        (false, "default_direct"),
        "Unlisted domain must fall through to default_direct"
    );

    let _ = fs::remove_dir_all(&test_dir);
}

// ============================================================================
// Challenge Suite 5: Corrupt Cache Resilience Matrix
// ============================================================================

#[test]
fn test_adversarial_corrupt_cache_recovery_matrix() {
    let test_dir = std::env::temp_dir().join(format!("zprt_corrupt_matrix_{}", std::process::id()));
    let _ = fs::create_dir_all(&test_dir);

    let json_path = test_dir.join("routing_rules.json");
    let bin_path = test_dir.join("routing_rules.bin");

    // Standard valid JSON database
    fs::write(&json_path, r#"{"4": "gamecool"}"#).unwrap();

    // Subtest A: 0-byte cache file
    {
        fs::write(&bin_path, b"").unwrap();
        assert!(
            SmartRouter::is_compilation_needed(&test_dir),
            "0-byte file must require compilation"
        );
        let router = SmartRouter::new(&test_dir);
        assert!(router.is_mapped(), "Must recover from 0-byte file");
        assert_eq!(router.should_route("game"), (true, "database_routed"));
    }

    // Subtest B: Truncated headers (1 byte, 16 bytes, 32 bytes, 63 bytes)
    for &trunc_size in &[1usize, 16, 32, 63] {
        let garbage = vec![0x42u8; trunc_size];
        fs::write(&bin_path, &garbage).unwrap();
        assert!(
            SmartRouter::is_compilation_needed(&test_dir),
            "Truncated header of {} bytes must require compilation",
            trunc_size
        );
        let router = SmartRouter::new(&test_dir);
        assert!(router.is_mapped(), "Must recover from {}-byte truncated header", trunc_size);
        assert_eq!(router.should_route("cool"), (true, "database_routed"));
    }

    // Subtest C: Invalid magic bytes (0xDEADBEEF instead of 0x5A505254)
    {
        let header = BinaryHeaderV2 {
            magic: 0xDEADBEEF,
            version: FORMAT_VERSION,
            header_size: HEADER_SIZE,
            source_mtime_epoch: 1000,
            total_domain_count: 2,
            bucket_table_offset: 64,
            bucket_table_len: 2048,
            payload_offset: 2112,
            payload_len: 8,
            cidr_table_offset: 2120,
            cidr_table_len: 0,
            target_ipv4_cidr_count: 0,
            exclude_ipv4_cidr_count: 0,
            target_ipv6_cidr_count: 0,
            exclude_ipv6_cidr_count: 0,
            target_list_domain_count: 0,
            exclude_list_domain_count: 0,
            checksum: 0,
        };
        fs::write(&bin_path, header.to_bytes()).unwrap();
        assert!(
            SmartRouter::is_compilation_needed(&test_dir),
            "Invalid magic 0xDEADBEEF must require compilation"
        );
        let router = SmartRouter::new(&test_dir);
        assert!(router.is_mapped());
        assert_eq!(router.header().unwrap().magic, MAGIC);
        assert_eq!(router.should_route("game"), (true, "database_routed"));
    }

    // Subtest D: Mismatched version (version 1 and version 99)
    for &bad_version in &[1u16, 99u16] {
        let header = BinaryHeaderV2 {
            magic: MAGIC,
            version: bad_version,
            header_size: HEADER_SIZE,
            source_mtime_epoch: 1000,
            total_domain_count: 2,
            bucket_table_offset: 64,
            bucket_table_len: 2048,
            payload_offset: 2112,
            payload_len: 8,
            cidr_table_offset: 2120,
            cidr_table_len: 0,
            target_ipv4_cidr_count: 0,
            exclude_ipv4_cidr_count: 0,
            target_ipv6_cidr_count: 0,
            exclude_ipv6_cidr_count: 0,
            target_list_domain_count: 0,
            exclude_list_domain_count: 0,
            checksum: 0,
        };
        fs::write(&bin_path, header.to_bytes()).unwrap();
        assert!(
            SmartRouter::is_compilation_needed(&test_dir),
            "Bad version {} must require compilation",
            bad_version
        );
        let router = SmartRouter::new(&test_dir);
        assert!(router.is_mapped());
        assert_eq!(router.header().unwrap().version, FORMAT_VERSION);
    }

    // Subtest E: Truncated payload (header says payload 10,000 bytes, but file is only 100 bytes)
    {
        let header = BinaryHeaderV2 {
            magic: MAGIC,
            version: FORMAT_VERSION,
            header_size: HEADER_SIZE,
            source_mtime_epoch: 1000,
            total_domain_count: 2500,
            bucket_table_offset: 64,
            bucket_table_len: 2048,
            payload_offset: 2112,
            payload_len: 10000,
            cidr_table_offset: 12112,
            cidr_table_len: 64,
            target_ipv4_cidr_count: 0,
            exclude_ipv4_cidr_count: 0,
            target_ipv6_cidr_count: 0,
            exclude_ipv6_cidr_count: 0,
            target_list_domain_count: 0,
            exclude_list_domain_count: 0,
            checksum: 0,
        };
        let mut truncated_data = header.to_bytes().to_vec();
        truncated_data.extend_from_slice(&vec![0u8; 100]); // truncated before cidr_table_offset
        fs::write(&bin_path, &truncated_data).unwrap();

        // Router must detect truncated payload during mmap load, recompile, and succeed
        let router = SmartRouter::new(&test_dir);
        assert!(router.is_mapped(), "Must recover from truncated payload file");
        assert_eq!(router.should_route("cool"), (true, "database_routed"));
    }

    let _ = fs::remove_dir_all(&test_dir);
}

// ============================================================================
// Challenge Suite 6: Multi-File Mtime Invalidation Matrix
// ============================================================================

#[test]
fn test_adversarial_multi_file_mtime_invalidation_matrix() {
    let test_dir = std::env::temp_dir().join(format!("zprt_mtime_matrix_{}", std::process::id()));
    let lists_dir = test_dir.join("lists");
    let _ = fs::create_dir_all(&lists_dir);

    let json_path = test_dir.join("routing_rules.json");
    let bin_path = test_dir.join("routing_rules.bin");

    let list_gen = lists_dir.join("list-general.txt");
    let list_goog = lists_dir.join("list-google.txt");
    let list_exc = lists_dir.join("list-exclude.txt");
    let ipset_tgt = lists_dir.join("ipset-target.txt");
    let ipset_exc = lists_dir.join("ipset-exclude.txt");

    fs::write(&json_path, r#"{"4": "game"}"#).unwrap();
    fs::write(&list_gen, "domain1.com\n").unwrap();
    fs::write(&list_goog, "domain2.com\n").unwrap();
    fs::write(&list_exc, "excluded1.com\n").unwrap();
    fs::write(&ipset_tgt, "104.16.0.0/13\n").unwrap();
    fs::write(&ipset_exc, "192.168.0.0/16\n").unwrap();

    // 1. Initial compilation
    assert!(SmartRouter::is_compilation_needed(&test_dir));
    SmartRouter::compile(&test_dir).unwrap();
    assert!(bin_path.exists());
    assert!(!SmartRouter::is_compilation_needed(&test_dir));

    let list_files = [
        ("list-general.txt", &list_gen, "domain1.com\nnew-gen.com\n"),
        ("list-google.txt", &list_goog, "domain2.com\nnew-goog.com\n"),
        ("list-exclude.txt", &list_exc, "excluded1.com\nnew-exc.com\n"),
        ("ipset-target.txt", &ipset_tgt, "104.16.0.0/13\n104.24.0.0/14\n"),
        ("ipset-exclude.txt", &ipset_exc, "192.168.0.0/16\n10.0.0.0/8\n"),
    ];

    // 2. Iterate through each list file: advancing mtime MUST invalidate binary cache
    for (name, path, new_content) in list_files {
        std::thread::sleep(Duration::from_millis(60));
        fs::write(path, new_content).unwrap();

        assert!(
            SmartRouter::is_compilation_needed(&test_dir),
            "Advancing mtime of '{}' must trigger is_compilation_needed == true",
            name
        );

        // Load database recompiles automatically
        let router = SmartRouter::new(&test_dir);
        assert!(router.is_mapped());
        assert!(
            !SmartRouter::is_compilation_needed(&test_dir),
            "After router load, is_compilation_needed must be false for '{}'",
            name
        );
    }

    // 3. Modifying routing_rules.json itself MUST invalidate binary cache
    std::thread::sleep(Duration::from_millis(60));
    fs::write(&json_path, r#"{"4": "gamecool"}"#).unwrap();
    assert!(
        SmartRouter::is_compilation_needed(&test_dir),
        "Advancing mtime of routing_rules.json must trigger compilation"
    );

    let router = SmartRouter::new(&test_dir);
    assert!(router.is_mapped());
    assert!(
        !SmartRouter::is_compilation_needed(&test_dir),
        "Immediately after compilation, cache must be fresh"
    );

    // Dynamic domain registration via auto_add_domain:
    // When "cool" matches from database, it is registered into list-general-user.txt.
    // This updates list-general-user.txt mtime, which invalidates routing_rules.bin!
    assert_eq!(router.should_route("cool"), (true, "database_routed"));
    assert!(
        SmartRouter::is_compilation_needed(&test_dir),
        "auto_add_domain write to user list file must trigger compilation requirement"
    );

    // Next router initialization recompiles to incorporate newly added domain into binary cache
    let router2 = SmartRouter::new(&test_dir);
    assert!(router2.is_mapped());
    assert!(!SmartRouter::is_compilation_needed(&test_dir));
    assert_eq!(router2.should_route("cool"), (true, "target_routed"));

    // 4. Verify no stray .tmp files left in test directory
    if let Ok(entries) = fs::read_dir(&test_dir) {
        for entry in entries.filter_map(Result::ok) {
            let filename = entry.file_name().to_string_lossy().to_string();
            assert!(
                !filename.ends_with(".tmp"),
                "Leaked temporary staging file found: {}",
                filename
            );
        }
    }

    let _ = fs::remove_dir_all(&test_dir);
}
