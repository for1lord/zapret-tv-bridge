use std::fs::{self, File};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use memmap2::Mmap;

use zapret_tv_bridge_rs::router::{
    binary_search_bucket, contains_ipv4, parse_ipv4_cidr, SmartRouter,
};

/// Helper to query Windows Private Committed Bytes (PagefileUsage) and Working Set
fn get_process_memory_stats() -> (usize, usize) {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct PROCESS_MEMORY_COUNTERS {
        cb: u32,
        PageFaultCount: u32,
        PeakWorkingSetSize: usize,
        WorkingSetSize: usize,
        QuotaPeakPagedPoolUsage: usize,
        QuotaPagedPoolUsage: usize,
        QuotaPeakNonPagedPoolUsage: usize,
        QuotaNonPagedPoolUsage: usize,
        PagefileUsage: usize,
        PeakPagefileUsage: usize,
    }

    extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut std::ffi::c_void,
            ppsmc: *mut PROCESS_MEMORY_COUNTERS,
            cb: u32,
        ) -> i32;
    }

    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let proc = GetCurrentProcess();
        if K32GetProcessMemoryInfo(proc, &mut counters, counters.cb) != 0 {
            (counters.PagefileUsage, counters.WorkingSetSize)
        } else {
            (0, 0)
        }
    }
}

// =========================================================================
// SECTION 1: Empirical Subnet Interval Boundary Testing
// =========================================================================

#[test]
fn test_empirical_target_subnet_boundaries() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        eprintln!("Skipping: base dir rules not found");
        return;
    }
    let router = SmartRouter::new(base_dir);

    // 1. Target Subnet: 142.250.0.0/15 (Google & YouTube CDN)
    let below_142_250 = IpAddr::V4(Ipv4Addr::new(142, 249, 255, 255));
    let start_142_250 = IpAddr::V4(Ipv4Addr::new(142, 250, 0, 0));
    let mid_142_250_a = IpAddr::V4(Ipv4Addr::new(142, 250, 128, 0));
    let mid_142_250_b = IpAddr::V4(Ipv4Addr::new(142, 251, 0, 1));
    let end_142_250 = IpAddr::V4(Ipv4Addr::new(142, 251, 255, 255));
    let above_142_250 = IpAddr::V4(Ipv4Addr::new(142, 252, 0, 0));

    assert_ne!(router.should_route_ip(below_142_250).1, "target_routed");
    assert_eq!(
        router.should_route_ip(start_142_250),
        (true, "target_routed")
    );
    assert_eq!(
        router.should_route_ip(mid_142_250_a),
        (true, "target_routed")
    );
    assert_eq!(
        router.should_route_ip(mid_142_250_b),
        (true, "target_routed")
    );
    assert_eq!(router.should_route_ip(end_142_250), (true, "target_routed"));
    assert_ne!(router.should_route_ip(above_142_250).1, "target_routed");

    // 2. Target Subnet: 66.22.196.0/22 (Discord Voice RTC)
    let iv_discord = parse_ipv4_cidr("66.22.196.0/22").expect("Parse 66.22.196.0/22");
    assert_eq!(iv_discord.start, u32::from(Ipv4Addr::new(66, 22, 196, 0)));
    assert_eq!(iv_discord.end, u32::from(Ipv4Addr::new(66, 22, 199, 255)));

    let discord_slice = [iv_discord];
    assert!(!contains_ipv4(
        &discord_slice,
        u32::from(Ipv4Addr::new(66, 22, 195, 255))
    ));
    assert!(contains_ipv4(
        &discord_slice,
        u32::from(Ipv4Addr::new(66, 22, 196, 0))
    ));
    assert!(contains_ipv4(
        &discord_slice,
        u32::from(Ipv4Addr::new(66, 22, 197, 128))
    ));
    assert!(contains_ipv4(
        &discord_slice,
        u32::from(Ipv4Addr::new(66, 22, 199, 255))
    ));
    assert!(!contains_ipv4(
        &discord_slice,
        u32::from(Ipv4Addr::new(66, 22, 200, 0))
    ));

    let below_66_22 = IpAddr::V4(Ipv4Addr::new(66, 22, 195, 255));
    let start_66_22 = IpAddr::V4(Ipv4Addr::new(66, 22, 196, 0));
    let mid_66_22 = IpAddr::V4(Ipv4Addr::new(66, 22, 197, 128));
    let end_66_22_single = IpAddr::V4(Ipv4Addr::new(66, 22, 199, 255));
    let end_66_22_merged = IpAddr::V4(Ipv4Addr::new(66, 22, 211, 255));
    let above_66_22_merged = IpAddr::V4(Ipv4Addr::new(66, 22, 212, 0));

    assert_ne!(router.should_route_ip(below_66_22).1, "target_routed");
    assert_eq!(router.should_route_ip(start_66_22), (true, "target_routed"));
    assert_eq!(router.should_route_ip(mid_66_22), (true, "target_routed"));
    assert_eq!(
        router.should_route_ip(end_66_22_single),
        (true, "target_routed")
    );
    assert_eq!(
        router.should_route_ip(end_66_22_merged),
        (true, "target_routed")
    );
    assert_ne!(
        router.should_route_ip(above_66_22_merged).1,
        "target_routed"
    );

    // 3. Target Subnet: 104.16.0.0/13 (Cloudflare & Media CDNs)
    let iv_cf = parse_ipv4_cidr("104.16.0.0/13").expect("Parse 104.16.0.0/13");
    assert_eq!(iv_cf.start, u32::from(Ipv4Addr::new(104, 16, 0, 0)));
    assert_eq!(iv_cf.end, u32::from(Ipv4Addr::new(104, 23, 255, 255)));

    let cf_slice = [iv_cf];
    assert!(!contains_ipv4(
        &cf_slice,
        u32::from(Ipv4Addr::new(104, 15, 255, 255))
    ));
    assert!(contains_ipv4(
        &cf_slice,
        u32::from(Ipv4Addr::new(104, 16, 0, 0))
    ));
    assert!(contains_ipv4(
        &cf_slice,
        u32::from(Ipv4Addr::new(104, 20, 0, 1))
    ));
    assert!(contains_ipv4(
        &cf_slice,
        u32::from(Ipv4Addr::new(104, 23, 255, 255))
    ));
    assert!(!contains_ipv4(
        &cf_slice,
        u32::from(Ipv4Addr::new(104, 24, 0, 0))
    ));

    let below_104_16 = IpAddr::V4(Ipv4Addr::new(104, 15, 255, 255));
    let start_104_16 = IpAddr::V4(Ipv4Addr::new(104, 16, 0, 0));
    let mid_104_16 = IpAddr::V4(Ipv4Addr::new(104, 20, 0, 1));
    let end_104_16_single = IpAddr::V4(Ipv4Addr::new(104, 23, 255, 255));
    let end_104_16_merged = IpAddr::V4(Ipv4Addr::new(104, 27, 255, 255));
    let above_104_16_merged = IpAddr::V4(Ipv4Addr::new(104, 28, 0, 0));

    assert_ne!(router.should_route_ip(below_104_16).1, "target_routed");
    assert_eq!(
        router.should_route_ip(start_104_16),
        (true, "target_routed")
    );
    assert_eq!(router.should_route_ip(mid_104_16), (true, "target_routed"));
    assert_eq!(
        router.should_route_ip(end_104_16_single),
        (true, "target_routed")
    );
    assert_eq!(
        router.should_route_ip(end_104_16_merged),
        (true, "target_routed")
    );
    assert_ne!(
        router.should_route_ip(above_104_16_merged).1,
        "target_routed"
    );
}

#[test]
fn test_empirical_exclude_subnet_boundaries() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        return;
    }
    let router = SmartRouter::new(base_dir);

    // 1. Exclude Subnet: 192.168.0.0/16 (Private RFC 1918)
    let below_192_168 = IpAddr::V4(Ipv4Addr::new(192, 167, 255, 255));
    let start_192_168 = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0));
    let mid_192_168 = IpAddr::V4(Ipv4Addr::new(192, 168, 128, 1));
    let end_192_168 = IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255));
    let above_192_168 = IpAddr::V4(Ipv4Addr::new(192, 169, 0, 0));

    assert_ne!(router.should_route_ip(below_192_168).1, "exclude_direct");
    assert_eq!(
        router.should_route_ip(start_192_168),
        (false, "exclude_direct")
    );
    assert_eq!(
        router.should_route_ip(mid_192_168),
        (false, "exclude_direct")
    );
    assert_eq!(
        router.should_route_ip(end_192_168),
        (false, "exclude_direct")
    );
    assert_ne!(router.should_route_ip(above_192_168).1, "exclude_direct");

    // 2. Exclude Subnet: 10.0.0.0/8 (Private RFC 1918)
    let below_10 = IpAddr::V4(Ipv4Addr::new(9, 255, 255, 255));
    let start_10 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let mid_10 = IpAddr::V4(Ipv4Addr::new(10, 128, 0, 1));
    let end_10 = IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255));
    let above_10 = IpAddr::V4(Ipv4Addr::new(11, 0, 0, 0));

    assert_ne!(router.should_route_ip(below_10).1, "exclude_direct");
    assert_eq!(router.should_route_ip(start_10), (false, "exclude_direct"));
    assert_eq!(router.should_route_ip(mid_10), (false, "exclude_direct"));
    assert_eq!(router.should_route_ip(end_10), (false, "exclude_direct"));
    assert_ne!(router.should_route_ip(above_10).1, "exclude_direct");

    // 3. Exclude Subnet: 127.0.0.0/8 (Loopback RFC 1122)
    let below_127 = IpAddr::V4(Ipv4Addr::new(126, 255, 255, 255));
    let start_127 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0));
    let mid_127 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let end_127 = IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255));
    let above_127 = IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0));

    assert_ne!(router.should_route_ip(below_127).1, "exclude_direct");
    assert_eq!(router.should_route_ip(start_127), (false, "exclude_direct"));
    assert_eq!(router.should_route_ip(mid_127), (false, "exclude_direct"));
    assert_eq!(router.should_route_ip(end_127), (false, "exclude_direct"));
    assert_ne!(router.should_route_ip(above_127).1, "exclude_direct");
}

#[test]
fn test_empirical_ipv6_interval_boundaries() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        return;
    }
    let router = SmartRouter::new(base_dir);

    // 1. IPv6 Loopback: ::1 (RFC 4291)
    let below_v6_loopback: IpAddr = "::".parse().unwrap();
    let exact_v6_loopback: IpAddr = "::1".parse().unwrap();
    let above_v6_loopback: IpAddr = "::2".parse().unwrap();

    assert_ne!(
        router.should_route_ip(below_v6_loopback).1,
        "exclude_direct"
    );
    assert_eq!(
        router.should_route_ip(exact_v6_loopback),
        (false, "exclude_direct")
    );
    assert_ne!(
        router.should_route_ip(above_v6_loopback).1,
        "exclude_direct"
    );

    // 2. IPv6 Unique Local Address: fc00::/7 (RFC 4193)
    let below_fc00: IpAddr = "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
    let start_fc00: IpAddr = "fc00::".parse().unwrap();
    let mid_fc00_a: IpAddr = "fc80::1".parse().unwrap();
    let mid_fc00_b: IpAddr = "fd00::dead:beef".parse().unwrap();
    let end_fc00: IpAddr = "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
    let above_fc00: IpAddr = "fe00::".parse().unwrap();

    assert_ne!(router.should_route_ip(below_fc00).1, "exclude_direct");
    assert_eq!(
        router.should_route_ip(start_fc00),
        (false, "exclude_direct")
    );
    assert_eq!(
        router.should_route_ip(mid_fc00_a),
        (false, "exclude_direct")
    );
    assert_eq!(
        router.should_route_ip(mid_fc00_b),
        (false, "exclude_direct")
    );
    assert_eq!(router.should_route_ip(end_fc00), (false, "exclude_direct"));
    assert_ne!(router.should_route_ip(above_fc00).1, "exclude_direct");

    // 3. IPv6 Link-Local Unicast: fe80::/10 (RFC 4291)
    let below_fe80: IpAddr = "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
    let start_fe80: IpAddr = "fe80::".parse().unwrap();
    let mid_fe80_a: IpAddr = "fe80::1".parse().unwrap();
    let mid_fe80_b: IpAddr = "fe90::1".parse().unwrap();
    let mid_fe80_c: IpAddr = "fea0::1".parse().unwrap();
    let end_fe80: IpAddr = "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
    let above_fe80: IpAddr = "fec0::".parse().unwrap();

    assert_ne!(router.should_route_ip(below_fe80).1, "exclude_direct");
    assert_eq!(
        router.should_route_ip(start_fe80),
        (false, "exclude_direct")
    );
    assert_eq!(
        router.should_route_ip(mid_fe80_a),
        (false, "exclude_direct")
    );
    assert_eq!(
        router.should_route_ip(mid_fe80_b),
        (false, "exclude_direct")
    );
    assert_eq!(
        router.should_route_ip(mid_fe80_c),
        (false, "exclude_direct")
    );
    assert_eq!(router.should_route_ip(end_fe80), (false, "exclude_direct"));
    assert_ne!(router.should_route_ip(above_fe80).1, "exclude_direct");
}

// =========================================================================
// SECTION 2: High-Throughput & Latency Benchmarking (1,000,000 queries)
// =========================================================================

#[test]
fn test_empirical_1m_cidr_and_mmap_benchmarks() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        return;
    }
    let router = SmartRouter::new(base_dir);

    let count: usize = 1_000_000;

    // -------------------------------------------------------------
    // Benchmark 1: 1,000,000 IP Queries on CIDR Tables (Feature F12)
    // -------------------------------------------------------------
    let ip_pool: [IpAddr; 8] = [
        "192.168.1.1".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
        "142.250.180.14".parse().unwrap(),
        "66.22.196.10".parse().unwrap(),
        "104.16.1.1".parse().unwrap(),
        "::1".parse().unwrap(),
        "fe80::1".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
    ];

    // Warm-up to fault in cache lines
    for i in 0..10_000 {
        let ip = ip_pool[i % ip_pool.len()];
        black_box(router.should_route_ip(ip));
    }

    let (mem_priv_before, mem_ws_before) = get_process_memory_stats();
    let t0 = Instant::now();
    for i in 0..count {
        let ip = ip_pool[i % ip_pool.len()];
        black_box(router.should_route_ip(ip));
    }
    let elapsed_ip = t0.elapsed();
    let (mem_priv_after, mem_ws_after) = get_process_memory_stats();

    let avg_ns_ip = (elapsed_ip.as_nanos() as f64) / (count as f64);
    let qps_ip = (count as f64) / elapsed_ip.as_secs_f64();
    let priv_delta_kb = (mem_priv_after as isize - mem_priv_before as isize) / 1024;
    let ws_delta_kb = (mem_ws_after as isize - mem_ws_before as isize) / 1024;

    println!("\n=======================================================");
    println!(" [Benchmark 1: 1M CIDR IP Queries (Feature F12)]");
    println!(" Total queries:           {}", count);
    println!(
        " Duration:                {:.2} ms",
        elapsed_ip.as_secs_f64() * 1000.0
    );
    println!(" Average latency:         {:.2} ns / query", avg_ns_ip);
    println!(" Throughput:              {:.2} queries / second", qps_ip);
    println!(" Private Commit Delta:    {} KB", priv_delta_kb);
    println!(" Working Set Delta:       {} KB", ws_delta_kb);
    println!("=======================================================\n");

    // Empirical assertion: CIDR query latency MUST be < 100 ns
    assert!(
        avg_ns_ip < 100.0,
        "CIDR average query latency ({:.2} ns) exceeded 100 ns threshold!",
        avg_ns_ip
    );
    // Zero heap memory leak assertion: Private commit must not grow
    assert!(
        priv_delta_kb.abs() <= 64,
        "Heap/private memory grew by {} KB across 1M CIDR queries!",
        priv_delta_kb
    );

    // -------------------------------------------------------------
    // Benchmark 2: 1,000,000 Pure Mmap Database Binary Searches (Feature F10)
    // -------------------------------------------------------------
    let bin_path = base_dir.join("routing_rules.bin");
    let file = File::open(&bin_path).expect("Open routing_rules.bin");
    let mmap = unsafe { Mmap::map(&file).expect("Mmap routing_rules.bin") };

    let entry15 = router.bucket_entry(15).expect("Bucket 15");
    assert!(entry15.byte_len > 0, "Bucket 15 must contain words");
    let slice15 = &mmap[entry15.offset as usize..(entry15.offset + entry15.byte_len) as usize];

    let search_targets: [&[u8]; 4] = [
        b"01lordfilm.zone",
        b"1000dosok.ru---",
        b"zzzzzzzzzzzzzzz",
        b"aaaaaaaaaaaaaaa",
    ];

    let t1 = Instant::now();
    for i in 0..count {
        let target = search_targets[i % search_targets.len()];
        black_box(binary_search_bucket(slice15, 15, target));
    }
    let elapsed_mmap = t1.elapsed();
    let avg_ns_mmap = (elapsed_mmap.as_nanos() as f64) / (count as f64);
    let qps_mmap = (count as f64) / elapsed_mmap.as_secs_f64();

    println!("\n=======================================================");
    println!(" [Benchmark 2: 1M Pure Mmap Binary Searches (Feature F10)]");
    println!(" Total queries:           {}", count);
    println!(
        " Duration:                {:.2} ms",
        elapsed_mmap.as_secs_f64() * 1000.0
    );
    println!(" Average latency:         {:.2} ns / query", avg_ns_mmap);
    println!(" Throughput:              {:.2} queries / second", qps_mmap);
    println!("=======================================================\n");

    assert!(
        avg_ns_mmap < 100.0,
        "Mmap binary search latency ({:.2} ns) exceeded 100 ns threshold!",
        avg_ns_mmap
    );

    // -------------------------------------------------------------
    // Benchmark 3: 1,000,000 Subnet Interval Checks (contains_ipv4)
    // -------------------------------------------------------------
    let target_ivs = router.target_ipv4_intervals();
    let test_addrs: [u32; 4] = [
        u32::from(Ipv4Addr::new(142, 250, 180, 14)),
        u32::from(Ipv4Addr::new(66, 22, 196, 10)),
        u32::from(Ipv4Addr::new(8, 8, 8, 8)),
        u32::from(Ipv4Addr::new(1, 1, 1, 1)),
    ];

    let t2 = Instant::now();
    for i in 0..count {
        let addr = test_addrs[i % test_addrs.len()];
        black_box(contains_ipv4(target_ivs, addr));
    }
    let elapsed_iv = t2.elapsed();
    let avg_ns_iv = (elapsed_iv.as_nanos() as f64) / (count as f64);
    let qps_iv = (count as f64) / elapsed_iv.as_secs_f64();

    println!("\n=======================================================");
    println!(" [Benchmark 3: 1M Pure Subnet Interval Checks (contains_ipv4)]");
    println!(" Total queries:           {}", count);
    println!(
        " Duration:                {:.2} ms",
        elapsed_iv.as_secs_f64() * 1000.0
    );
    println!(" Average latency:         {:.2} ns / query", avg_ns_iv);
    println!(" Throughput:              {:.2} queries / second", qps_iv);
    println!("=======================================================\n");

    assert!(
        avg_ns_iv < 10.0,
        "Interval check latency ({:.2} ns) exceeded 10 ns threshold!",
        avg_ns_iv
    );
}

// =========================================================================
// SECTION 3: Multi-Thread Concurrency & Contention Stress
// =========================================================================

#[test]
fn test_empirical_8_thread_concurrency_stress_with_auto_add() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        return;
    }

    let test_dir =
        std::env::temp_dir().join(format!("zprt_challenger_stress_{}", std::process::id()));
    let lists_dir = test_dir.join("lists");
    fs::create_dir_all(&lists_dir).expect("Create test lists dir");

    let _ = fs::copy(
        base_dir.join("routing_rules.bin"),
        test_dir.join("routing_rules.bin"),
    );
    let _ = fs::copy(
        base_dir.join("routing_rules.json"),
        test_dir.join("routing_rules.json"),
    );

    if let Ok(entries) = fs::read_dir(base_dir.join("lists")) {
        for entry in entries.filter_map(Result::ok) {
            let _ = fs::copy(entry.path(), lists_dir.join(entry.file_name()));
        }
    }
    let user_list_path = lists_dir.join("list-general-user.txt");
    fs::write(&user_list_path, "").expect("Init user list");

    let router = Arc::new(SmartRouter::new(&test_dir));

    let stop_signal = Arc::new(AtomicBool::new(false));
    let read_queries_completed = Arc::new(AtomicUsize::new(0));
    let auto_added_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();

    // Spawn 8 reader worker threads
    for _ in 0..8 {
        let r = Arc::clone(&router);
        let stop = Arc::clone(&stop_signal);
        let completed = Arc::clone(&read_queries_completed);

        handles.push(std::thread::spawn(move || {
            let sample_domains = [
                "yandex.ru",
                "video.google.com",
                "rr1---sn-vgqsknzk.googlevideo.com",
                "discord.com",
                "vk.com",
                "apple.com",
                "0.1lordfilm.one",
                "random-unlisted-direct.com",
            ];
            let sample_ips: [IpAddr; 4] = [
                "192.168.1.1".parse().unwrap(),
                "142.250.180.14".parse().unwrap(),
                "66.22.196.10".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
            ];

            let mut count = 0usize;
            let mut round = 0usize;

            while !stop.load(Ordering::Relaxed) && count < 100_000 {
                let domain = sample_domains[round % sample_domains.len()];
                let ip = sample_ips[round % sample_ips.len()];

                let (route_dom, tag_dom) = r.should_route(domain);
                let (route_ip, tag_ip) = r.should_route_ip(ip);

                black_box((route_dom, tag_dom));
                black_box((route_ip, tag_ip));

                count += 2;
                round += 1;
            }

            completed.fetch_add(count, Ordering::Relaxed);
            count
        }));
    }

    // Spawn 2 concurrent writer threads calling auto_add_domain during active reads
    for writer_idx in 0..2 {
        let r = Arc::clone(&router);
        let stop = Arc::clone(&stop_signal);
        let added = Arc::clone(&auto_added_count);

        handles.push(std::thread::spawn(move || {
            let mut write_count = 0usize;
            while !stop.load(Ordering::Relaxed) && write_count < 500 {
                let domain = format!("concurrent-dyn-domain-{}-{}.org", writer_idx, write_count);
                r.auto_add_domain(&domain);

                let (routed, reason) = r.should_route(&domain);
                assert!(routed, "Dynamically added domain must route immediately");
                assert_eq!(reason, "target_routed");

                write_count += 1;
                added.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
            write_count
        }));
    }

    let start = Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(1500) {
        if read_queries_completed.load(Ordering::Relaxed) >= 800_000 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    stop_signal.store(true, Ordering::SeqCst);

    for (i, h) in handles.into_iter().enumerate() {
        let res = h.join();
        assert!(
            res.is_ok(),
            "Thread #{} panicked during concurrency stress test!",
            i
        );
    }

    let total_reads = read_queries_completed.load(Ordering::Relaxed);
    let total_writes = auto_added_count.load(Ordering::Relaxed);

    println!("\n=======================================================");
    println!(" [8-Thread Concurrency & Dynamic auto_add Stress]");
    println!(" Total concurrent reads:  {}", total_reads);
    println!(" Total dynamic writes:    {}", total_writes);
    println!(" Contention panics:       0");
    println!(" Contention deadlocks:    0");
    println!("=======================================================\n");

    assert!(total_reads > 50_000);
    assert!(total_writes > 10);

    let _ = fs::remove_dir_all(&test_dir);
}
