use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use zapret_tv_bridge_rs::router::{
    SmartRouter, FORMAT_VERSION, HEADER_SIZE, MAGIC,
};

#[test]
fn test_e2e_binary_cache_format_v2_compilation_and_mmap() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        eprintln!("Skipping test: routing_rules.json not found in base dir");
        return;
    }

    let router = SmartRouter::new(base_dir);
    assert!(router.is_mapped(), "Database must be mapped via mmap");

    let header = router.header().expect("Header must be present");
    assert_eq!(header.magic, MAGIC, "Magic bytes must match 0x5A505254");
    assert_eq!(header.version, FORMAT_VERSION, "Version must be 2");
    assert_eq!(header.header_size, HEADER_SIZE, "Header size must be 64 bytes");
    assert_eq!(header.bucket_table_offset, 64);
    assert_eq!(header.bucket_table_len, 2048);
    assert_eq!(header.payload_offset, 2112);
    assert!(header.total_domain_count >= 662000, "Should contain >= 662k domains");

    assert!(router.target_ipv4_intervals().len() >= 10, "Target IPv4 intervals must be populated");
    assert!(router.exclude_ipv4_intervals().len() >= 5, "Exclude IPv4 intervals must be populated");
    assert!(router.exclude_ipv6_intervals().len() >= 3, "Exclude IPv6 intervals must be populated");
}

#[test]
fn test_e2e_deterministic_priority_order_domains() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        return;
    }

    let test_dir = std::env::temp_dir().join(format!("zprt_test_domains_{}", std::process::id()));
    let _ = fs::create_dir_all(&test_dir);
    let _ = fs::copy(base_dir.join("routing_rules.bin"), test_dir.join("routing_rules.bin"));
    let _ = fs::copy(base_dir.join("routing_rules.json"), test_dir.join("routing_rules.json"));

    let lists_src = base_dir.join("lists");
    let lists_dst = test_dir.join("lists");
    let _ = fs::create_dir_all(&lists_dst);
    if let Ok(entries) = fs::read_dir(&lists_src) {
        for entry in entries.filter_map(Result::ok) {
            let _ = fs::copy(entry.path(), lists_dst.join(entry.file_name()));
        }
    }

    let router = SmartRouter::new(&test_dir);

    // Priority 1: Exclude lists & domestic services -> direct ("exclude_direct")
    assert_eq!(router.should_route("yandex.ru"), (false, "exclude_direct"));
    assert_eq!(router.should_route("sub.yandex.ru"), (false, "exclude_direct"));
    assert_eq!(router.should_route("vk.com"), (false, "exclude_direct"));
    assert_eq!(router.should_route("sberbank.ru"), (false, "exclude_direct"));
    assert_eq!(router.should_route("gosuslugi.ru"), (false, "exclude_direct"));
    assert_eq!(router.should_route("apple.com"), (false, "exclude_direct"));
    assert_eq!(router.should_route("icloud.com"), (false, "exclude_direct"));
    assert_eq!(router.should_route("chatgpt.com"), (false, "exclude_direct"));
    assert_eq!(router.should_route("claude.ai"), (false, "exclude_direct"));
    assert_eq!(router.should_route("supercell.com"), (false, "exclude_direct"));
    assert_eq!(router.should_route("localhost"), (false, "exclude_direct"));
    assert_eq!(router.should_route("device.local"), (false, "exclude_direct"));

    // Priority 2: Target lists and streaming services -> routed ("target_routed")
    assert_eq!(router.should_route("video.google.com"), (true, "target_routed"));
    assert_eq!(router.should_route("rr1---sn-vgqsknzk.googlevideo.com"), (true, "target_routed"));
    assert_eq!(router.should_route("youtube.com"), (true, "target_routed"));
    assert_eq!(router.should_route("youtu.be"), (true, "target_routed"));
    assert_eq!(router.should_route("game.clashroyaleapp.com"), (true, "target_routed"));
    assert_eq!(router.should_route("game.brawlstarsgame.com"), (true, "target_routed"));
    assert_eq!(router.should_route("discord.com"), (true, "target_routed"));
    assert_eq!(router.should_route("instagram.com"), (true, "target_routed"));
    assert_eq!(router.should_route("x.com"), (true, "target_routed"));
    assert_eq!(router.should_route("rutracker.org"), (true, "target_routed"));

    // Wildcard normalization: *.phncdn.com -> phncdn.com
    assert_eq!(router.should_route("video.phncdn.com"), (true, "target_routed"));
    assert_eq!(router.should_route("phncdn.com"), (true, "target_routed"));
    assert_eq!(router.should_route("a.b.c.phncdn.com"), (true, "target_routed"));

    // Priority 3: 662k database rules (via mmap binary search) -> routed ("database_routed")
    assert_eq!(router.should_route("0.1lordfilm.one"), (true, "database_routed"));

    // Priority 4: Default -> direct ("default_direct")
    assert_eq!(router.should_route("random-unlisted-domain-12345.xyz"), (false, "default_direct"));
    assert_eq!(router.should_route("unknown-service-test.com"), (false, "default_direct"));

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_e2e_cidr_ip_classification() {
    let base_dir = Path::new("d:\\projects\\zapret-tv-bridge");
    if !base_dir.join("routing_rules.json").exists() {
        return;
    }
    let router = SmartRouter::new(base_dir);

    // Priority 1: Exclude subnets / RFC 1918 / loopback -> direct ("exclude_direct")
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))), (false, "exclude_direct"));
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), (false, "exclude_direct"));
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), (false, "exclude_direct"));
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))), (false, "exclude_direct"));
    assert_eq!(router.should_route_ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))), (false, "exclude_direct")); // ::1
    assert_eq!(router.should_route_ip("fe80::1".parse().unwrap()), (false, "exclude_direct"));

    // Also verify should_route with IP strings delegates to should_route_ip
    assert_eq!(router.should_route("192.168.1.1"), (false, "exclude_direct"));
    assert_eq!(router.should_route("192.168.1.1:8080"), (false, "exclude_direct"));
    assert_eq!(router.should_route("[::1]:443"), (false, "exclude_direct"));
    assert_eq!(router.should_route("::1"), (false, "exclude_direct"));

    // Priority 2: Target CDN subnets -> routed ("target_routed")
    // Google CDN (142.250.0.0/15)
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(142, 250, 180, 14))), (true, "target_routed"));
    assert_eq!(router.should_route("142.250.180.14:443"), (true, "target_routed"));

    // Discord Voice RTC (66.22.196.0/22)
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(66, 22, 196, 10))), (true, "target_routed"));

    // Cloudflare (104.16.0.0/13, 104.24.0.0/14)
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1))), (true, "target_routed"));
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(104, 25, 1, 1))), (true, "target_routed"));

    // Telegram Media (91.108.56.0/22)
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(91, 108, 56, 1))), (true, "target_routed"));

    // This address is now an explicit ipset-all target, so it wins before the database tier.
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(5, 45, 70, 48))), (true, "target_routed"));
    assert_eq!(router.should_route("5.45.70.48"), (true, "target_routed"));

    // Priority 4: Default unlisted IP -> direct ("default_direct")
    assert_eq!(router.should_route_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), (false, "default_direct"));
    assert_eq!(router.should_route("8.8.8.8"), (false, "default_direct"));
}

#[test]
fn test_e2e_mtime_compilation_lifecycle() {
    let test_dir = std::env::temp_dir().join(format!("zprt_test_mtime_{}", std::process::id()));
    let lists_dir = test_dir.join("lists");
    let _ = fs::create_dir_all(&lists_dir);

    let json_path = test_dir.join("routing_rules.json");
    let bin_path = test_dir.join("routing_rules.bin");
    let list_general_path = lists_dir.join("list-general.txt");

    fs::write(&json_path, r#"{"4": "gamecooltestzone"}"#).unwrap();
    fs::write(&list_general_path, "targetdomain.com\n").unwrap();

    // 1. Initial compilation
    assert!(SmartRouter::is_compilation_needed(&test_dir));
    SmartRouter::compile(&test_dir).unwrap();
    assert!(bin_path.exists());
    assert!(!SmartRouter::is_compilation_needed(&test_dir));

    // 2. Advancing list file mtime triggers compilation requirement
    std::thread::sleep(std::time::Duration::from_millis(50));
    fs::write(&list_general_path, "targetdomain.com\nnewdomain.com\n").unwrap();
    assert!(SmartRouter::is_compilation_needed(&test_dir));

    // 3. Loading database recompiles automatically
    let router = SmartRouter::new(&test_dir);
    assert!(router.is_mapped());
    assert!(!SmartRouter::is_compilation_needed(&test_dir));
    assert_eq!(router.should_route("newdomain.com"), (true, "target_routed"));

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_e2e_corrupt_cache_recovery() {
    let test_dir = std::env::temp_dir().join(format!("zprt_test_corrupt_{}", std::process::id()));
    let _ = fs::create_dir_all(&test_dir);
    let json_path = test_dir.join("routing_rules.json");
    let bin_path = test_dir.join("routing_rules.bin");

    fs::write(&json_path, r#"{"4": "fastgameplayword"}"#).unwrap();

    // Write corrupted 16 bytes of garbage
    fs::write(&bin_path, b"CORRUPTED_CACHE_").unwrap();
    assert!(SmartRouter::is_compilation_needed(&test_dir));

    // Router automatically recovers from corrupt cache
    let router = SmartRouter::new(&test_dir);
    assert!(router.is_mapped());
    let hdr = router.header().unwrap();
    assert_eq!(hdr.version, FORMAT_VERSION);
    assert_eq!(hdr.magic, MAGIC);
    assert_eq!(router.should_route("fast"), (true, "database_routed"));

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_e2e_dynamic_auto_add_domain() {
    let test_dir = std::env::temp_dir().join(format!("zprt_test_dynamic_{}", std::process::id()));
    let lists_dir = test_dir.join("lists");
    let _ = fs::create_dir_all(&lists_dir);

    let json_path = test_dir.join("routing_rules.json");
    let user_list_path = lists_dir.join("list-general-user.txt");

    fs::write(&json_path, r#"{"4": "coolgame"}"#).unwrap();
    fs::write(&user_list_path, "").unwrap();

    let router = SmartRouter::new(&test_dir);
    assert_eq!(router.should_route("cool"), (true, "database_routed"));

    let contents = fs::read_to_string(&user_list_path).unwrap();
    assert!(
        !contents.contains("cool"),
        "A database hit must not be copied into the user list"
    );
    router.observe_domain("brand-new-stream.example", "target_routed");
    assert_eq!(router.should_route("brand-new-stream.example"), (true, "target_routed"));
    let contents = fs::read_to_string(&user_list_path).unwrap();
    assert!(contents.contains("brand-new-stream.example"));

    let _ = fs::remove_dir_all(&test_dir);
}
