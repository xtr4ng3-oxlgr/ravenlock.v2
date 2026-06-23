use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const APP: &str = "RAVENLOCK";
const VERSION: &str = "2.0.0";
const AUTHOR: &str = "xtr4ng3";

const STATE_DIR: &str = ".ravenlock";
const BASELINE_FILE: &str = "baseline.tsv";
const CANARY_FILE: &str = "canaries.tsv";
const CONFIG_FILE: &str = "ravenlock.toml";
const SEAL_FILE: &str = "baseline.seal";
const REPORT_DIR: &str = "reports";
const CANARY_NAME: &str = ".ravenlock_canary_xtr4ng3.txt";

const BANNER: &str = r#"
██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗██╗      ██████╗  ██████╗██╗  ██╗
██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║██║     ██╔═══██╗██╔════╝██║ ██╔╝
██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║██║     ██║   ██║██║     █████╔╝ 
██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║     ██║   ██║██║     ██╔═██╗ 
██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║███████╗╚██████╔╝╚██████╗██║  ██╗
╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
LOCAL INTEGRITY SENTINEL :: BASELINE SEAL :: CANARY DEFENSE
"#;

#[derive(Clone, Debug)]
struct Config {
    roots: Vec<PathBuf>,
    excludes: Vec<String>,
    interval_seconds: u64,
    max_file_mb: u64,
    reports: Vec<String>,
}

#[derive(Clone, Debug)]
struct Entry {
    path: String,
    size: u64,
    modified: u64,
    fingerprint: u64,
    extension: String,
}

#[derive(Clone, Debug)]
struct Finding {
    severity: String,
    category: String,
    title: String,
    detail: String,
    recommendation: String,
}

#[derive(Clone, Debug)]
struct ScanReport {
    roots: Vec<PathBuf>,
    total_files: usize,
    added: usize,
    modified: usize,
    deleted: usize,
    suspicious_extensions: usize,
    canary_alerts: usize,
    seal_valid: bool,
    score: u32,
    verdict: String,
    findings: Vec<Finding>,
    generated_at: String,
    elapsed_ms: u128,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    let command = args[1].as_str();
    let result = match command {
        "init" => cmd_init(&args[2..]),
        "scan" => cmd_scan(&args[2..], true),
        "watch" => cmd_watch(&args[2..]),
        "tui" => cmd_tui(&args[2..]),
        "status" => cmd_status(),
        "refresh" => cmd_refresh(&args[2..]),
        "config" => cmd_config(),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        _ => {
            eprintln!("Comando no reconocido: {}", command);
            print_help();
            Err(())
        }
    };

    if result.is_err() {
        std::process::exit(1);
    }
}

fn print_help() {
    println!("{}", BANNER);
    println!("RAVENLOCK v{} · creado por {}", VERSION, AUTHOR);
    println!();
    println!("Uso:");
    println!("  ravenlock init [carpetas...]");
    println!("  ravenlock scan [carpetas...]");
    println!("  ravenlock watch --seconds 60 [carpetas...]");
    println!("  ravenlock tui --seconds 5 [carpetas...]");
    println!("  ravenlock refresh [carpetas...]");
    println!("  ravenlock status");
    println!("  ravenlock config");
    println!();
    println!("Notas:");
    println!("  - No borra archivos.");
    println!("  - No cifra archivos.");
    println!("  - No sube datos.");
    println!("  - Usa baseline local, sello local y archivos canario.");
}

fn cmd_config() -> Result<(), ()> {
    ensure_state_dirs().map_err(|e| fail(&format!("No se pudo crear estado: {}", e)))?;
    if config_file_path().exists() {
        println!("config ya existe: {}", config_file_path().display());
    } else {
        let cfg = Config::default();
        write_config(&cfg).map_err(|e| fail(&format!("No se pudo escribir config: {}", e)))?;
        println!("config creada: {}", config_file_path().display());
    }
    Ok(())
}

fn cmd_init(raw_args: &[String]) -> Result<(), ()> {
    ensure_state_dirs().map_err(|e| fail(&format!("No se pudo crear estado: {}", e)))?;
    let cfg = load_or_create_config();
    let roots = select_roots(raw_args, &cfg);

    println!("{}", BANNER);
    println!("[{}] creando baseline v2", APP);

    let mut entries = Vec::new();
    for root in &roots {
        println!("  -> {}", root.display());
        create_canary(root);
        collect_entries(root, &cfg, &mut entries);
    }

    write_baseline(&entries).map_err(|e| fail(&format!("No se pudo escribir baseline: {}", e)))?;
    write_canaries(&roots).map_err(|e| fail(&format!("No se pudo escribir canaries: {}", e)))?;
    write_seal().map_err(|e| fail(&format!("No se pudo escribir sello: {}", e)))?;

    let mut new_cfg = cfg.clone();
    new_cfg.roots = roots.clone();
    write_config(&new_cfg).map_err(|e| fail(&format!("No se pudo escribir config: {}", e)))?;

    println!();
    println!("baseline creada: {} archivos", entries.len());
    println!("config  : {}", config_file_path().display());
    println!("baseline: {}", baseline_file_path().display());
    println!("seal    : {}", seal_file_path().display());
    println!("RAVENLOCK armado.");
    Ok(())
}

fn cmd_refresh(raw_args: &[String]) -> Result<(), ()> {
    println!("refresh: actualizando baseline tras cambios intencionales");
    cmd_init(raw_args)
}

fn cmd_scan(raw_args: &[String], print_console: bool) -> Result<(), ()> {
    ensure_state_dirs().map_err(|e| fail(&format!("No se pudo crear estado: {}", e)))?;
    let cfg = load_or_create_config();
    let roots = select_roots(raw_args, &cfg);

    let baseline = read_baseline().map_err(|_| {
        fail("No existe baseline. Ejecutá primero: ravenlock init");
    })?;

    let started = Instant::now();
    let mut current = Vec::new();

    if print_console {
        println!("{}", BANNER);
        println!("[{}] escaneo defensivo v2", APP);
    }

    for root in &roots {
        if print_console {
            println!("  -> {}", root.display());
        }
        collect_entries(root, &cfg, &mut current);
    }

    let mut report = compare_and_score(&roots, &baseline, &current);
    report.elapsed_ms = started.elapsed().as_millis();

    if print_console {
        print_report_console(&report);
    }

    write_reports(&report)?;
    Ok(())
}

fn cmd_watch(raw_args: &[String]) -> Result<(), ()> {
    let mut seconds: u64 = 60;
    let mut rest = Vec::new();

    let mut i = 0;
    while i < raw_args.len() {
        if raw_args[i] == "--seconds" && i + 1 < raw_args.len() {
            seconds = raw_args[i + 1].parse::<u64>().unwrap_or(60);
            i += 2;
        } else {
            rest.push(raw_args[i].clone());
            i += 1;
        }
    }

    if seconds < 10 {
        seconds = 10;
    }

    println!("{}", BANNER);
    println!("modo watch");
    println!("intervalo: {} segundos", seconds);
    println!("CTRL+C para salir");

    loop {
        let _ = cmd_scan(&rest, true);
        println!("siguiente escaneo en {} segundos", seconds);
        thread::sleep(Duration::from_secs(seconds));
    }
}

fn cmd_tui(raw_args: &[String]) -> Result<(), ()> {
    let mut seconds: u64 = 5;
    let mut rest = Vec::new();

    let mut i = 0;
    while i < raw_args.len() {
        if raw_args[i] == "--seconds" && i + 1 < raw_args.len() {
            seconds = raw_args[i + 1].parse::<u64>().unwrap_or(5);
            i += 2;
        } else {
            rest.push(raw_args[i].clone());
            i += 1;
        }
    }

    if seconds < 3 {
        seconds = 3;
    }

    ensure_state_dirs().map_err(|e| fail(&format!("No se pudo crear estado: {}", e)))?;
    let cfg = load_or_create_config();
    let roots = select_roots(&rest, &cfg);

    loop {
        clear_screen();

        let started = Instant::now();
        let baseline = match read_baseline() {
            Ok(b) => b,
            Err(_) => {
                println!("{}", BANNER);
                println!("No existe baseline. Ejecutá primero: ravenlock init");
                return Err(());
            }
        };

        let mut current = Vec::new();
        for root in &roots {
            collect_entries(root, &cfg, &mut current);
        }

        let mut report = compare_and_score(&roots, &baseline, &current);
        report.elapsed_ms = started.elapsed().as_millis();

        print_tui(&report);
        let _ = write_reports(&report);

        thread::sleep(Duration::from_secs(seconds));
    }
}

fn cmd_status() -> Result<(), ()> {
    println!("{}", BANNER);
    println!("estado local");
    println!("config   : {}", display_status(&config_file_path()));
    println!("baseline : {}", display_status(&baseline_file_path()));
    println!("seal     : {}", display_status(&seal_file_path()));
    println!("canarios : {}", display_status(&canary_file_path()));
    println!("reportes : {}", display_status(&report_dir_path()));

    let seal_ok = verify_seal().unwrap_or(false);
    println!("seal ok  : {}", if seal_ok { "YES" } else { "NO" });

    if let Ok(entries) = read_baseline() {
        println!("archivos : {}", entries.len());
    }

    let cfg = load_or_create_config();
    println!("interval : {}s", cfg.interval_seconds);
    println!("max mb   : {}", cfg.max_file_mb);
    println!("roots:");
    for r in cfg.roots {
        println!("  - {}", r.display());
    }

    Ok(())
}

impl Default for Config {
    fn default() -> Self {
        Config {
            roots: default_roots(),
            excludes: vec![
                "\\node_modules".to_string(),
                "\\.git".to_string(),
                "\\target".to_string(),
                "\\__pycache__".to_string(),
                "\\AppData\\Local\\Microsoft".to_string(),
            ],
            interval_seconds: 60,
            max_file_mb: 128,
            reports: vec!["html".to_string(), "json".to_string(), "sarif".to_string()],
        }
    }
}

fn load_or_create_config() -> Config {
    ensure_state_dirs().ok();

    if !config_file_path().exists() {
        let cfg = Config::default();
        let _ = write_config(&cfg);
        return cfg;
    }

    match read_config() {
        Ok(c) => c,
        Err(_) => Config::default(),
    }
}

fn read_config() -> Result<Config, ()> {
    let text = fs::read_to_string(config_file_path()).map_err(|_| ())?;
    let mut cfg = Config::default();

    for line in text.lines() {
        let clean = line.trim();
        if clean.is_empty() || clean.starts_with('#') {
            continue;
        }

        if let Some(value) = clean.strip_prefix("interval_seconds") {
            if let Some(v) = value.split('=').nth(1) {
                cfg.interval_seconds = v.trim().parse::<u64>().unwrap_or(cfg.interval_seconds);
            }
        } else if let Some(value) = clean.strip_prefix("max_file_mb") {
            if let Some(v) = value.split('=').nth(1) {
                cfg.max_file_mb = v.trim().parse::<u64>().unwrap_or(cfg.max_file_mb);
            }
        } else if clean.starts_with("root") {
            if let Some(v) = clean.split('=').nth(1) {
                let p = trim_quotes(v.trim());
                if !p.is_empty() {
                    cfg.roots.push(PathBuf::from(p));
                }
            }
        } else if clean.starts_with("exclude") {
            if let Some(v) = clean.split('=').nth(1) {
                let p = trim_quotes(v.trim());
                if !p.is_empty() {
                    cfg.excludes.push(p.to_string());
                }
            }
        }
    }

    cfg.roots.retain(|p| p.exists() && p.is_dir());
    if cfg.roots.is_empty() {
        cfg.roots = default_roots();
    }

    Ok(cfg)
}

fn write_config(cfg: &Config) -> std::io::Result<()> {
    let mut file = File::create(config_file_path())?;
    writeln!(file, "# RAVENLOCK v{} config", VERSION)?;
    writeln!(file, "# creado por {}", AUTHOR)?;
    writeln!(file)?;
    writeln!(file, "interval_seconds = {}", cfg.interval_seconds)?;
    writeln!(file, "max_file_mb = {}", cfg.max_file_mb)?;
    writeln!(file)?;
    for root in &cfg.roots {
        writeln!(file, "root = \"{}\"", root.display())?;
    }
    writeln!(file)?;
    for ex in &cfg.excludes {
        writeln!(file, "exclude = \"{}\"", ex)?;
    }
    Ok(())
}

fn trim_quotes(s: &str) -> &str {
    s.trim().trim_matches('"').trim_matches('\'')
}

fn select_roots(raw_args: &[String], cfg: &Config) -> Vec<PathBuf> {
    let direct: Vec<PathBuf> = raw_args.iter()
        .filter(|x| !x.starts_with("--"))
        .map(PathBuf::from)
        .filter(|p| p.exists() && p.is_dir())
        .collect();

    if direct.is_empty() {
        cfg.roots.clone()
    } else {
        direct
    }
}

fn default_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(home) = home_dir() {
        for name in ["Desktop", "Documents", "Downloads", "Escritorio", "Documentos", "Descargas"] {
            let p = home.join(name);
            if p.exists() && p.is_dir() && !roots.contains(&p) {
                roots.push(p);
            }
        }
    }

    if roots.is_empty() {
        roots.push(env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    }

    roots
}

fn home_dir() -> Option<PathBuf> {
    if let Ok(p) = env::var("USERPROFILE") {
        return Some(PathBuf::from(p));
    }
    if let Ok(p) = env::var("HOME") {
        return Some(PathBuf::from(p));
    }
    None
}

fn ensure_state_dirs() -> std::io::Result<()> {
    fs::create_dir_all(state_dir_path())?;
    fs::create_dir_all(report_dir_path())?;
    Ok(())
}

fn state_dir_path() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(STATE_DIR)
}

fn baseline_file_path() -> PathBuf {
    state_dir_path().join(BASELINE_FILE)
}

fn canary_file_path() -> PathBuf {
    state_dir_path().join(CANARY_FILE)
}

fn config_file_path() -> PathBuf {
    state_dir_path().join(CONFIG_FILE)
}

fn seal_file_path() -> PathBuf {
    state_dir_path().join(SEAL_FILE)
}

fn report_dir_path() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(REPORT_DIR)
}

fn display_status(path: &Path) -> String {
    if path.exists() {
        format!("OK ({})", path.display())
    } else {
        format!("NO EXISTE ({})", path.display())
    }
}

fn should_skip(path: &Path, cfg: &Config) -> bool {
    let lower = path.to_string_lossy().to_lowercase();

    let built_in = [
        "\\windows",
        "\\program files",
        "\\program files (x86)",
        "\\appdata\\local\\packages",
        "\\appdata\\local\\microsoft",
        "\\node_modules",
        "\\.git",
        "\\target",
        "\\__pycache__",
        "/windows",
        "/program files",
        "/node_modules",
        "/.git",
        "/target",
        "/__pycache__",
    ];

    if built_in.iter().any(|x| lower.contains(&x.to_lowercase())) {
        return true;
    }

    for ex in &cfg.excludes {
        if lower.contains(&ex.to_lowercase()) {
            return true;
        }
    }

    false
}

fn collect_entries(root: &Path, cfg: &Config, out: &mut Vec<Entry>) {
    if should_skip(root, cfg) {
        return;
    }

    let read = match fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => return,
    };

    for item in read.flatten() {
        let path = item.path();

        if path.is_dir() {
            collect_entries(&path, cfg, out);
        } else if path.is_file() {
            if let Some(entry) = build_entry(&path, cfg.max_file_mb) {
                out.push(entry);
            }
        }
    }
}

fn build_entry(path: &Path, max_file_mb: u64) -> Option<Entry> {
    let meta = fs::metadata(path).ok()?;
    let modified = meta.modified().ok()
        .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let extension = path.extension()
        .and_then(OsStr::to_str)
        .unwrap_or("")
        .to_lowercase();

    Some(Entry {
        path: normalize_path(path),
        size: meta.len(),
        modified,
        fingerprint: fingerprint_file(path, max_file_mb),
        extension,
    })
}

fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\t', " ")
}

fn fingerprint_file(path: &Path, max_file_mb: u64) -> u64 {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return 0,
    };

    let max_bytes = max_file_mb.saturating_mul(1024).saturating_mul(1024);
    if meta.len() > max_bytes {
        return fast_path_fingerprint(path, meta.len());
    }

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    let mut hash: u64 = 14695981039346656037;
    let prime: u64 = 1099511628211;
    let mut buf = [0u8; 8192];

    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        for b in &buf[..n] {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(prime);
        }
    }

    hash
}

fn fast_path_fingerprint(path: &Path, size: u64) -> u64 {
    let mut hash: u64 = 14695981039346656037;
    let prime: u64 = 1099511628211;
    for b in path.to_string_lossy().bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(prime);
    }
    hash ^= size;
    hash = hash.wrapping_mul(prime);
    hash
}

fn write_baseline(entries: &[Entry]) -> std::io::Result<()> {
    let mut file = File::create(baseline_file_path())?;
    writeln!(file, "# RAVENLOCK baseline v{}", VERSION)?;
    writeln!(file, "# path\tsize\tmodified\tfingerprint\textension")?;
    for e in entries {
        writeln!(file, "{}\t{}\t{}\t{:016x}\t{}", e.path, e.size, e.modified, e.fingerprint, e.extension)?;
    }
    Ok(())
}

fn read_baseline() -> Result<Vec<Entry>, ()> {
    let text = fs::read_to_string(baseline_file_path()).map_err(|_| ())?;
    let mut entries = Vec::new();

    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 {
            continue;
        }

        let extension = if parts.len() >= 5 { parts[4].to_string() } else { String::new() };

        entries.push(Entry {
            path: parts[0].to_string(),
            size: parts[1].parse::<u64>().unwrap_or(0),
            modified: parts[2].parse::<u64>().unwrap_or(0),
            fingerprint: u64::from_str_radix(parts[3], 16).unwrap_or(0),
            extension,
        });
    }

    Ok(entries)
}

fn create_canary(root: &Path) {
    let canary = root.join(CANARY_NAME);
    if canary.exists() {
        return;
    }

    if let Ok(mut f) = File::create(&canary) {
        let _ = writeln!(f, "RAVENLOCK CANARY FILE");
        let _ = writeln!(f, "Created by xtr4ng3");
        let _ = writeln!(f, "Purpose: local defensive integrity monitoring");
        let _ = writeln!(f, "Do not delete unless you are intentionally resetting the baseline.");
        let _ = writeln!(f, "Root: {}", root.display());
        let _ = writeln!(f, "Timestamp: {}", timestamp_file());
    }
}

fn write_canaries(roots: &[PathBuf]) -> std::io::Result<()> {
    let mut file = File::create(canary_file_path())?;
    writeln!(file, "# RAVENLOCK canaries v{}", VERSION)?;
    for root in roots {
        let canary = root.join(CANARY_NAME);
        let fingerprint = if canary.exists() {
            fingerprint_file(&canary, 32)
        } else {
            0
        };
        writeln!(file, "{}\t{:016x}", normalize_path(&canary), fingerprint)?;
    }
    Ok(())
}

fn read_canaries() -> Result<HashMap<String, u64>, ()> {
    let text = fs::read_to_string(canary_file_path()).map_err(|_| ())?;
    let mut map = HashMap::new();

    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            map.insert(parts[0].to_string(), u64::from_str_radix(parts[1], 16).unwrap_or(0));
        }
    }

    Ok(map)
}

fn write_seal() -> std::io::Result<()> {
    let baseline = fs::read_to_string(baseline_file_path()).unwrap_or_default();
    let canaries = fs::read_to_string(canary_file_path()).unwrap_or_default();
    let seal = fnv64_text(&(baseline + &canaries));
    let mut file = File::create(seal_file_path())?;
    writeln!(file, "RAVENLOCK-SEAL-v{}", VERSION)?;
    writeln!(file, "{:016x}", seal)?;
    Ok(())
}

fn verify_seal() -> Result<bool, ()> {
    let seal_text = fs::read_to_string(seal_file_path()).map_err(|_| ())?;
    let expected = seal_text.lines().nth(1).unwrap_or("").trim().to_string();

    let baseline = fs::read_to_string(baseline_file_path()).map_err(|_| ())?;
    let canaries = fs::read_to_string(canary_file_path()).map_err(|_| ())?;
    let actual = format!("{:016x}", fnv64_text(&(baseline + &canaries)));

    Ok(expected == actual)
}

fn fnv64_text(text: &str) -> u64 {
    let mut hash: u64 = 14695981039346656037;
    let prime: u64 = 1099511628211;

    for b in text.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(prime);
    }

    hash
}

fn compare_and_score(roots: &[PathBuf], baseline: &[Entry], current: &[Entry]) -> ScanReport {
    let mut findings = Vec::new();

    let base_map: HashMap<String, &Entry> = baseline.iter().map(|e| (e.path.clone(), e)).collect();
    let cur_map: HashMap<String, &Entry> = current.iter().map(|e| (e.path.clone(), e)).collect();

    let mut added = 0usize;
    let mut modified = 0usize;
    let mut deleted = 0usize;
    let mut suspicious_ext = 0usize;
    let mut canary_alerts = 0usize;

    for (path, current_entry) in &cur_map {
        match base_map.get(path) {
            None => added += 1,
            Some(old) => {
                if old.size != current_entry.size || old.fingerprint != current_entry.fingerprint {
                    modified += 1;
                }
            }
        }

        if suspicious_extension(path) {
            suspicious_ext += 1;
        }
    }

    for path in base_map.keys() {
        if !cur_map.contains_key(path) {
            deleted += 1;
        }
    }

    let seal_valid = verify_seal().unwrap_or(false);
    if !seal_valid {
        add_finding(
            &mut findings,
            "high",
            "baseline",
            "Baseline seal mismatch",
            "The local baseline seal does not match current baseline/canary metadata.",
            "Review .ravenlock contents. Refresh baseline only after verifying expected changes.",
        );
    }

    if let Ok(canaries) = read_canaries() {
        for (canary, old_fp) in canaries {
            match cur_map.get(&canary) {
                None => {
                    canary_alerts += 1;
                    add_finding(
                        &mut findings,
                        "critical",
                        "canary",
                        "Canary file missing",
                        &format!("Canary disappeared: {}", canary),
                        "Stop activity and inspect recent file operations in this directory.",
                    );
                }
                Some(e) => {
                    if e.fingerprint != old_fp {
                        canary_alerts += 1;
                        add_finding(
                            &mut findings,
                            "critical",
                            "canary",
                            "Canary file modified",
                            &format!("Canary changed: {}", canary),
                            "Treat this as a high-priority local integrity alert.",
                        );
                    }
                }
            }
        }
    }

    if deleted > 20 {
        add_finding(
            &mut findings,
            "high",
            "deletion",
            "Large deletion wave",
            &format!("{} baseline files are missing.", deleted),
            "Review recent activity, backups, sync clients and suspicious processes.",
        );
    }

    if modified > 50 {
        add_finding(
            &mut findings,
            "high",
            "modification",
            "Large modification wave",
            &format!("{} files changed since baseline.", modified),
            "Investigate for mass editing, encryption, sync corruption or unwanted automation.",
        );
    }

    if suspicious_ext > 0 {
        add_finding(
            &mut findings,
            if suspicious_ext > 10 { "high" } else { "medium" },
            "extension",
            "Suspicious extension pattern",
            &format!("{} files with extensions commonly seen in encryption or destructive events.", suspicious_ext),
            "Review filenames and creation times. Restore from trusted backup if needed.",
        );
    }

    if added > 100 {
        add_finding(
            &mut findings,
            "medium",
            "creation",
            "Large file creation wave",
            &format!("{} new files detected.", added),
            "Correlate with expected downloads, installers, sync tools or build systems.",
        );
    }

    let mut score = 0u32;
    score += (canary_alerts as u32).saturating_mul(45);
    if !seal_valid {
        score += 30;
    }
    score += ((deleted / 10) as u32).saturating_mul(6);
    score += ((modified / 20) as u32).saturating_mul(8);
    score += (suspicious_ext as u32).saturating_mul(5);
    score += ((added / 50) as u32).saturating_mul(4);
    if score > 100 {
        score = 100;
    }

    if findings.is_empty() {
        add_finding(
            &mut findings,
            "info",
            "baseline",
            "No high-risk drift detected",
            "Current scan did not exceed local alert thresholds.",
            "Keep baseline updated after intentional changes.",
        );
    }

    let verdict = if score >= 80 {
        "critical"
    } else if score >= 55 {
        "high"
    } else if score >= 30 {
        "medium"
    } else if score > 0 {
        "low"
    } else {
        "clean"
    }.to_string();

    ScanReport {
        roots: roots.to_vec(),
        total_files: current.len(),
        added,
        modified,
        deleted,
        suspicious_extensions: suspicious_ext,
        canary_alerts,
        seal_valid,
        score,
        verdict,
        findings,
        generated_at: timestamp_human(),
        elapsed_ms: 0,
    }
}

fn suspicious_extension(path: &str) -> bool {
    let lower = path.to_lowercase();
    let ext = Path::new(&lower).extension().and_then(OsStr::to_str).unwrap_or("");

    let suspicious = [
        "locked", "encrypted", "crypt", "crypto", "enc", "pay", "payme",
        "restore", "black", "lockbit", "deadbolt", "ransom", "ryk", "ryuk",
        "wncry", "wannacry", "cerber", "conti", "revil"
    ];

    suspicious.iter().any(|x| ext == *x || lower.ends_with(&format!(".{}", x)))
}

fn add_finding(
    findings: &mut Vec<Finding>,
    severity: &str,
    category: &str,
    title: &str,
    detail: &str,
    recommendation: &str,
) {
    findings.push(Finding {
        severity: severity.to_string(),
        category: category.to_string(),
        title: title.to_string(),
        detail: detail.to_string(),
        recommendation: recommendation.to_string(),
    });
}

fn print_report_console(report: &ScanReport) {
    println!();
    println!("================ RAVENLOCK v2 REPORT ================");
    println!("generated : {}", report.generated_at);
    println!("verdict   : {}", report.verdict.to_uppercase());
    println!("score     : {}/100", report.score);
    println!("seal ok   : {}", if report.seal_valid { "YES" } else { "NO" });
    println!("files     : {}", report.total_files);
    println!("added     : {}", report.added);
    println!("modified  : {}", report.modified);
    println!("deleted   : {}", report.deleted);
    println!("susp ext  : {}", report.suspicious_extensions);
    println!("canaries  : {}", report.canary_alerts);
    println!("elapsed   : {}ms", report.elapsed_ms);
    println!("------------------------------------------------------");
    for f in &report.findings {
        println!("[{}] {} :: {}", f.severity.to_uppercase(), f.category, f.title);
        println!("  {}", f.detail);
        println!("  -> {}", f.recommendation);
    }
    println!("======================================================");
}

fn print_tui(report: &ScanReport) {
    println!("{}", BANNER);
    println!("┌──────────────────────────────────────────────────────────────────────────────┐");
    println!("│ RAVENLOCK v{}  |  LOCAL INTEGRITY SENTINEL  |  xtr4ng3              │", VERSION);
    println!("├──────────────────────────────────────────────────────────────────────────────┤");
    println!("│ VERDICT: {:<10} SCORE: {:>3}/100   SEAL: {:<3}   ELAPSED: {:>6}ms        │",
        report.verdict.to_uppercase(),
        report.score,
        if report.seal_valid { "OK" } else { "BAD" },
        report.elapsed_ms
    );
    println!("├───────────────────────────────┬──────────────────────────────────────────────┤");
    println!("│ METRICS                       │ ROOTS                                        │");
    println!("│ total files : {:<14} │ {:<44} │", report.total_files, root_line(report, 0));
    println!("│ added       : {:<14} │ {:<44} │", report.added, root_line(report, 1));
    println!("│ modified    : {:<14} │ {:<44} │", report.modified, root_line(report, 2));
    println!("│ deleted     : {:<14} │ {:<44} │", report.deleted, root_line(report, 3));
    println!("│ susp ext    : {:<14} │ {:<44} │", report.suspicious_extensions, root_line(report, 4));
    println!("│ canaries    : {:<14} │ {:<44} │", report.canary_alerts, root_line(report, 5));
    println!("├───────────────────────────────┴──────────────────────────────────────────────┤");
    println!("│ FINDINGS                                                                     │");
    for i in 0..6 {
        if let Some(f) = report.findings.get(i) {
            println!("│ [{:<8}] {:<16} {:<49} │",
                f.severity.to_uppercase(),
                truncate(&f.category, 16),
                truncate(&f.title, 49)
            );
        } else {
            println!("│                                                                              │");
        }
    }
    println!("├──────────────────────────────────────────────────────────────────────────────┤");
    println!("│ REPORTS: HTML / JSON / SARIF   |   MODE: LIVE TUI   |   CTRL+C TO EXIT       │");
    println!("└──────────────────────────────────────────────────────────────────────────────┘");
}

fn root_line(report: &ScanReport, index: usize) -> String {
    report.roots.get(index)
        .map(|p| truncate(&p.display().to_string(), 44))
        .unwrap_or_default()
}

fn truncate(input: &str, len: usize) -> String {
    if input.chars().count() <= len {
        return input.to_string();
    }

    let mut out = String::new();
    for c in input.chars().take(len.saturating_sub(3)) {
        out.push(c);
    }
    out.push_str("...");
    out
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
    let _ = std::io::stdout().flush();
}

fn write_reports(report: &ScanReport) -> Result<(), ()> {
    fs::create_dir_all(report_dir_path()).map_err(|e| fail(&format!("No se pudo crear reports: {}", e)))?;

    let report_base = format!("ravenlock_v2_report_{}", timestamp_file());
    let json_path = report_dir_path().join(format!("{}.json", report_base));
    let html_path = report_dir_path().join(format!("{}.html", report_base));
    let sarif_path = report_dir_path().join(format!("{}.sarif", report_base));

    write_json_report(report, &json_path).map_err(|e| fail(&format!("No se pudo escribir JSON: {}", e)))?;
    write_html_report(report, &html_path).map_err(|e| fail(&format!("No se pudo escribir HTML: {}", e)))?;
    write_sarif_report(report, &sarif_path).map_err(|e| fail(&format!("No se pudo escribir SARIF: {}", e)))?;

    Ok(())
}

fn write_json_report(report: &ScanReport, path: &Path) -> std::io::Result<()> {
    let mut file = File::create(path)?;

    writeln!(file, "{{")?;
    writeln!(file, "  \"tool\": \"RAVENLOCK\",")?;
    writeln!(file, "  \"version\": \"{}\",", VERSION)?;
    writeln!(file, "  \"author\": \"{}\",", AUTHOR)?;
    writeln!(file, "  \"generated_at\": \"{}\",", json_escape(&report.generated_at))?;
    writeln!(file, "  \"score\": {},", report.score)?;
    writeln!(file, "  \"verdict\": \"{}\",", json_escape(&report.verdict))?;
    writeln!(file, "  \"seal_valid\": {},", if report.seal_valid { "true" } else { "false" })?;
    writeln!(file, "  \"total_files\": {},", report.total_files)?;
    writeln!(file, "  \"added\": {},", report.added)?;
    writeln!(file, "  \"modified\": {},", report.modified)?;
    writeln!(file, "  \"deleted\": {},", report.deleted)?;
    writeln!(file, "  \"suspicious_extensions\": {},", report.suspicious_extensions)?;
    writeln!(file, "  \"canary_alerts\": {},", report.canary_alerts)?;
    writeln!(file, "  \"elapsed_ms\": {},", report.elapsed_ms)?;
    writeln!(file, "  \"roots\": [")?;
    for (i, r) in report.roots.iter().enumerate() {
        let comma = if i + 1 == report.roots.len() { "" } else { "," };
        writeln!(file, "    \"{}\"{}", json_escape(&r.display().to_string()), comma)?;
    }
    writeln!(file, "  ],")?;
    writeln!(file, "  \"findings\": [")?;
    for (i, f) in report.findings.iter().enumerate() {
        let comma = if i + 1 == report.findings.len() { "" } else { "," };
        writeln!(file, "    {{")?;
        writeln!(file, "      \"severity\": \"{}\",", json_escape(&f.severity))?;
        writeln!(file, "      \"category\": \"{}\",", json_escape(&f.category))?;
        writeln!(file, "      \"title\": \"{}\",", json_escape(&f.title))?;
        writeln!(file, "      \"detail\": \"{}\",", json_escape(&f.detail))?;
        writeln!(file, "      \"recommendation\": \"{}\"", json_escape(&f.recommendation))?;
        writeln!(file, "    }}{}", comma)?;
    }
    writeln!(file, "  ]")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_html_report(report: &ScanReport, path: &Path) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    let risk_color = match report.verdict.as_str() {
        "critical" => "#ff304f",
        "high" => "#ff5a36",
        "medium" => "#ffd166",
        "low" => "#7ef9ff",
        _ => "#8dff8d",
    };

    writeln!(file, "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\"><title>RAVENLOCK v2</title>")?;
    writeln!(file, "<style>body{{background:#05070b;color:#e8f6ff;font-family:Consolas,Segoe UI,Arial;padding:30px}}h1,h2{{color:#ff304f}}.card{{background:#0b1018;border:1px solid #2c3444;border-radius:14px;padding:18px;margin:16px 0}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #202838;padding:9px;text-align:left}}th{{color:#7ef9ff}}.score{{font-size:48px;color:{};font-weight:800}}.small{{color:#9fb1c7}}code{{color:#d6f7ff}}</style>", risk_color)?;
    writeln!(file, "</head><body>")?;
    writeln!(file, "<h1>RAVENLOCK v2</h1><p class=\"small\">Local Integrity Sentinel · xtr4ng3 · {}</p>", html_escape(&report.generated_at))?;
    writeln!(file, "<div class=\"card\"><h2>Verdict</h2><div class=\"score\">{} / 100</div><p><b>{}</b></p><p>Baseline seal: <b>{}</b></p></div>",
        report.score,
        html_escape(&report.verdict.to_uppercase()),
        if report.seal_valid { "OK" } else { "BAD" }
    )?;
    writeln!(file, "<div class=\"card\"><h2>Summary</h2><table><tr><th>Metric</th><th>Value</th></tr>")?;
    writeln!(file, "<tr><td>Total files</td><td>{}</td></tr>", report.total_files)?;
    writeln!(file, "<tr><td>Added</td><td>{}</td></tr>", report.added)?;
    writeln!(file, "<tr><td>Modified</td><td>{}</td></tr>", report.modified)?;
    writeln!(file, "<tr><td>Deleted</td><td>{}</td></tr>", report.deleted)?;
    writeln!(file, "<tr><td>Suspicious extensions</td><td>{}</td></tr>", report.suspicious_extensions)?;
    writeln!(file, "<tr><td>Canary alerts</td><td>{}</td></tr>", report.canary_alerts)?;
    writeln!(file, "<tr><td>Elapsed</td><td>{}ms</td></tr>", report.elapsed_ms)?;
    writeln!(file, "</table></div>")?;
    writeln!(file, "<div class=\"card\"><h2>Protected roots</h2><ul>")?;
    for r in &report.roots {
        writeln!(file, "<li><code>{}</code></li>", html_escape(&r.display().to_string()))?;
    }
    writeln!(file, "</ul></div>")?;
    writeln!(file, "<div class=\"card\"><h2>Findings</h2><table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Recommendation</th></tr>")?;
    for f in &report.findings {
        writeln!(
            file,
            "<tr><td>{}</td><td>{}</td><td><b>{}</b><br>{}</td><td>{}</td></tr>",
            html_escape(&f.severity),
            html_escape(&f.category),
            html_escape(&f.title),
            html_escape(&f.detail),
            html_escape(&f.recommendation)
        )?;
    }
    writeln!(file, "</table></div><p class=\"small\">RAVENLOCK no borra, no cifra y no envía datos.</p></body></html>")?;
    Ok(())
}

fn write_sarif_report(report: &ScanReport, path: &Path) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "{{")?;
    writeln!(file, "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",")?;
    writeln!(file, "  \"version\": \"2.1.0\",")?;
    writeln!(file, "  \"runs\": [{{")?;
    writeln!(file, "    \"tool\": {{\"driver\": {{\"name\": \"RAVENLOCK\", \"version\": \"{}\", \"informationUri\": \"https://github.com/\"}}}},", VERSION)?;
    writeln!(file, "    \"results\": [")?;
    for (i, f) in report.findings.iter().enumerate() {
        let comma = if i + 1 == report.findings.len() { "" } else { "," };
        let level = match f.severity.as_str() {
            "critical" | "high" => "error",
            "medium" => "warning",
            _ => "note",
        };
        writeln!(file, "      {{")?;
        writeln!(file, "        \"ruleId\": \"{}\",", json_escape(&f.category))?;
        writeln!(file, "        \"level\": \"{}\",", level)?;
        writeln!(file, "        \"message\": {{\"text\": \"{} - {}\"}}", json_escape(&f.title), json_escape(&f.detail))?;
        writeln!(file, "      }}{}", comma)?;
    }
    writeln!(file, "    ]")?;
    writeln!(file, "  }}]")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn timestamp_file() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
        .to_string()
}

fn timestamp_human() -> String {
    format!("unix:{}", timestamp_file())
}

fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn fail(message: &str) {
    eprintln!("[ERROR] {}", message);
}
