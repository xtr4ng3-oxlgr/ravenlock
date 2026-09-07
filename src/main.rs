use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const APP: &str = "RAVENLOCK";
const VERSION: &str = "1.0.0";
const AUTHOR: &str = "xtr4ng3";
const STATE_DIR: &str = ".ravenlock";
const STATE_FILE: &str = "baseline.tsv";
const CANARY_FILE: &str = "canaries.tsv";
const REPORT_DIR: &str = "reports";
const CANARY_NAME: &str = ".ravenlock_canary_xtr4ng3.txt";

const BANNER: &str = r#"
 ██▀███   ▄▄▄    ██▒   █▓▓█████  ███▄    █  ██▓     ▒█████   ▄████▄   ██ ▄█▀
▓██ ▒ ██▒▒████▄ ▓██░   █▒▓█   ▀  ██ ▀█   █ ▓██▒    ▒██▒  ██▒▒██▀ ▀█   ██▄█▒
▓██ ░▄█ ▒▒██  ▀█▄▓██  █▒░▒███   ▓██  ▀█ ██▒▒██░    ▒██░  ██▒▒▓█    ▄ ▓███▄░
▒██▀▀█▄  ░██▄▄▄▄██▒██ █░░▒▓█  ▄ ▓██▒  ▐▌██▒▒██░    ▒██   ██░▒▓▓▄ ▄██▒▓██ █▄
░██▓ ▒██▒ ▓█   ▓██▒▒▀█░  ░▒████▒▒██░   ▓██░░██████▒░ ████▓▒░▒ ▓███▀ ░▒██▒ █▄
░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ▐░  ░░ ▒░ ░░ ▒░   ▒ ▒ ░ ▒░▓  ░░ ▒░▒░▒░ ░ ░▒ ▒  ░▒ ▒▒ ▓▒
  ░▒ ░ ▒░  ▒   ▒▒ ░░ ░░   ░ ░  ░░ ░░   ░ ▒░░ ░ ▒  ░  ░ ▒ ▒░   ░  ▒   ░ ░▒ ▒░
  ░░   ░   ░   ▒     ░░     ░      ░   ░ ░   ░ ░   ░ ░ ░ ▒  ░        ░ ░░ ░
   ░           ░  ░   ░     ░  ░         ░     ░  ░    ░ ░  ░ ░      ░  ░
 ::  CANARY BASELINE DEFENSE :: BY.XTR4NG3
"#;

#[derive(Clone, Debug)]
struct Entry {
    path: String,
    size: u64,
    modified: u64,
    fingerprint: u64,
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
    score: u32,
    verdict: String,
    findings: Vec<Finding>,
    generated_at: String,
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
        "scan" => cmd_scan(&args[2..]),
        "watch" => cmd_watch(&args[2..]),
        "status" => cmd_status(),
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
    println!("  ravenlock status");
    println!();
    println!("Ejemplos:");
    println!("  ravenlock init");
    println!("  ravenlock scan");
    println!("  ravenlock init C:\\Users\\User\\Documents C:\\Users\\User\\Desktop");
    println!("  ravenlock watch --seconds 30 C:\\Users\\User\\Documents");
    println!();
    println!("Notas:");
    println!("  - No borra archivos.");
    println!("  - No cifra archivos.");
    println!("  - No sube datos a internet.");
    println!("  - Usa línea base local y archivos canario.");
}

fn cmd_init(raw_args: &[String]) -> Result<(), ()> {
    let roots = parse_roots(raw_args);
    if roots.is_empty() {
        fail("No se encontró ninguna carpeta válida para proteger. Verificá las rutas indicadas.");
        return Err(());
    }
    ensure_state_dirs().map_err(|e| fail(&format!("No se pudo crear estado local: {}", e)))?;

    println!("{}", BANNER);
    println!("[{}] creando línea base local", APP);
    println!("raices: {}", roots.len());

    let mut entries: Vec<Entry> = Vec::new();
    for root in &roots {
        println!("  -> {}", root.display());
        create_canary(root);
        collect_entries(root, &mut entries);
    }

    write_baseline(&entries).map_err(|e| fail(&format!("No se pudo escribir baseline: {}", e)))?;
    write_canaries(&roots).map_err(|e| fail(&format!("No se pudo escribir canaries: {}", e)))?;

    println!();
    println!("baseline creada: {} archivos", entries.len());
    println!("estado local: {}", state_file_path().display());
    println!("canarios: {}", canary_file_path().display());
    println!("RAVENLOCK armado.");
    Ok(())
}

fn cmd_scan(raw_args: &[String]) -> Result<(), ()> {
    ensure_state_dirs().map_err(|e| fail(&format!("No se pudo crear estado local: {}", e)))?;

    let roots = if raw_args.is_empty() {
        read_canary_roots().unwrap_or_else(|_| default_roots())
    } else {
        parse_roots(raw_args)
    };

    if roots.is_empty() {
        fail("No se encontró ninguna carpeta válida para escanear. Verificá las rutas indicadas.");
        return Err(());
    }

    let baseline = read_baseline().map_err(|_| {
        fail("No existe baseline. Ejecutá primero: ravenlock init");
    })?;

    println!("{}", BANNER);
    println!("[{}] escaneo defensivo iniciado", APP);

    let mut current_entries: Vec<Entry> = Vec::new();
    for root in &roots {
        println!("  -> {}", root.display());
        collect_entries(root, &mut current_entries);
    }

    let report = compare_and_score(&roots, &baseline, &current_entries);
    print_report_console(&report);

    let report_base = format!("ravenlock_report_{}", timestamp_file());
    let json_path = report_dir_path().join(format!("{}.json", report_base));
    let html_path = report_dir_path().join(format!("{}.html", report_base));

    write_json_report(&report, &json_path).map_err(|e| fail(&format!("No se pudo escribir JSON: {}", e)))?;
    write_html_report(&report, &html_path).map_err(|e| fail(&format!("No se pudo escribir HTML: {}", e)))?;

    println!();
    println!("reporte JSON: {}", json_path.display());
    println!("reporte HTML: {}", html_path.display());
    Ok(())
}

fn cmd_watch(raw_args: &[String]) -> Result<(), ()> {
    let mut seconds: u64 = 60;
    let mut rest: Vec<String> = Vec::new();
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
    println!("modo vigilancia local");
    println!("intervalo: {} segundos", seconds);
    println!("presioná CTRL+C para salir");
    println!();

    loop {
        let _ = cmd_scan(&rest);
        println!();
        println!("siguiente escaneo en {} segundos", seconds);
        thread::sleep(Duration::from_secs(seconds));
    }
}

fn cmd_status() -> Result<(), ()> {
    println!("{}", BANNER);
    println!("estado local");

    let state = state_file_path();
    let canaries = canary_file_path();
    let reports = report_dir_path();

    println!("baseline : {}", display_status(&state));
    println!("canarios : {}", display_status(&canaries));
    println!("reportes : {}", display_status(&reports));

    if let Ok(entries) = read_baseline() {
        println!("archivos en baseline: {}", entries.len());
    }

    if let Ok(roots) = read_canary_roots() {
        println!("raíces protegidas:");
        for r in roots {
            println!("  - {}", r.display());
        }
    }

    Ok(())
}

fn fail(message: &str) {
    eprintln!("[ERROR] {}", message);
}

fn display_status(path: &Path) -> String {
    if path.exists() {
        format!("OK ({})", path.display())
    } else {
        format!("NO EXISTE ({})", path.display())
    }
}

fn parse_roots(args: &[String]) -> Vec<PathBuf> {
    if args.is_empty() {
        return default_roots();
    }

    let mut roots = Vec::new();
    for a in args {
        if a.starts_with("--") {
            continue;
        }
        let p = PathBuf::from(a);
        if p.exists() && p.is_dir() {
            roots.push(p);
        } else {
            eprintln!("[ADVERTENCIA] Ruta ignorada (no existe o no es una carpeta): {}", a);
        }
    }
    roots
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

fn state_file_path() -> PathBuf {
    state_dir_path().join(STATE_FILE)
}

fn canary_file_path() -> PathBuf {
    state_dir_path().join(CANARY_FILE)
}

fn report_dir_path() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(REPORT_DIR)
}

fn should_skip_dir(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_lowercase();

    let blocked = [
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

    blocked.iter().any(|b| lower.contains(b))
}

fn collect_entries(root: &Path, out: &mut Vec<Entry>) {
    if should_skip_dir(root) {
        return;
    }

    let read = match fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => return,
    };

    for item in read.flatten() {
        let path = item.path();

        if path.is_dir() {
            collect_entries(&path, out);
        } else if path.is_file() {
            if let Some(entry) = build_entry(&path) {
                out.push(entry);
            }
        }
    }
}

fn build_entry(path: &Path) -> Option<Entry> {
    let meta = fs::metadata(path).ok()?;
    let modified = meta.modified().ok()
        .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Some(Entry {
        path: normalize_path(path),
        size: meta.len(),
        modified,
        fingerprint: fingerprint_file(path),
    })
}

fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\t', " ")
}

fn fingerprint_file(path: &Path) -> u64 {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    let mut hash: u64 = 14695981039346656037;
    let prime: u64 = 1099511628211;

    let mut buf = [0u8; 8192];

    // Hashes the entire file content, not a size-limited prefix: a
    // fixed-size cap here would let an in-place change past that offset
    // (e.g. content encrypted or altered without changing file size)
    // go completely undetected, which defeats the point of an integrity
    // baseline built specifically to catch that kind of drift.
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

fn write_baseline(entries: &[Entry]) -> std::io::Result<()> {
    let mut file = File::create(state_file_path())?;
    writeln!(file, "# RAVENLOCK baseline v{}", VERSION)?;
    writeln!(file, "# path\tsize\tmodified\tfingerprint")?;
    for e in entries {
        writeln!(file, "{}\t{}\t{}\t{:016x}", e.path, e.size, e.modified, e.fingerprint)?;
    }
    Ok(())
}

fn read_baseline() -> Result<Vec<Entry>, ()> {
    let text = fs::read_to_string(state_file_path()).map_err(|_| ())?;
    let mut entries = Vec::new();

    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 4 {
            continue;
        }

        let size = parts[1].parse::<u64>().unwrap_or(0);
        let modified = parts[2].parse::<u64>().unwrap_or(0);
        let fingerprint = u64::from_str_radix(parts[3], 16).unwrap_or(0);

        entries.push(Entry {
            path: parts[0].to_string(),
            size,
            modified,
            fingerprint,
        });
    }

    Ok(entries)
}

fn write_canaries(roots: &[PathBuf]) -> std::io::Result<()> {
    let mut file = File::create(canary_file_path())?;
    writeln!(file, "# RAVENLOCK canaries v{}", VERSION)?;
    for root in roots {
        let canary = root.join(CANARY_NAME);
        let token = format!("RAVENLOCK_CANARY::{}::{}::{}", AUTHOR, timestamp_file(), root.display());
        let fingerprint = fingerprint_file(&canary);
        writeln!(file, "{}\t{}\t{:016x}", normalize_path(&canary), token, fingerprint)?;
    }
    Ok(())
}

fn read_canary_roots() -> Result<Vec<PathBuf>, ()> {
    let text = fs::read_to_string(canary_file_path()).map_err(|_| ())?;
    let mut roots = HashSet::new();

    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.is_empty() {
            continue;
        }

        let p = PathBuf::from(parts[0]);
        if let Some(parent) = p.parent() {
            roots.insert(parent.to_path_buf());
        }
    }

    Ok(roots.into_iter().collect())
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

fn compare_and_score(roots: &[PathBuf], baseline: &[Entry], current: &[Entry]) -> ScanReport {
    let mut findings: Vec<Finding> = Vec::new();

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

    for root in roots {
        let canary = normalize_path(&root.join(CANARY_NAME));
        match cur_map.get(&canary) {
            None => {
                canary_alerts += 1;
                add_finding(
                    &mut findings,
                    "critical",
                    "canary",
                    "Canary file missing",
                    &format!("Canary disappeared: {}", canary),
                    "Stop execution activity and inspect recent file operations in this directory.",
                );
            }
            Some(e) => {
                if let Some(old) = base_map.get(&canary) {
                    if old.fingerprint != e.fingerprint || old.size != e.size {
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

    if deleted > 0 {
        let (severity, title) = if deleted > 20 {
            ("high", "Large deletion wave")
        } else {
            ("medium", "Files deleted")
        };
        add_finding(
            &mut findings,
            severity,
            "deletion",
            title,
            &format!("{} baseline file(s) are missing.", deleted),
            "Review recent activity, backups, sync clients and suspicious processes.",
        );
    }

    if modified > 0 {
        let (severity, title) = if modified > 50 {
            ("high", "Large modification wave")
        } else if modified > 5 {
            ("medium", "Files modified")
        } else {
            ("low", "Files modified")
        };
        add_finding(
            &mut findings,
            severity,
            "modification",
            title,
            &format!("{} file(s) changed since baseline.", modified),
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

    // Per-unit contributions so a small, real change (the common case on a
    // personal folder) still moves the score and verdict away from
    // "clean" -- the previous formula only counted modifications/deletions
    // in batches of 20/10, so anything below that floor scored 0 and the
    // report claimed "no high-risk drift" even when a file had, in fact,
    // changed. Wave bonuses are kept on top for mass-change events, which
    // are more suspicious than the same count spread out incidentally.
    let mut score = 0u32;
    score += (canary_alerts as u32).saturating_mul(45);
    score += (deleted as u32).saturating_mul(2);
    score += (modified as u32).saturating_mul(2);
    score += (suspicious_ext as u32).saturating_mul(5);
    score += (added as u32).saturating_mul(1);
    if deleted > 20 {
        score = score.saturating_add(15);
    }
    if modified > 50 {
        score = score.saturating_add(15);
    }
    if added > 100 {
        score = score.saturating_add(10);
    }
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
        score,
        verdict,
        findings,
        generated_at: timestamp_human(),
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
    println!("================ RAVENLOCK REPORT ================");
    println!("generated : {}", report.generated_at);
    println!("verdict   : {}", report.verdict.to_uppercase());
    println!("score     : {}/100", report.score);
    println!("files     : {}", report.total_files);
    println!("added     : {}", report.added);
    println!("modified  : {}", report.modified);
    println!("deleted   : {}", report.deleted);
    println!("susp ext  : {}", report.suspicious_extensions);
    println!("canaries  : {}", report.canary_alerts);
    println!("--------------------------------------------------");
    for f in &report.findings {
        println!("[{}] {} :: {}", f.severity.to_uppercase(), f.category, f.title);
        println!("  {}", f.detail);
        println!("  -> {}", f.recommendation);
    }
    println!("==================================================");
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
    writeln!(file, "  \"total_files\": {},", report.total_files)?;
    writeln!(file, "  \"added\": {},", report.added)?;
    writeln!(file, "  \"modified\": {},", report.modified)?;
    writeln!(file, "  \"deleted\": {},", report.deleted)?;
    writeln!(file, "  \"suspicious_extensions\": {},", report.suspicious_extensions)?;
    writeln!(file, "  \"canary_alerts\": {},", report.canary_alerts)?;
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

    let risk_class = match report.verdict.as_str() {
        "critical" => "#e0304f",
        "high" => "#e0663a",
        "medium" => "#d9a441",
        "low" => "#5fb3c9",
        _ => "#6fd196",
    };

    writeln!(file, "<!doctype html>")?;
    writeln!(file, "<html lang=\"es\"><head><meta charset=\"utf-8\"><title>RAVENLOCK Report</title>")?;
    writeln!(file, "<style>")?;
    writeln!(file, "body{{background:#0a0d10;color:#dce4e8;font-family:'Segoe UI',Consolas,Arial;padding:30px}}")?;
    writeln!(file, "h1,h2{{color:#5fb3c9;letter-spacing:0.5px}} .card{{background:#12171b;border:1px solid #263038;border-left:3px solid #3d5560;border-radius:4px;padding:18px;margin:16px 0}}")?;
    writeln!(file, "table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #232d34;padding:9px;text-align:left}}th{{color:#8fb8c4}}")?;
    writeln!(file, ".score{{font-size:48px;color:{};font-weight:800}} .small{{color:#7d919a}} code{{color:#a9c6cf}}", risk_class)?;
    writeln!(file, "</style></head><body>")?;

    writeln!(file, "<h1>RAVENLOCK</h1>")?;
    writeln!(file, "<p class=\"small\">Local Integrity Sentinel · xtr4ng3 · {}</p>", html_escape(&report.generated_at))?;

    writeln!(file, "<div class=\"card\"><h2>Verdict</h2>")?;
    writeln!(file, "<div class=\"score\">{} / 100</div>", report.score)?;
    writeln!(file, "<p><b>{}</b></p>", html_escape(&report.verdict.to_uppercase()))?;
    writeln!(file, "</div>")?;

    writeln!(file, "<div class=\"card\"><h2>Summary</h2><table>")?;
    writeln!(file, "<tr><th>Metric</th><th>Value</th></tr>")?;
    writeln!(file, "<tr><td>Total files</td><td>{}</td></tr>", report.total_files)?;
    writeln!(file, "<tr><td>Added</td><td>{}</td></tr>", report.added)?;
    writeln!(file, "<tr><td>Modified</td><td>{}</td></tr>", report.modified)?;
    writeln!(file, "<tr><td>Deleted</td><td>{}</td></tr>", report.deleted)?;
    writeln!(file, "<tr><td>Suspicious extensions</td><td>{}</td></tr>", report.suspicious_extensions)?;
    writeln!(file, "<tr><td>Canary alerts</td><td>{}</td></tr>", report.canary_alerts)?;
    writeln!(file, "</table></div>")?;

    writeln!(file, "<div class=\"card\"><h2>Protected roots</h2><ul>")?;
    for r in &report.roots {
        writeln!(file, "<li><code>{}</code></li>", html_escape(&r.display().to_string()))?;
    }
    writeln!(file, "</ul></div>")?;

    writeln!(file, "<div class=\"card\"><h2>Findings</h2><table>")?;
    writeln!(file, "<tr><th>Severity</th><th>Category</th><th>Finding</th><th>Recommendation</th></tr>")?;
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
    writeln!(file, "</table></div>")?;

    writeln!(file, "<p class=\"small\">RAVENLOCK no borra, no cifra y no envía datos. El reporte se interpreta con contexto local.</p>")?;
    writeln!(file, "</body></html>")?;
    Ok(())
}

fn timestamp_file() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    secs.to_string()
}

fn timestamp_human() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    format!("unix:{}", secs)
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
