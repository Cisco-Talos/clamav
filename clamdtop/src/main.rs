// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only

use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use ratatui::{Frame, Terminal};

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const RECONNECT_DELAY: Duration = Duration::from_secs(3);
const MAX_PROTOCOL_LINE_BYTES: usize = 16 * 1024;
const MAX_STATS_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_STATS_RESPONSE_LINES: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Endpoint {
    Tcp {
        host: String,
        port: u16,
    },
    #[cfg(unix)]
    Unix(PathBuf),
}

impl Endpoint {
    fn label(&self) -> String {
        let label = match self {
            Self::Tcp { host, port } if host.contains(':') => format!("[{host}]:{port}"),
            Self::Tcp { host, port } => format!("{host}:{port}"),
            #[cfg(unix)]
            Self::Unix(_) => "local".to_string(),
        };
        sanitize_terminal_text(&label)
    }
}

#[derive(Clone, Debug, Default)]
struct MemoryStats {
    heap_mb: Option<f64>,
    mmap_mb: Option<f64>,
    used_mb: Option<f64>,
    free_mb: Option<f64>,
    releasable_mb: Option<f64>,
    pools: Option<u32>,
    pools_used_mb: Option<f64>,
    pools_total_mb: Option<f64>,
}

#[derive(Clone, Debug)]
struct Task {
    command: String,
    elapsed: f64,
    file: String,
}

#[derive(Clone, Debug)]
struct DaemonStats {
    endpoint: String,
    status: String,
    version_response: String,
    engine_version: String,
    database_version: String,
    database_time: String,
    connected_at: Option<Instant>,
    primary_live: u32,
    primary_idle: u32,
    primary_max: u32,
    live: u32,
    idle: u32,
    max_threads: u32,
    queue: u32,
    max_queue: u32,
    memory: MemoryStats,
    memory_peak_mb: f64,
    tasks: Vec<Task>,
}

impl DaemonStats {
    fn new(endpoint: &Endpoint) -> Self {
        Self {
            endpoint: endpoint.label(),
            status: "Connecting".to_string(),
            version_response: "Unknown".to_string(),
            engine_version: "—".to_string(),
            database_version: "—".to_string(),
            database_time: "—".to_string(),
            connected_at: None,
            primary_live: 0,
            primary_idle: 0,
            primary_max: 0,
            live: 0,
            idle: 0,
            max_threads: 0,
            queue: 0,
            max_queue: 0,
            memory: MemoryStats::default(),
            memory_peak_mb: 0.0,
            tasks: Vec::new(),
        }
    }

    fn clear_connection_data(&mut self) {
        self.version_response = "Unknown".to_string();
        self.engine_version = "—".to_string();
        self.database_version = "—".to_string();
        self.database_time = "—".to_string();
        self.connected_at = None;
        self.primary_live = 0;
        self.primary_idle = 0;
        self.primary_max = 0;
        self.live = 0;
        self.idle = 0;
        self.max_threads = 0;
        self.queue = 0;
        self.max_queue = 0;
        self.memory = MemoryStats::default();
        self.memory_peak_mb = 0.0;
        self.tasks.clear();
    }

    fn connection_age(&self) -> String {
        let Some(start) = self.connected_at else {
            return "--:--".to_string();
        };
        let seconds = start.elapsed().as_secs();
        if seconds >= 86_400 {
            format!("{}d {:02}h", seconds / 86_400, (seconds / 3_600) % 24)
        } else {
            format!(
                "{:02}:{:02}:{:02}",
                seconds / 3_600,
                (seconds / 60) % 60,
                seconds % 60
            )
        }
    }
}

#[derive(Clone, Debug)]
struct CliOptions {
    endpoints: Vec<Endpoint>,
    default_colors: bool,
}

enum WorkerCommand {
    ResetQueue,
}

#[derive(Debug)]
struct App {
    daemons: Vec<DaemonStats>,
    selected: Option<usize>,
    show_help: bool,
    default_colors: bool,
    reset_generation: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("clamdtop: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let options = parse_cli(&arguments)?;
    if options.endpoints.is_empty() {
        print_help();
        return Ok(());
    }

    // A blocked terminal must not let periodic worker updates consume memory.
    // Keep a bounded number of recent snapshots and coalesce any overflow.
    let (updates_tx, updates_rx) = mpsc::sync_channel(options.endpoints.len());
    let reset_generation = Arc::new(AtomicU64::new(0));
    let mut worker_commands = Vec::with_capacity(options.endpoints.len());
    for (index, endpoint) in options.endpoints.iter().cloned().enumerate() {
        // Reset requests are idempotent, so retaining more than one per worker
        // only delays the next STATS request when a key is held down.
        let (command_tx, command_rx) = mpsc::sync_channel(1);
        worker_commands.push(command_tx);
        let updates_tx = updates_tx.clone();
        let reset_generation = Arc::clone(&reset_generation);
        thread::Builder::new()
            .name(format!("clamdtop-{index}"))
            .spawn(move || daemon_worker(index, endpoint, updates_tx, command_rx, reset_generation))
            .map_err(|error| format!("could not start daemon worker: {error}"))?;
    }
    drop(updates_tx);

    let mut app = App {
        daemons: options.endpoints.iter().map(DaemonStats::new).collect(),
        selected: None,
        show_help: false,
        default_colors: options.default_colors,
        reset_generation: 0,
    };

    let mut terminal = TerminalGuard::new()?;
    loop {
        while let Ok((index, generation, stats)) = updates_rx.try_recv() {
            if generation >= app.reset_generation {
                if let Some(daemon) = app.daemons.get_mut(index) {
                    *daemon = stats;
                }
            }
        }

        terminal
            .terminal
            .draw(|frame| draw(frame, &app))
            .map_err(|e| e.to_string())?;

        if event::poll(Duration::from_millis(150)).map_err(|e| e.to_string())? {
            match event::read().map_err(|e| e.to_string())? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if app.show_help {
                        app.show_help = false;
                        if matches!(key.code, KeyCode::Char('q' | 'Q') | KeyCode::Esc) {
                            break;
                        }
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => break,
                        KeyCode::Char('c')
                            if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                        {
                            break
                        }
                        KeyCode::Char('h') | KeyCode::Char('H') => app.show_help = true,
                        KeyCode::Char('r') | KeyCode::Char('R') => {
                            app.reset_generation = app.reset_generation.saturating_add(1);
                            reset_generation.store(app.reset_generation, Ordering::Release);
                            for daemon in &mut app.daemons {
                                daemon.max_queue = daemon.queue;
                                daemon.memory_peak_mb = memory_bar_total(&daemon.memory);
                            }
                            for command in &worker_commands {
                                let _ = command.try_send(WorkerCommand::ResetQueue);
                            }
                        }
                        KeyCode::Up => select_previous(&mut app),
                        KeyCode::Down => select_next(&mut app),
                        _ => {}
                    }
                }
                Event::Resize(_, _) => {
                    // Ratatui recalculates its layout on the next draw.
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn parse_cli(args: &[String]) -> Result<CliOptions, String> {
    let mut config_file = option_env!("CLAMAV_DEFAULT_CLAMD_CONFIG")
        .unwrap_or("/etc/clamav/clamd.conf")
        .to_string();
    let mut default_colors = false;
    let mut endpoints = Vec::new();
    let mut index = 0;
    let mut positional_only = false;
    while index < args.len() {
        let arg = &args[index];
        if !positional_only && arg == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if positional_only {
            endpoints.push(parse_endpoint(arg)?);
            index += 1;
            continue;
        }
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("Clam AntiVirus Monitoring Tool {}", clamav_version());
                std::process::exit(0);
            }
            "-d" | "--defaultcolors" => default_colors = true,
            "-c" | "--config-file" => {
                index += 1;
                config_file = args
                    .get(index)
                    .ok_or("-c requires a configuration file")?
                    .clone();
            }
            _ if arg.starts_with("--config-file=") => {
                config_file = arg["--config-file=".len()..].to_string();
                if config_file.is_empty() {
                    return Err("--config-file requires a configuration file".to_string());
                }
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ => endpoints.push(parse_endpoint(arg)?),
        }
        index += 1;
    }

    if endpoints.is_empty() {
        endpoints = endpoints_from_config(Path::new(&config_file))?;
    }
    Ok(CliOptions {
        endpoints,
        default_colors,
    })
}

fn parse_endpoint(input: &str) -> Result<Endpoint, String> {
    #[cfg(unix)]
    {
        if let Some(path) = input.strip_prefix("unix:") {
            if path.is_empty() {
                return Err("Unix socket path is empty".to_string());
            }
            return Ok(Endpoint::Unix(PathBuf::from(path)));
        }
        let path = Path::new(input);
        if path.is_absolute() || path.exists() {
            return Ok(Endpoint::Unix(path.to_path_buf()));
        }
    }

    let (host, port) = if input.starts_with('[') {
        let close = input
            .find(']')
            .ok_or_else(|| format!("invalid bracketed address: {input}"))?;
        let host = &input[1..close];
        let suffix = &input[close + 1..];
        let port = if suffix.is_empty() {
            3310
        } else {
            let port = suffix
                .strip_prefix(':')
                .ok_or_else(|| format!("invalid bracketed address: {input}"))?;
            parse_port(port).map_err(|_| format!("invalid port in address: {input}"))?
        };
        (host.to_string(), port)
    } else if input.matches(':').count() == 1 {
        let (host, port) = input.split_once(':').unwrap();
        let port = parse_port(port).map_err(|_| format!("invalid port in address: {input}"))?;
        (host.to_string(), port)
    } else {
        (input.to_string(), 3310)
    };
    if host.is_empty() {
        return Err(format!("host is empty in address: {input}"));
    }
    if host.chars().any(char::is_whitespace) {
        return Err(format!("host contains whitespace in address: {input}"));
    }
    Ok(Endpoint::Tcp { host, port })
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("invalid port: {value}"))?;
    if port == 0 {
        return Err("port must be between 1 and 65535".to_string());
    }
    Ok(port)
}

fn endpoints_from_config(path: &Path) -> Result<Vec<Endpoint>, String> {
    let contents = fs::read_to_string(path).map_err(|error| {
        format!(
            "could not read clamd configuration {}: {error}",
            path.display()
        )
    })?;
    let mut local_socket = None;
    let mut tcp_socket = None;
    let mut tcp_addr = None;
    for line in contents.lines() {
        let Some((key, value)) = parse_config_directive(line) else {
            continue;
        };
        match key.as_str() {
            "localsocket" => local_socket = Some(value),
            "tcpsocket" => tcp_socket = Some(value),
            "tcpaddr" => tcp_addr = Some(value),
            _ => {}
        }
    }
    if let Some(socket_path) = local_socket {
        if socket_path.is_empty() {
            return Err(format!("invalid LocalSocket in {}", path.display()));
        }
        #[cfg(unix)]
        return Ok(vec![Endpoint::Unix(PathBuf::from(socket_path))]);
        #[cfg(not(unix))]
        return Err(format!(
            "local socket endpoints are not supported on this platform: {socket_path}"
        ));
    }
    if let Some(port) = tcp_socket {
        let host = tcp_addr.unwrap_or_else(|| "localhost".to_string());
        let host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(&host)
            .to_string();
        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err(format!("invalid TCPAddr in {}", path.display()));
        }
        return Ok(vec![Endpoint::Tcp {
            host,
            port: parse_port(&port)
                .map_err(|error| format!("invalid TCPSocket in {}: {error}", path.display()))?,
        }]);
    }
    Err(format!(
        "no LocalSocket or TCPSocket configured in {}",
        path.display()
    ))
}

fn parse_config_directive(line: &str) -> Option<(String, String)> {
    let mut quote = None;
    let mut escaped = false;
    let mut end = line.len();
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' && quote.is_some() {
            escaped = true;
        } else if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
        } else if ch == '#' && quote.is_none() {
            end = index;
            break;
        }
    }
    let line = line[..end].trim();
    let (key, value) = line.split_once(char::is_whitespace)?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value);
    Some((key.to_ascii_lowercase(), value.to_string()))
}

fn clamav_version() -> &'static str {
    option_env!("CLAMAV_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

fn print_help() {
    println!(
        "\n                       Clam AntiVirus: Monitoring Tool {}",
        clamav_version()
    );
    println!("           By The ClamAV Team: https://www.clamav.net/about.html#credits");
    println!("\n    clamdtop [-hVc] [host[:port] /path/to/clamd.sock ...]\n");
    println!("    --help                 -h         Show this help");
    println!("    --version              -V         Show version");
    println!("    --config-file=FILE     -c FILE    Read clamd's configuration file from FILE");
    println!("    --defaultcolors        -d         Use default terminal colors");
    println!(
        "    host[:port]                       Connect to clamd on host at port (default 3310)"
    );
    println!("    /path/to/clamd.sock               Connect to clamd over a local socket\n");
}

enum Transport {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Read for Transport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buffer),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

fn connect(endpoint: &Endpoint) -> io::Result<BufReader<Transport>> {
    let transport = match endpoint {
        Endpoint::Tcp { host, port } => {
            let addresses = (host.as_str(), *port).to_socket_addrs()?;
            let deadline = Instant::now() + CONNECT_TIMEOUT;
            let mut last_error = None;
            let mut connected = None;
            for address in addresses {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match TcpStream::connect_timeout(&address, remaining) {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            let stream = connected.ok_or_else(|| {
                last_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "host resolved to no addresses",
                    )
                })
            })?;
            stream.set_read_timeout(Some(IO_TIMEOUT))?;
            stream.set_write_timeout(Some(IO_TIMEOUT))?;
            Transport::Tcp(stream)
        }
        #[cfg(unix)]
        Endpoint::Unix(path) => {
            let stream = std::os::unix::net::UnixStream::connect(path)?;
            stream.set_read_timeout(Some(IO_TIMEOUT))?;
            stream.set_write_timeout(Some(IO_TIMEOUT))?;
            Transport::Unix(stream)
        }
    };
    Ok(BufReader::new(transport))
}

fn daemon_worker(
    index: usize,
    endpoint: Endpoint,
    updates: SyncSender<(usize, u64, DaemonStats)>,
    commands: Receiver<WorkerCommand>,
    reset_generation: Arc<AtomicU64>,
) {
    let mut stats = DaemonStats::new(&endpoint);
    let mut applied_reset_generation = reset_generation.load(Ordering::Acquire);
    'reconnect: loop {
        stats.clear_connection_data();
        apply_requested_reset(&mut stats, &reset_generation, &mut applied_reset_generation);
        stats.status = "Connecting".to_string();
        if !publish_update(&updates, index, applied_reset_generation, &stats) {
            return;
        }
        let mut use_legacy_session = false;
        let (mut stream, version_response) = 'session: loop {
            let mut stream = match connect(&endpoint) {
                Ok(stream) => stream,
                Err(error) => {
                    stats.status =
                        format!("Offline · {}", sanitize_terminal_text(&error.to_string()));
                    if !publish_update(&updates, index, applied_reset_generation, &stats)
                        || !wait_for_commands(
                            &commands,
                            &mut stats,
                            &reset_generation,
                            &mut applied_reset_generation,
                            RECONNECT_DELAY,
                        )
                    {
                        return;
                    }
                    continue 'reconnect;
                }
            };
            // clamd closes a one-shot connection after each command. Modern
            // daemons support IDSESSION; SESSION preserves compatibility with
            // the older protocol used by the original clamdtop fallback.
            let session_command = if use_legacy_session {
                "SESSION"
            } else {
                "IDSESSION"
            };
            if let Err(error) = request(&mut stream, session_command) {
                stats.clear_connection_data();
                stats.status = format!(
                    "Protocol error · {}",
                    sanitize_terminal_text(&error.to_string())
                );
                if !publish_update(&updates, index, applied_reset_generation, &stats)
                    || !wait_for_commands(
                        &commands,
                        &mut stats,
                        &reset_generation,
                        &mut applied_reset_generation,
                        RECONNECT_DELAY,
                    )
                {
                    return;
                }
                continue 'reconnect;
            }
            stats.status = "Connected".to_string();
            stats.connected_at = Some(Instant::now());
            if let Err(error) = request(&mut stream, "VERSION") {
                if !use_legacy_session {
                    use_legacy_session = true;
                    continue 'session;
                }
                stats.clear_connection_data();
                stats.status = format!(
                    "Protocol error · {}",
                    sanitize_terminal_text(&error.to_string())
                );
                if !publish_update(&updates, index, applied_reset_generation, &stats)
                    || !wait_for_commands(
                        &commands,
                        &mut stats,
                        &reset_generation,
                        &mut applied_reset_generation,
                        RECONNECT_DELAY,
                    )
                {
                    return;
                }
                continue 'reconnect;
            }
            let version_response = match read_line(&mut stream) {
                Ok(Some(line)) => line,
                Ok(None) if !use_legacy_session => {
                    use_legacy_session = true;
                    continue 'session;
                }
                Ok(None) => {
                    stats.clear_connection_data();
                    stats.status = "Connection closed".to_string();
                    if !publish_update(&updates, index, applied_reset_generation, &stats)
                        || !wait_for_commands(
                            &commands,
                            &mut stats,
                            &reset_generation,
                            &mut applied_reset_generation,
                            RECONNECT_DELAY,
                        )
                    {
                        return;
                    }
                    continue 'reconnect;
                }
                Err(_) if !use_legacy_session => {
                    use_legacy_session = true;
                    continue 'session;
                }
                Err(error) => {
                    stats.clear_connection_data();
                    stats.status = format!(
                        "Protocol error · {}",
                        sanitize_terminal_text(&error.to_string())
                    );
                    if !publish_update(&updates, index, applied_reset_generation, &stats)
                        || !wait_for_commands(
                            &commands,
                            &mut stats,
                            &reset_generation,
                            &mut applied_reset_generation,
                            RECONNECT_DELAY,
                        )
                    {
                        return;
                    }
                    continue 'reconnect;
                }
            };
            if is_unknown_command(&version_response) && !use_legacy_session {
                use_legacy_session = true;
                continue 'session;
            }
            if is_protocol_error(&version_response) {
                stats.clear_connection_data();
                stats.status = if is_command_unavailable(&version_response) {
                    "VERSION command unavailable".to_string()
                } else {
                    "VERSION command rejected".to_string()
                };
                if !publish_update(&updates, index, applied_reset_generation, &stats)
                    || !wait_for_commands(
                        &commands,
                        &mut stats,
                        &reset_generation,
                        &mut applied_reset_generation,
                        RECONNECT_DELAY,
                    )
                {
                    return;
                }
                continue 'reconnect;
            }
            break 'session (stream, version_response);
        };
        parse_version(&version_response, &mut stats);

        loop {
            match commands.try_recv() {
                Ok(WorkerCommand::ResetQueue) => apply_requested_reset(
                    &mut stats,
                    &reset_generation,
                    &mut applied_reset_generation,
                ),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    let _ = request(&mut stream, "END");
                    return;
                }
            }
            match request(&mut stream, "STATS").and_then(|_| read_stats(&mut stream)) {
                Ok(response) => {
                    parse_stats(&response, &mut stats);
                    apply_requested_reset(
                        &mut stats,
                        &reset_generation,
                        &mut applied_reset_generation,
                    );
                    stats.memory_peak_mb =
                        stats.memory_peak_mb.max(memory_bar_total(&stats.memory));
                    stats.status = "Online".to_string();
                    if !publish_update(&updates, index, applied_reset_generation, &stats) {
                        return;
                    }
                }
                Err(error) => {
                    stats.clear_connection_data();
                    stats.status = format!(
                        "Reconnecting · {}",
                        sanitize_terminal_text(&error.to_string())
                    );
                    if !publish_update(&updates, index, applied_reset_generation, &stats) {
                        return;
                    }
                    break;
                }
            }
            if !wait_for_commands(
                &commands,
                &mut stats,
                &reset_generation,
                &mut applied_reset_generation,
                REFRESH_INTERVAL,
            ) {
                let _ = request(&mut stream, "END");
                return;
            }
        }
        if !wait_for_commands(
            &commands,
            &mut stats,
            &reset_generation,
            &mut applied_reset_generation,
            RECONNECT_DELAY,
        ) {
            return;
        }
    }
}

fn publish_update(
    updates: &SyncSender<(usize, u64, DaemonStats)>,
    index: usize,
    generation: u64,
    stats: &DaemonStats,
) -> bool {
    match updates.try_send((index, generation, stats.clone())) {
        Ok(()) | Err(TrySendError::Full(_)) => true,
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn reset_maxima(stats: &mut DaemonStats) {
    stats.max_queue = stats.queue;
    stats.memory_peak_mb = memory_bar_total(&stats.memory);
}

fn apply_requested_reset(
    stats: &mut DaemonStats,
    reset_generation: &AtomicU64,
    applied_reset_generation: &mut u64,
) {
    let requested_reset_generation = reset_generation.load(Ordering::Acquire);
    if *applied_reset_generation < requested_reset_generation {
        reset_maxima(stats);
        *applied_reset_generation = requested_reset_generation;
    }
}

fn wait_for_commands(
    commands: &Receiver<WorkerCommand>,
    stats: &mut DaemonStats,
    reset_generation: &AtomicU64,
    applied_reset_generation: &mut u64,
    duration: Duration,
) -> bool {
    let deadline = Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        match commands.recv_timeout(remaining) {
            Ok(WorkerCommand::ResetQueue) => {
                apply_requested_reset(stats, reset_generation, applied_reset_generation)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => return true,
            Err(mpsc::RecvTimeoutError::Disconnected) => return false,
        }
    }
}

fn request(stream: &mut BufReader<Transport>, command: &str) -> io::Result<()> {
    stream
        .get_mut()
        .write_all(format!("n{command}\n").as_bytes())?;
    stream.get_mut().flush()
}

fn read_line<R: BufRead>(stream: &mut R) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    loop {
        let buffer = stream.fill_buf()?;
        if buffer.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "clamd closed the connection in the middle of a response line",
                ))
            };
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(buffer.len(), |index| index + 1);
        if bytes.len().saturating_add(take) > MAX_PROTOCOL_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("clamd response line exceeds {MAX_PROTOCOL_LINE_BYTES} bytes"),
            ));
        }
        bytes.extend_from_slice(&buffer[..take]);
        stream.consume(take);
        if newline.is_some() {
            // Filenames in clamd task records may contain arbitrary Unix path
            // bytes. Keep the response usable and render invalid UTF-8 as the
            // replacement character instead of reconnecting needlessly.
            let line = String::from_utf8_lossy(&bytes).into_owned();
            return Ok(Some(strip_session_prefix(
                line.trim_end_matches(['\r', '\n']).to_string(),
            )));
        }
    }
}

fn strip_session_prefix(line: String) -> String {
    if let Some((prefix, rest)) = line.split_once(": ") {
        if prefix.chars().all(|ch| ch.is_ascii_digit()) {
            return rest.to_string();
        }
    }
    line
}

fn read_stats<R: BufRead>(stream: &mut R) -> io::Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut bytes = 0usize;
    while let Some(line) = read_line(stream)? {
        if line == "END" {
            return Ok(lines);
        }
        if !line.starts_with('\t') && is_protocol_error(&line) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("clamd rejected STATS: {}", sanitize_terminal_text(&line)),
            ));
        }
        bytes = bytes.saturating_add(line.len() + 1);
        if lines.len() >= MAX_STATS_RESPONSE_LINES || bytes > MAX_STATS_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "clamd STATS response is too large",
            ));
        }
        lines.push(line);
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "clamd closed the connection while returning STATS",
    ))
}

fn is_protocol_error(line: &str) -> bool {
    let line = line.trim().to_ascii_uppercase();
    is_unknown_command(&line)
        || is_command_unavailable(&line)
        || line == "ERROR"
        || line.starts_with("ERROR:")
        || line.ends_with(" ERROR")
}

fn is_unknown_command(line: &str) -> bool {
    line.trim_start()
        .to_ascii_uppercase()
        .starts_with("UNKNOWN COMMAND")
}

fn is_command_unavailable(line: &str) -> bool {
    line.to_ascii_uppercase().contains("COMMAND UNAVAILABLE")
}

fn sanitize_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '\u{fffd}' } else { ch })
        .collect()
}

fn parse_version(line: &str, stats: &mut DaemonStats) {
    let body = line
        .strip_prefix("ClamAV:")
        .map(str::trim)
        .unwrap_or(line)
        .trim();
    stats.version_response = sanitize_terminal_text(body);
    let engine_version = body
        .split_whitespace()
        .find(|word| word.chars().next().is_some_and(|ch| ch.is_ascii_digit()))
        .unwrap_or("unknown")
        .split('/')
        .next()
        .unwrap_or("unknown")
        .split('-')
        .next()
        .unwrap_or("unknown");
    stats.engine_version = sanitize_terminal_text(engine_version);
    let mut parts = body.split('/');
    let _ = parts.next();
    if let Some(database_version) = parts.next() {
        stats.database_version = sanitize_terminal_text(database_version.trim());
    }
    if let Some(date) = parts.next() {
        stats.database_time = sanitize_terminal_text(date.trim());
    }
}

fn parse_stats(lines: &[String], stats: &mut DaemonStats) {
    stats.primary_live = 0;
    stats.primary_idle = 0;
    stats.primary_max = 0;
    stats.live = 0;
    stats.idle = 0;
    stats.max_threads = 0;
    stats.queue = 0;
    stats.memory = MemoryStats::default();
    stats.tasks.clear();
    let mut primary = false;
    for line in lines {
        if line.starts_with('\t') {
            if let Some(task) = parse_task(line) {
                stats.tasks.push(task);
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_uppercase();
        let value = value.trim();
        match key.as_str() {
            "STATE" => {
                primary = value.to_ascii_uppercase().contains("PRIMARY");
            }
            "THREADS" => {
                let values = parse_named_numbers(value);
                let live = values.get("live").copied().unwrap_or(0);
                let idle = values.get("idle").copied().unwrap_or(0);
                let max = values.get("max").copied().unwrap_or(0);
                stats.live = stats.live.saturating_add(live);
                stats.idle = stats.idle.saturating_add(idle);
                stats.max_threads = stats.max_threads.saturating_add(max);
                if primary {
                    stats.primary_live = live;
                    stats.primary_idle = idle;
                    stats.primary_max = max;
                }
            }
            "QUEUE" => {
                if let Some(count) = value
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u32>().ok())
                {
                    stats.queue = stats.queue.saturating_add(count);
                }
            }
            "MEMSTATS" => stats.memory = parse_memory(value),
            _ => {}
        }
    }
    stats.max_queue = stats.max_queue.max(stats.queue);
}

fn parse_named_numbers(input: &str) -> std::collections::HashMap<String, u32> {
    let tokens: Vec<_> = input.split_whitespace().collect();
    let mut values = std::collections::HashMap::new();
    for pair in tokens.windows(2) {
        if let Ok(value) = pair[1].parse::<u32>() {
            values.insert(pair[0].to_ascii_lowercase(), value);
        }
    }
    values
}

fn parse_memory(input: &str) -> MemoryStats {
    let mut result = MemoryStats::default();
    let tokens: Vec<_> = input.split_whitespace().collect();
    for pair in tokens.windows(2) {
        let key = pair[0].to_ascii_lowercase();
        let raw = pair[1].trim_end_matches(['M', 'm']);
        match key.as_str() {
            "pools" => result.pools = raw.parse().ok(),
            _ => {
                let Some(value) = parse_memory_amount(raw) else {
                    continue;
                };
                match key.as_str() {
                    "heap" => result.heap_mb = Some(value),
                    "mmap" => result.mmap_mb = Some(value),
                    "used" => result.used_mb = Some(value),
                    "free" => result.free_mb = Some(value),
                    "releasable" => result.releasable_mb = Some(value),
                    "pools_used" => result.pools_used_mb = Some(value),
                    "pools_total" => result.pools_total_mb = Some(value),
                    _ => {}
                }
            }
        }
    }
    result
}

fn parse_memory_amount(value: &str) -> Option<f64> {
    value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value >= 0.0)
}

fn total_memory_mb(memory: &MemoryStats) -> Option<f64> {
    if memory.heap_mb.is_none() && memory.mmap_mb.is_none() {
        return None;
    }
    let total = memory.heap_mb.unwrap_or_default()
        + memory.mmap_mb.unwrap_or_default()
        + memory.pools_total_mb.unwrap_or_default();
    total.is_finite().then_some(total)
}

fn parse_task(line: &str) -> Option<Task> {
    let mut fields = line
        .trim()
        .splitn(3, char::is_whitespace)
        .filter(|part| !part.is_empty());
    let command = sanitize_terminal_text(fields.next()?);
    let elapsed = fields
        .next()?
        .parse::<f64>()
        .ok()
        .filter(|elapsed| elapsed.is_finite() && *elapsed >= 0.0)?;
    let file = sanitize_terminal_text(fields.next().unwrap_or("(no file)"));
    Some(Task {
        command,
        elapsed,
        file,
    })
}

fn select_previous(app: &mut App) {
    if app.daemons.len() <= 1 {
        return;
    }
    app.selected = match app.selected {
        None => Some(app.daemons.len() - 1),
        Some(0) => None,
        Some(index) => Some(index - 1),
    };
}

fn select_next(app: &mut App) {
    if app.daemons.len() <= 1 {
        return;
    }
    app.selected = match app.selected {
        None => Some(0),
        Some(index) if index + 1 >= app.daemons.len() => None,
        Some(index) => Some(index + 1),
    };
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn new() -> Result<Self, String> {
        enable_raw_mode()
            .map_err(|error| format!("could not enable terminal raw mode: {error}"))?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, crossterm::cursor::Hide) {
            // Either command may have succeeded before the later one failed.
            let _ = execute!(stdout, LeaveAlternateScreen, crossterm::cursor::Show);
            let _ = disable_raw_mode();
            return Err(format!("could not initialize terminal: {error}"));
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
                let _ = disable_raw_mode();
                return Err(error.to_string());
            }
        };
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
        let _ = self.terminal.show_cursor();
    }
}

fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let summary_height = (app.daemons.len() as u16 + 1).min(area.height.saturating_sub(5));
    let available = area.height.saturating_sub(summary_height.saturating_add(2));
    let details_height = available.saturating_sub(3).min(11);
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(summary_height),
            Constraint::Length(details_height),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);
    render_header(frame, vertical[0], app);
    if app.show_help {
        render_help(
            frame,
            vertical[1].union(vertical[2]).union(vertical[3]),
            app.default_colors,
        );
    } else {
        render_daemon_table(frame, vertical[1], app);
        if let Some(index) = app
            .selected
            .or_else(|| (app.daemons.len() == 1).then_some(0))
            .filter(|index| *index < app.daemons.len())
        {
            render_details(
                frame,
                vertical[2],
                &app.daemons[index],
                app.default_colors,
                app.daemons[index].memory_peak_mb,
            );
        }
        render_tasks(frame, vertical[3], app);
    }
    render_footer(frame, vertical[4], app);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let format = time::macros::format_description!(
        "[weekday repr:short] [month repr:short] [day padding:space] [hour]:[minute]:[second] [year]"
    );
    let date = now.format(&format).unwrap_or_default();
    let text = format!("  ClamdTOP version {}   {}", clamav_version(), date);
    let style = if app.default_colors {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Black)
            .bg(Color::White)
            .add_modifier(Modifier::BOLD)
    };
    frame.render_widget(Paragraph::new(text).style(style), area);
}

fn render_daemon_table(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = app.daemons.iter().enumerate().map(|(index, daemon)| {
        Row::new(vec![
            Cell::from(format!("{:2}", index + 1)),
            Cell::from(daemon.connection_age()),
            Cell::from(daemon.live.to_string()),
            Cell::from(daemon.idle.to_string()),
            Cell::from(daemon.queue.to_string()),
            Cell::from(daemon.max_queue.to_string()),
            Cell::from(format_memory(&daemon.memory)),
            Cell::from(daemon.engine_version.clone()),
            Cell::from(daemon.database_version.clone()),
            Cell::from(format_database_time(daemon)),
            Cell::from(daemon.endpoint.clone()),
        ])
        .style(
            if app
                .selected
                .or_else(|| (app.daemons.len() == 1).then_some(0))
                == Some(index)
            {
                selected_style(app.default_colors)
            } else {
                Style::default()
            },
        )
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Length(9),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Min(13),
        ],
    )
    .header(
        Row::new([
            "NO", "CONNTIME", "LIV", "IDL", "QUEUE", "MAXQ", "MEM", "ENGINE", "DBVER", "DBTIME",
            "HOST",
        ])
        .style(queue_header_style(app.default_colors)),
    )
    .column_spacing(1);
    frame.render_widget(table, area);
}

fn render_details(
    frame: &mut Frame<'_>,
    area: Rect,
    daemon: &DaemonStats,
    default_colors: bool,
    memory_peak_mb: f64,
) {
    let version_style = if default_colors {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::default().fg(Color::Black).bg(Color::Green)
    };
    let version = Paragraph::new(format!(
        "Details for Clamd version: {}",
        daemon.version_response
    ))
    .style(version_style);
    frame.render_widget(version, Rect::new(area.x, area.y, area.width, 1));

    let text_style = if default_colors {
        Style::default()
    } else {
        Style::default().fg(Color::Cyan)
    };
    let value_style = if default_colors {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    };
    let primary_line = Line::from(vec![
        Span::styled("Primary threads: ", text_style),
        Span::styled(
            format_thread_counts(daemon.primary_live, daemon.primary_idle, daemon.primary_max),
            value_style,
        ),
    ]);
    let queue_line = Line::from(vec![
        Span::styled("Queue: ", text_style),
        Span::styled(
            format!("{} items   {} max", daemon.queue, daemon.max_queue),
            value_style,
        ),
    ]);

    let format_value =
        |value: Option<f64>| value.map_or_else(|| "N/A".to_string(), |mb| format!("{mb:.0}M"));
    let mem_line = memory_line(
        "Mem",
        &[
            ("heap", format_value(daemon.memory.heap_mb)),
            ("mmap", format_value(daemon.memory.mmap_mb)),
            ("unused", format_value(daemon.memory.releasable_mb)),
        ],
        default_colors,
    );
    let (libc_used, libc_free, libc_total) = match (daemon.memory.used_mb, daemon.memory.free_mb) {
        (Some(used), Some(free)) => (
            format!("{used:.0}M"),
            format!("{free:.0}M"),
            format!("{:.0}M", used + free),
        ),
        _ => ("N/A".to_string(), "N/A".to_string(), "N/A".to_string()),
    };
    let libc_line = memory_line(
        "Libc",
        &[
            ("used", libc_used),
            ("free", libc_free),
            ("total", libc_total),
        ],
        default_colors,
    );
    let pool_line = memory_line(
        "Pool",
        &[
            (
                "count",
                daemon
                    .memory
                    .pools
                    .map_or_else(|| "N/A".to_string(), |n| n.to_string()),
            ),
            ("used", format_value(daemon.memory.pools_used_mb)),
            ("total", format_value(daemon.memory.pools_total_mb)),
        ],
        default_colors,
    );
    let memory_lines = [mem_line, libc_line, pool_line];
    let memory_content_width = memory_lines.iter().map(Line::width).max().unwrap_or(0);

    // Leave at least 42 columns for the thread and queue meters. Size the
    // memory panel to its content instead of stretching it to fill the screen.
    // The box needs three key/value rows and a meter inside its borders.  The
    // details area also has a version row above the box, so six total rows
    // would put the meter on the bottom border.
    let memory_box = memory_panel_area(area, memory_content_width);
    let left_width = memory_box.map_or(area.width, |box_area| {
        box_area.x.saturating_sub(area.x).saturating_sub(1)
    });

    frame.render_widget(
        Paragraph::new(primary_line),
        Rect::new(area.x, area.y.saturating_add(1), left_width, 1),
    );
    render_segmented_bar(
        frame,
        Rect::new(area.x, area.y.saturating_add(2), left_width.min(41), 1),
        daemon.primary_live as f64,
        daemon.primary_idle as f64,
        daemon.primary_max as f64,
        if default_colors {
            Color::Reset
        } else {
            Color::Magenta
        },
        if default_colors {
            Color::Reset
        } else {
            Color::Green
        },
    );
    frame.render_widget(
        Paragraph::new(queue_line),
        Rect::new(area.x, area.y.saturating_add(4), left_width.min(41), 1),
    );
    render_segmented_bar(
        frame,
        Rect::new(area.x, area.y.saturating_add(5), left_width.min(41), 1),
        daemon.queue as f64,
        0.0,
        daemon.max_queue as f64,
        if default_colors {
            Color::Reset
        } else {
            Color::Magenta
        },
        if default_colors {
            Color::Reset
        } else {
            Color::Green
        },
    );

    if let Some(memory_box) = memory_box {
        frame.render_widget(Block::default().borders(Borders::ALL), memory_box);
        for (offset, line) in memory_lines.iter().enumerate() {
            frame.render_widget(
                Paragraph::new(line.clone()),
                Rect::new(
                    memory_box.x.saturating_add(1),
                    memory_box.y.saturating_add(1 + offset as u16),
                    memory_box.width.saturating_sub(2),
                    1,
                ),
            );
        }
        let total = memory_bar_total(&daemon.memory);
        let idle = daemon.memory.mmap_mb.unwrap_or_default()
            + daemon.memory.releasable_mb.unwrap_or_default()
            + (daemon.memory.pools_total_mb.unwrap_or_default()
                - daemon.memory.pools_used_mb.unwrap_or_default());
        render_segmented_bar(
            frame,
            Rect::new(
                memory_box.x.saturating_add(1),
                memory_box.y.saturating_add(4),
                (memory_content_width as u16 + 2).min(memory_box.width.saturating_sub(2)),
                1,
            ),
            total,
            idle.max(0.0),
            memory_peak_mb,
            if default_colors {
                Color::Reset
            } else {
                Color::Magenta
            },
            if default_colors {
                Color::Reset
            } else {
                Color::Green
            },
        );
    } else {
        // At compact widths, keep all three memory rows visible below the
        // thread and queue meters instead of drawing a panel over them.
        for (offset, line) in memory_lines.iter().enumerate() {
            let row = 7 + offset as u16;
            if row < area.height {
                frame.render_widget(
                    Paragraph::new(line.clone()),
                    Rect::new(area.x, area.y.saturating_add(row), area.width, 1),
                );
            }
        }
        let bar_row = 10;
        if bar_row < area.height {
            let total = memory_bar_total(&daemon.memory);
            let idle = daemon.memory.mmap_mb.unwrap_or_default()
                + daemon.memory.releasable_mb.unwrap_or_default()
                + (daemon.memory.pools_total_mb.unwrap_or_default()
                    - daemon.memory.pools_used_mb.unwrap_or_default());
            render_segmented_bar(
                frame,
                Rect::new(
                    area.x,
                    area.y.saturating_add(bar_row),
                    (memory_content_width as u16 + 2).min(area.width),
                    1,
                ),
                total,
                idle.max(0.0),
                memory_peak_mb,
                if default_colors {
                    Color::Reset
                } else {
                    Color::Magenta
                },
                if default_colors {
                    Color::Reset
                } else {
                    Color::Green
                },
            );
        }
    }
}

fn render_segmented_bar(
    frame: &mut Frame<'_>,
    area: Rect,
    live: f64,
    idle: f64,
    max: f64,
    active_color: Color,
    idle_color: Color,
) {
    if area.height == 0 || area.width < 3 {
        return;
    }
    let inner = area.width.saturating_sub(2) as usize;
    let active = if max > 0.0 {
        (((live - idle).max(0.0) / max) * inner as f64).round() as usize
    } else {
        0
    }
    .min(inner);
    let dim = if max > 0.0 {
        ((idle.max(0.0) / max) * inner as f64).floor() as usize
    } else {
        0
    }
    .min(inner.saturating_sub(active));
    let remaining = inner.saturating_sub(active + dim);
    let line = Line::from(vec![
        Span::styled("[", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            "|".repeat(active),
            Style::default()
                .fg(active_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "|".repeat(dim),
            Style::default().fg(idle_color).add_modifier(Modifier::DIM),
        ),
        Span::raw(" ".repeat(remaining)),
        Span::styled("]", Style::default().add_modifier(Modifier::BOLD)),
    ]);
    frame.render_widget(
        Paragraph::new(line),
        Rect::new(area.x, area.y, inner as u16 + 2, 1),
    );
}

fn format_thread_counts(live: u32, idle: u32, max: u32) -> String {
    format!("live{live:3} idle{idle:3} max{max:3}")
}

fn memory_panel_area(area: Rect, memory_content_width: usize) -> Option<Rect> {
    if area.width < 85 || area.height < 7 {
        return None;
    }
    let desired_width = (memory_content_width as u16).saturating_add(4).min(66);
    let width = desired_width.min(area.width.saturating_sub(43));
    Some(Rect::new(
        area.x + area.width.saturating_sub(width),
        area.y.saturating_add(1),
        width,
        6.min(area.height.saturating_sub(1)),
    ))
}

fn render_tasks(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut tasks: Vec<_> = app
        .daemons
        .iter()
        .enumerate()
        .filter(|(index, _)| app.selected.is_none() || app.selected == Some(*index))
        .flat_map(|(index, daemon)| daemon.tasks.iter().map(move |task| (index, daemon, task)))
        .collect();
    tasks.sort_by(|left, right| right.2.elapsed.total_cmp(&left.2.elapsed));
    let multiple = app.daemons.len() > 1;
    let column_count = if multiple { 4 } else { 3 };
    let visible_rows = area.height.saturating_sub(1) as usize;
    let hidden = tasks.len().saturating_sub(visible_rows);
    let task_rows = visible_rows.saturating_sub(usize::from(hidden > 0));
    let mut rows: Vec<Row<'_>> = tasks
        .iter()
        .take(task_rows)
        .map(|(index, _, task)| {
            let mut cells = Vec::new();
            if multiple {
                cells.push(Cell::from(format!("{:2}", index + 1)));
            }
            cells.push(
                Cell::from(task.command.clone())
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            );
            cells.push(Cell::from(format!("{:10.3}s", task.elapsed)));
            cells.push(Cell::from(task.file.clone()));
            Row::new(cells)
        })
        .collect();
    if hidden > 0 {
        rows.push(Row::new(vec![Cell::from(format!(
            "*** {hidden} more task(s) not shown ***"
        ))
        .column_span(column_count)]));
    }
    let mut constraints = Vec::new();
    let mut header = Vec::new();
    if multiple {
        constraints.push(Constraint::Length(3));
        header.push("NO");
    }
    constraints.extend([
        Constraint::Length(15),
        Constraint::Length(14),
        Constraint::Min(20),
    ]);
    header.extend(["COMMAND", "QUEUEDSINCE", "FILE"]);
    let table = Table::new(rows, constraints)
        .header(Row::new(header).style(queue_header_style(app.default_colors)))
        .column_spacing(0);
    frame.render_widget(table, area);
}

fn render_help(frame: &mut Frame<'_>, area: Rect, default_colors: bool) {
    let text = "NO              Unique clamd number\nCONNTIME        How long it is connected\nLIV             Total number of live threads\nIDL             Total number of idle threads\nQUEUE           Number of items in queue\nMAXQ            Maximum number of items observed in queue\nMEM             Total memory usage (if available)\nENGINE          Engine version\nDBVER           Database version\nDBTIME          Database publish time\nHOST            Which clamd; local means Unix socket\nPrimary threads Threadpool used to receive commands\nlive            Executing commands, or scanning\nidle            Waiting for commands, will exit after idle_timeout\nmax             Maximum number of threads configured for this pool\nQueue           Tasks queued for processing, but not picked up by a thread\nCOMMAND         Command this thread is executing\nQUEUEDSINCE     How long this task is executing\nFILE            Which file it is processing (if applicable)\nMem / Libc      Memory usage reported by libc\nPool            Memory usage reported by libclamav's pool";
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .style(if default_colors {
                Style::default()
            } else {
                Style::default().fg(Color::White)
            }),
        area,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let unavailable = app.daemons.iter().find(|daemon| daemon.status != "Online");
    let disconnected = app
        .daemons
        .iter()
        .filter(|daemon| daemon.status != "Online")
        .count();
    let text = if app.show_help {
        "Press any key to exit help".to_string()
    } else {
        let status = unavailable.map_or_else(String::new, |daemon| {
            format!("{}: {}   ", daemon.endpoint, daemon.status)
        });
        let mut controls = "H - help   Q - quit   R - reset maximums".to_string();
        if app.daemons.len() > 1 {
            controls.push_str("   ↑ - previous clamd   ↓ - next clamd");
        }
        format!("{status}{controls}")
    };
    frame.render_widget(
        Paragraph::new(text).style(if disconnected > 0 {
            if app.default_colors {
                Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD)
            }
        } else {
            Style::default().add_modifier(Modifier::REVERSED)
        }),
        area,
    );
}

fn queue_header_style(default_colors: bool) -> Style {
    if default_colors {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::default().fg(Color::Black).bg(Color::Green)
    }
}

fn memory_line(section: &str, fields: &[(&str, String)], default_colors: bool) -> Line<'static> {
    let section_style = if default_colors {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    };
    let key_style = if default_colors {
        Style::default().add_modifier(Modifier::UNDERLINED)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };
    let separator_style = if default_colors {
        Style::default()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let mut spans = vec![Span::styled(format!("{section}: "), section_style)];
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ", separator_style));
        }
        spans.push(Span::styled((*key).to_string(), key_style));
        spans.push(Span::raw(" "));
        let value_style = if default_colors {
            Style::default().add_modifier(Modifier::BOLD)
        } else if value == "N/A" {
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::DIM)
        } else {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        };
        spans.push(Span::styled(value.clone(), value_style));
    }
    Line::from(spans)
}

fn selected_style(default_colors: bool) -> Style {
    if default_colors {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::default().fg(Color::Black).bg(Color::Cyan)
    }
}
fn memory_bar_total(memory: &MemoryStats) -> f64 {
    let total = memory.heap_mb.unwrap_or_default()
        + memory.mmap_mb.unwrap_or_default()
        + memory.pools_total_mb.unwrap_or_default();
    if total.is_finite() && total > 0.0 {
        total
    } else {
        0.0
    }
}
fn format_memory(memory: &MemoryStats) -> String {
    let Some(total) = total_memory_mb(memory) else {
        return "N/A".to_string();
    };
    if total >= 1024.0 {
        format!("{:.1}G", total / 1024.0)
    } else if total <= 0.0 {
        "N/A".to_string()
    } else {
        format!("{total:.0}M")
    }
}
fn format_database_time(daemon: &DaemonStats) -> String {
    let parts: Vec<_> = daemon.database_time.split_whitespace().collect();
    if parts.len() < 5 {
        return "N/A".to_string();
    }
    let month = match parts[1] {
        "Jan" => "01",
        "Feb" => "02",
        "Mar" => "03",
        "Apr" => "04",
        "May" => "05",
        "Jun" => "06",
        "Jul" => "07",
        "Aug" => "08",
        "Sep" => "09",
        "Oct" => "10",
        "Nov" => "11",
        "Dec" => "12",
        _ => return "N/A".to_string(),
    };
    let Ok(day) = parts[2].parse::<u8>() else {
        return "N/A".to_string();
    };
    let hour = parts[3].split(':').next().unwrap_or("00");
    format!("{}-{month}-{day:02}T{hour}", parts[4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_ipv4_ipv6_and_unix_endpoints() {
        assert_eq!(
            parse_endpoint("clamd.example").unwrap(),
            Endpoint::Tcp {
                host: "clamd.example".into(),
                port: 3310
            }
        );
        assert_eq!(
            parse_endpoint("127.0.0.1:3320").unwrap(),
            Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 3320
            }
        );
        assert_eq!(
            parse_endpoint("[::1]:3311").unwrap(),
            Endpoint::Tcp {
                host: "::1".into(),
                port: 3311
            }
        );
        assert_eq!(
            parse_endpoint("::1").unwrap(),
            Endpoint::Tcp {
                host: "::1".into(),
                port: 3310
            }
        );
        assert!(parse_endpoint("localhost:0").is_err());
        assert!(parse_endpoint("[::1]:0").is_err());
        #[cfg(unix)]
        {
            assert_eq!(
                parse_endpoint("unix:/run/clamd.sock").unwrap(),
                Endpoint::Unix(PathBuf::from("/run/clamd.sock"))
            );
            assert!(parse_endpoint("unix:").is_err());
        }
    }

    #[test]
    fn parses_queue_and_thread_statistics() {
        let lines = vec![
            "STATE: PRIMARY".to_string(),
            "THREADS: live 3 idle 2 max 8".to_string(),
            "STATE: MULTISCAN".to_string(),
            "THREADS: live 4 idle 5 max 12".to_string(),
            "QUEUE: 4 items".to_string(),
            "\tSCAN 0.125 /var/tmp/sample file".to_string(),
        ];
        let mut stats = DaemonStats::new(&Endpoint::Tcp {
            host: "localhost".into(),
            port: 3310,
        });
        parse_stats(&lines, &mut stats);
        assert_eq!(
            (stats.primary_live, stats.primary_idle, stats.primary_max),
            (3, 2, 8)
        );
        assert_eq!(
            (
                stats.live,
                stats.idle,
                stats.max_threads,
                stats.queue,
                stats.max_queue
            ),
            (7, 7, 20, 4, 4)
        );
        assert_eq!(stats.tasks.len(), 1);
        assert_eq!(stats.tasks[0].file, "/var/tmp/sample file");
    }

    #[test]
    fn formats_primary_thread_counts_without_extra_separators() {
        assert_eq!(format_thread_counts(10, 9, 10), "live 10 idle  9 max 10");
        assert_eq!(format_thread_counts(1, 0, 10), "live  1 idle  0 max 10");
    }

    #[test]
    fn sizes_the_memory_panel_to_its_content() {
        let panel = memory_panel_area(Rect::new(0, 0, 120, 11), 36).unwrap();
        assert_eq!(panel, Rect::new(80, 1, 40, 6));
        // The panel interior is exactly the three text rows plus the two bar
        // brackets; it cannot leave a wider unused bar area on the right.
        assert_eq!(panel.width.saturating_sub(2), 36 + 2);
        assert!(memory_panel_area(Rect::new(0, 0, 84, 11), 36).is_none());
        assert!(memory_panel_area(Rect::new(0, 0, 120, 6), 36).is_none());
    }

    #[test]
    fn parses_memory_fields_and_version() {
        let memory = parse_memory(
            "heap 12M mmap 4M used 9M free 7M releasable 1M pools 3 pools_used 2M pools_total 8M",
        );
        assert_eq!(memory.heap_mb, Some(12.0));
        assert_eq!(memory.pools, Some(3));
        assert_eq!(memory.pools_total_mb, Some(8.0));
        let pool_only = parse_memory(
            "heap N/A mmap N/A used N/A free N/A releasable N/A pools 1 pools_used 972.994M pools_total 973.030M",
        );
        assert_eq!(pool_only.heap_mb, None);
        assert_eq!(pool_only.pools_used_mb, Some(972.994));
        assert_eq!(format_memory(&pool_only), "N/A");
        let mut stats = DaemonStats::new(&Endpoint::Tcp {
            host: "host".into(),
            port: 3310,
        });
        parse_version(
            "ClamAV: ClamAV 1.6.0/27650/Thu Oct 30 10:30:00 2026",
            &mut stats,
        );
        assert_eq!(stats.engine_version, "1.6.0");
        assert_eq!(stats.database_version, "27650");
        assert_eq!(format_database_time(&stats), "2026-10-30T10");
    }

    #[test]
    fn rejects_invalid_numbers_and_terminal_control_characters() {
        let memory = parse_memory("heap NaN mmap -1M pools 2 pools_total infM");
        assert_eq!(memory.heap_mb, None);
        assert_eq!(memory.mmap_mb, None);
        assert_eq!(memory.pools, Some(2));
        assert_eq!(memory.pools_total_mb, None);
        assert!(parse_task("SCAN NaN /tmp/file").is_none());
        let task = parse_task("SCAN 1.5 /tmp/\u{1b}[2J").unwrap();
        assert_eq!(task.file, "/tmp/�[2J");
    }

    #[test]
    fn sanitizes_all_version_fields_before_rendering() {
        let mut stats = DaemonStats::new(&Endpoint::Tcp {
            host: "localhost".into(),
            port: 3310,
        });
        parse_version(
            "ClamAV: ClamAV 1.6.0\u{1b}[2J/27650/Thu Oct 30 10:30:00 2026",
            &mut stats,
        );
        assert_eq!(stats.engine_version, "1.6.0�[2J");
        assert!(!stats.version_response.contains('\u{1b}'));
    }

    #[test]
    fn clears_absent_memory_from_a_new_stats_response() {
        let mut stats = DaemonStats::new(&Endpoint::Tcp {
            host: "localhost".into(),
            port: 3310,
        });
        parse_stats(
            &["MEMSTATS: heap 10M mmap 2M pools_total 3M".to_string()],
            &mut stats,
        );
        assert_eq!(stats.memory.heap_mb, Some(10.0));
        parse_stats(&["QUEUE: 1 items".to_string()], &mut stats);
        assert_eq!(stats.memory.heap_mb, None);
        assert_eq!(stats.memory.pools_total_mb, None);
    }

    #[test]
    fn recognizes_terminal_protocol_errors() {
        assert!(is_protocol_error("COMMAND UNAVAILABLE"));
        assert!(is_protocol_error("UNKNOWN COMMAND"));
        assert!(is_protocol_error("STATS ERROR"));
        assert!(!is_protocol_error("QUEUE: 1 items"));
    }

    #[test]
    fn stats_protocol_error_does_not_wait_for_end() {
        let mut reader = BufReader::new(&b"2: COMMAND UNAVAILABLE\n"[..]);
        let error = read_stats(&mut reader).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn stats_task_text_is_not_treated_as_a_protocol_error() {
        let mut reader = BufReader::new(&b"2: \tSCAN 1.0 /tmp/COMMAND UNAVAILABLE\n2: END\n"[..]);
        assert_eq!(
            read_stats(&mut reader).unwrap(),
            vec!["\tSCAN 1.0 /tmp/COMMAND UNAVAILABLE"]
        );
    }

    #[test]
    fn stats_task_with_non_utf8_filename_remains_usable() {
        let mut reader = BufReader::new(&b"2: \tSCAN 1.0 /tmp/\xff\n2: END\n"[..]);
        assert_eq!(read_stats(&mut reader).unwrap(), vec!["\tSCAN 1.0 /tmp/�"]);
    }

    #[test]
    fn coalesces_updates_when_the_terminal_is_not_draining_them() {
        let endpoint = Endpoint::Tcp {
            host: "localhost".into(),
            port: 3310,
        };
        let stats = DaemonStats::new(&endpoint);
        let (updates, receiver) = mpsc::sync_channel(1);
        assert!(publish_update(&updates, 0, 0, &stats));
        assert!(publish_update(&updates, 0, 0, &stats));
        assert!(receiver.try_recv().is_ok());
        drop(receiver);
        assert!(!publish_update(&updates, 0, 0, &stats));
    }

    #[test]
    fn applies_the_latest_requested_reset_once() {
        let endpoint = Endpoint::Tcp {
            host: "localhost".into(),
            port: 3310,
        };
        let mut stats = DaemonStats::new(&endpoint);
        stats.queue = 4;
        stats.max_queue = 9;
        stats.memory.pools_total_mb = Some(12.0);
        stats.memory_peak_mb = 21.0;
        let reset_generation = AtomicU64::new(1);
        let mut applied_reset_generation = 0;

        apply_requested_reset(&mut stats, &reset_generation, &mut applied_reset_generation);
        assert_eq!(applied_reset_generation, 1);
        assert_eq!(stats.max_queue, 4);
        assert_eq!(stats.memory_peak_mb, 12.0);

        stats.max_queue = 10;
        reset_generation.store(3, Ordering::Release);
        apply_requested_reset(&mut stats, &reset_generation, &mut applied_reset_generation);
        assert_eq!(applied_reset_generation, 3);
        assert_eq!(stats.max_queue, 4);
    }

    #[test]
    fn parses_actual_clamd_queue_and_idsession_response_lines() {
        let lines = vec![
            strip_session_prefix("2: STATE: VALID PRIMARY".to_string()),
            strip_session_prefix("2: THREADS: live 1  idle 0 max 10 idle-timeout 30".to_string()),
            strip_session_prefix("2: QUEUE: 0 items".to_string()),
            strip_session_prefix("2: MEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A pools 1 pools_used 972.994M pools_total 973.030M".to_string()),
        ];
        let mut stats = DaemonStats::new(&Endpoint::Tcp {
            host: "localhost".into(),
            port: 3310,
        });
        parse_stats(&lines, &mut stats);
        assert_eq!(stats.primary_live, 1);
        assert_eq!(stats.primary_max, 10);
        assert_eq!(stats.queue, 0);
        assert_eq!(stats.memory.pools, Some(1));
        assert_eq!(format_memory(&stats.memory), "N/A");
        assert_eq!(memory_bar_total(&stats.memory), 973.03);
    }

    #[test]
    fn accepts_commands_and_endpoint_selection() {
        let options = parse_cli(&["-d".into(), "localhost:3310".into()]).unwrap();
        assert!(options.default_colors);
        assert_eq!(options.endpoints.len(), 1);
    }

    #[test]
    fn reads_clamd_tcp_and_local_socket_settings() {
        let path =
            std::env::temp_dir().join(format!("clamdtop-config-{}.conf", std::process::id()));
        fs::write(&path, "# local clamd\nTCPAddr 127.0.0.1\nTCPSocket 3317\n").unwrap();
        let endpoints = endpoints_from_config(&path).unwrap();
        assert_eq!(
            endpoints,
            vec![Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 3317
            }]
        );

        fs::write(&path, "TCPAddr ::1\nTCPSocket 3317 # clamd port\n").unwrap();
        let endpoints = endpoints_from_config(&path).unwrap();
        assert_eq!(
            endpoints,
            vec![Endpoint::Tcp {
                host: "::1".into(),
                port: 3317
            }]
        );
        fs::write(&path, "TCPAddr localhost\nTCPSocket 0\n").unwrap();
        assert!(endpoints_from_config(&path).is_err());

        #[cfg(unix)]
        {
            fs::write(&path, "LocalSocket /var/run/clamd.sock\nTCPSocket 3317\n").unwrap();
            let endpoints = endpoints_from_config(&path).unwrap();
            assert_eq!(
                endpoints,
                vec![Endpoint::Unix(PathBuf::from("/var/run/clamd.sock"))]
            );
        }
        fs::remove_file(path).unwrap();
    }
}
