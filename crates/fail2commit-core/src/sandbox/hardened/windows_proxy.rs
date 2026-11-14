//! TCP loopback transport for the shared SPEC-018 egress policy.
//!
//! This transport is deliberately not wired into hardened job launch yet:
//! Internet jobs remain unavailable until per-package WFP loopback allowance
//! and the complete direct-route refusal probe are implemented and verified.

#![allow(dead_code)]

use crate::isolation::ActivityKind;
use crate::sandbox::bait::BaitSet;
use crate::sandbox::egress::{all_public, find_head_end, has_bait, Request, Watch};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY_INSPECT: usize = 8 * 1024;
const MAX_RESOLVED_ADDRESSES: usize = 32;
const MAX_CONNECTIONS: usize = 64;
const MAX_TUNNEL_BYTES: u64 = 512 * 1024 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(30 * 60);
const ACCEPT_POLL: Duration = Duration::from_millis(10);
const IO_POLL: Duration = Duration::from_millis(50);
const WRITE_TIMEOUT: Duration = Duration::from_millis(250);
const IO_CHUNK: usize = 16 * 1024;

type Resolver = dyn Fn(&str, u16, Instant, &AtomicBool) -> Option<Vec<SocketAddr>> + Send + Sync;
type Connector = dyn Fn(SocketAddr, Duration) -> io::Result<TcpStream> + Send + Sync;

struct DnsRequest {
    host: String,
    port: u16,
    result: mpsc::Sender<Option<Vec<SocketAddr>>>,
}

struct DnsPool {
    senders: [mpsc::SyncSender<DnsRequest>; 2],
    next: AtomicUsize,
}

static DNS_POOL: OnceLock<Option<DnsPool>> = OnceLock::new();

fn dns_pool() -> Option<&'static DnsPool> {
    DNS_POOL
        .get_or_init(|| {
            let mut senders = Vec::with_capacity(2);
            for slot in 0..2 {
                let (sender, receiver) = mpsc::sync_channel::<DnsRequest>(1);
                let started = thread::Builder::new()
                    .name(format!("f2c-hardened-dns-{slot}"))
                    .spawn(move || {
                        while let Ok(request) = receiver.recv() {
                            let result =
                                crate::sandbox::egress::resolve(&request.host, request.port);
                            let _ = request.result.send(result);
                        }
                    });
                if started.is_err() {
                    return None;
                }
                // These two bounded workers intentionally live for the process
                // lifetime: Windows name resolution is not cancellable through
                // ToSocketAddrs, and per-request detached resolver threads would
                // make proxy teardown unbounded.
                senders.push(sender);
            }
            let senders: [mpsc::SyncSender<DnsRequest>; 2] = senders.try_into().ok()?;
            Some(DnsPool {
                senders,
                next: AtomicUsize::new(0),
            })
        })
        .as_ref()
}

fn resolve_bounded(
    host: &str,
    port: u16,
    deadline: Instant,
    stop: &AtomicBool,
) -> Option<Vec<SocketAddr>> {
    let pool = dns_pool()?;
    let (result, receiver) = mpsc::channel();
    let request = DnsRequest {
        host: host.to_owned(),
        port,
        result,
    };
    let first = pool.next.fetch_add(1, Ordering::Relaxed) % pool.senders.len();
    let mut queued = false;
    for offset in 0..pool.senders.len() {
        match pool.senders[(first + offset) % pool.senders.len()].try_send(DnsRequest {
            host: request.host.clone(),
            port: request.port,
            result: request.result.clone(),
        }) {
            Ok(()) => {
                queued = true;
                break;
            }
            Err(mpsc::TrySendError::Full(_)) => {}
            Err(mpsc::TrySendError::Disconnected(_)) => continue,
        }
    }
    if !queued {
        return None;
    }
    loop {
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match receiver.recv_timeout(remaining.min(IO_POLL)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

/// A job-scoped proxy bound only to IPv4 loopback on an ephemeral port.
/// Dropping it closes the listener and every accepted/upstream socket, then
/// joins its bounded workers before returning the shared activity report.
pub(crate) struct Egress {
    address: SocketAddr,
    watch: Arc<Watch>,
    stop: Arc<AtomicBool>,
    sockets: Arc<SocketRegistry>,
    accept_thread: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Egress {
    pub(crate) fn port(&self) -> u16 {
        self.address.port()
    }

    pub(crate) fn environment(&self) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        let url = format!("http://{}:{}", self.address.ip(), self.address.port());
        [
            ("HTTP_PROXY", url.as_str()),
            ("HTTPS_PROXY", url.as_str()),
            ("ALL_PROXY", url.as_str()),
            ("NO_PROXY", ""),
            ("http_proxy", url.as_str()),
            ("https_proxy", url.as_str()),
            ("all_proxy", url.as_str()),
            ("no_proxy", ""),
            ("npm_config_proxy", url.as_str()),
            ("npm_config_https_proxy", url.as_str()),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect()
    }

    pub(crate) fn report(&self) -> crate::isolation::ActivityReport {
        self.watch.take_report()
    }

    pub(crate) fn tripped(&self) -> bool {
        self.watch.tripped()
    }
}

impl Drop for Egress {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.sockets.shutdown_all();
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
        let workers = std::mem::take(
            &mut *self
                .workers
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        );
        for worker in workers {
            let _ = worker.join();
        }
    }
}

#[derive(Default)]
struct SocketState {
    closed: bool,
    sockets: HashMap<u64, TcpStream>,
}

#[derive(Default)]
struct SocketRegistry {
    next_id: AtomicU64,
    state: Mutex<SocketState>,
}

struct SocketRegistration {
    id: u64,
    registry: Arc<SocketRegistry>,
}

impl SocketRegistry {
    fn register(self: &Arc<Self>, stream: &TcpStream) -> io::Result<SocketRegistration> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.closed {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "proxy is stopping",
            ));
        }
        let clone = stream.try_clone()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        state.sockets.insert(id, clone);
        Ok(SocketRegistration {
            id,
            registry: Arc::clone(self),
        })
    }

    fn connect_registered(
        self: &Arc<Self>,
        address: SocketAddr,
        timeout: Duration,
        connector: &Connector,
    ) -> io::Result<(TcpStream, SocketRegistration)> {
        // Holding the same lock used to linearize cancellation ensures a
        // connector cannot begin after shutdown/bait cancellation is committed.
        // Connector implementations have a strict timeout.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "proxy is stopping",
            ));
        }
        let stream = connector(address, timeout)?;
        let clone = stream.try_clone()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        state.sockets.insert(id, clone);
        Ok((
            stream,
            SocketRegistration {
                id,
                registry: Arc::clone(self),
            },
        ))
    }

    fn write_if_open(&self, stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "proxy is stopping",
            ));
        }
        stream.write_all(bytes)
    }

    fn shutdown_all(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.closed = true;
        for stream in state.sockets.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn shutdown_except(&self, keep: &TcpStream) {
        let keep_local = keep.local_addr().ok();
        let keep_peer = keep.peer_addr().ok();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.closed = true;
        for stream in state.sockets.values() {
            if stream.local_addr().ok() == keep_local && stream.peer_addr().ok() == keep_peer {
                continue;
            }
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for SocketRegistration {
    fn drop(&mut self) {
        self.registry
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .sockets
            .remove(&self.id);
    }
}

pub(crate) fn start(watch: Arc<Watch>, bait: Option<Arc<BaitSet>>) -> crate::Result<Egress> {
    start_with(
        watch,
        bait,
        Arc::new(resolve_bounded),
        Arc::new(connect_one),
    )
}

fn start_with(
    watch: Arc<Watch>,
    bait: Option<Arc<BaitSet>>,
    resolver: Arc<Resolver>,
    connector: Arc<Connector>,
) -> crate::Result<Egress> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
        return Err(crate::Error::isolation_unavailable(
            "hardened egress proxy did not bind IPv4 loopback",
        ));
    }
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let sockets = Arc::new(SocketRegistry::default());
    let workers = Arc::new(Mutex::new(Vec::new()));
    let accept_thread = {
        let stop = Arc::clone(&stop);
        let sockets = Arc::clone(&sockets);
        let workers = Arc::clone(&workers);
        let watch = Arc::clone(&watch);
        thread::Builder::new()
            .name("f2c-hardened-egress".into())
            .spawn(move || {
                accept_loop(
                    listener, stop, sockets, workers, watch, bait, resolver, connector,
                )
            })?
    };
    Ok(Egress {
        address,
        watch,
        stop,
        sockets,
        accept_thread: Some(accept_thread),
        workers,
    })
}

fn accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    sockets: Arc<SocketRegistry>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    watch: Arc<Watch>,
    bait: Option<Arc<BaitSet>>,
    resolver: Arc<Resolver>,
    connector: Arc<Connector>,
) {
    let live = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) && !watch.tripped() {
        reap_finished_workers(&workers);
        match listener.accept() {
            Ok((mut client, _peer)) => {
                let count = live.fetch_add(1, Ordering::SeqCst) + 1;
                if count > MAX_CONNECTIONS {
                    live.fetch_sub(1, Ordering::SeqCst);
                    sockets.shutdown_all();
                    watch.trip(
                        ActivityKind::Limit,
                        "egress proxy connection limit exceeded",
                    );
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
                if client.set_nodelay(true).is_err()
                    || client.set_read_timeout(Some(IO_POLL)).is_err()
                    || client.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
                {
                    live.fetch_sub(1, Ordering::SeqCst);
                    watch.record(ActivityKind::NetRefused, "egress client setup failed");
                    continue;
                }
                let registration = match sockets.register(&client) {
                    Ok(registration) => registration,
                    Err(_) => {
                        live.fetch_sub(1, Ordering::SeqCst);
                        watch.record(
                            ActivityKind::NetRefused,
                            "egress client registration failed",
                        );
                        continue;
                    }
                };
                let thread_watch = Arc::clone(&watch);
                let thread_bait = bait.clone();
                let thread_stop = Arc::clone(&stop);
                let thread_sockets = Arc::clone(&sockets);
                let thread_live = Arc::clone(&live);
                let thread_resolver = Arc::clone(&resolver);
                let thread_connector = Arc::clone(&connector);
                let worker = thread::spawn(move || {
                    let _client_registration = registration;
                    let _ = handle_connection(
                        &mut client,
                        thread_watch,
                        thread_bait.as_deref(),
                        thread_resolver.as_ref(),
                        thread_connector.as_ref(),
                        thread_stop,
                        thread_sockets,
                    );
                    thread_live.fetch_sub(1, Ordering::SeqCst);
                });
                workers
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push(worker);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(_) => {
                sockets.shutdown_all();
                watch.trip(ActivityKind::NetRefused, "egress proxy listener failed");
                stop.store(true, Ordering::SeqCst);
                break;
            }
        }
    }
    reap_finished_workers(&workers);
}

fn reap_finished_workers(workers: &Mutex<Vec<JoinHandle<()>>>) {
    let mut handles = workers.lock().unwrap_or_else(|poison| poison.into_inner());
    let mut index = 0;
    while index < handles.len() {
        if handles[index].is_finished() {
            let handle = handles.swap_remove(index);
            let _ = handle.join();
        } else {
            index += 1;
        }
    }
}

fn connect_one(address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    TcpStream::connect_timeout(&address, timeout)
}

fn handle_connection(
    client: &mut TcpStream,
    watch: Arc<Watch>,
    bait: Option<&BaitSet>,
    resolver: &Resolver,
    connector: &Connector,
    stop: Arc<AtomicBool>,
    sockets: Arc<SocketRegistry>,
) -> io::Result<()> {
    let request_deadline = Instant::now() + HEAD_TIMEOUT;
    let (head, initial_body) = match read_request(client, &stop, request_deadline) {
        Ok(request) => request,
        Err(_) => {
            watch.record(
                ActivityKind::NetRefused,
                "malformed or timed-out proxy request",
            );
            return refuse(client, "400 Bad Request", "malformed proxy request");
        }
    };
    let Some(request) = Request::parse(&head) else {
        watch.record(ActivityKind::NetRefused, "malformed proxy request");
        return refuse(client, "400 Bad Request", "malformed proxy request");
    };
    if request.port == 0
        || request.host.contains('@')
        || request.host.chars().any(char::is_whitespace)
    {
        watch.record(ActivityKind::NetRefused, "malformed proxy destination");
        return refuse(client, "400 Bad Request", "malformed proxy destination");
    }
    if has_bait(bait, &head, &initial_body) {
        // Do not include the bait value or hostname in the report.
        sockets.shutdown_except(client);
        watch.trip(ActivityKind::Bait, "egress proxy detected a bait value");
        stop.store(true, Ordering::SeqCst);
        return refuse(
            client,
            "403 Forbidden",
            "blocked by the fail2commit bait policy",
        );
    }
    let Some(targets) = resolver(
        &request.host,
        request.port,
        Instant::now() + RESOLVE_TIMEOUT,
        &stop,
    ) else {
        watch.record(
            ActivityKind::NetRefused,
            "proxy destination did not resolve",
        );
        return refuse(client, "403 Forbidden", "destination did not resolve");
    };
    if stop.load(Ordering::SeqCst) || watch.tripped() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "proxy is stopping",
        ));
    }
    if targets.len() > MAX_RESOLVED_ADDRESSES || !all_public(&targets) {
        watch.record(ActivityKind::NetRefused, "proxy destination is not public");
        return refuse(
            client,
            "403 Forbidden",
            "only public internet addresses are allowed",
        );
    }
    let mut upstream = None;
    let mut upstream_registration = None;
    let connect_deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
    for address in targets {
        let timeout = connect_deadline.saturating_duration_since(std::time::Instant::now());
        if timeout.is_zero() || stop.load(Ordering::SeqCst) || watch.tripped() {
            break;
        }
        if let Ok((stream, registration)) = sockets.connect_registered(address, timeout, connector)
        {
            upstream = Some(stream);
            upstream_registration = Some(registration);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        watch.record(
            ActivityKind::NetRefused,
            "public proxy destination was unreachable",
        );
        return refuse(client, "502 Bad Gateway", "destination unreachable");
    };
    upstream.set_nodelay(true)?;
    upstream.set_read_timeout(Some(IO_POLL))?;
    upstream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let _upstream_registration = upstream_registration.expect("registered with connect");
    let total = Arc::new(AtomicU64::new(0));
    let connection_deadline = Instant::now() + MAX_CONNECTION_LIFETIME;
    if request.method.eq_ignore_ascii_case("CONNECT") {
        if !initial_body.is_empty() {
            account_transfer(initial_body.len(), &total, &watch, &stop, &sockets)?;
            sockets.write_if_open(&mut upstream, &initial_body)?;
        }
        sockets.write_if_open(client, b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        watch.record(ActivityKind::NetAllowed, request.authority());
        return tunnel(
            client,
            &mut upstream,
            total,
            watch,
            stop,
            sockets,
            connection_deadline,
        );
    }
    let forwarded_head = match forward_http_head(&head) {
        Ok(head) => head,
        Err(_) => {
            watch.record(ActivityKind::NetRefused, "malformed absolute HTTP request");
            return refuse(client, "400 Bad Request", "malformed proxy request");
        }
    };
    sockets.write_if_open(&mut upstream, &forwarded_head)?;
    if !initial_body.is_empty() {
        sockets.write_if_open(&mut upstream, &initial_body)?;
    }
    watch.record(ActivityKind::NetAllowed, request.authority());
    // One plain HTTP request per client connection. Do not tunnel later client
    // bytes, which could hide a second uninspected request after the bait scan.
    upstream.shutdown(Shutdown::Write)?;
    copy_limited(
        &mut upstream,
        client,
        &total,
        &watch,
        &stop,
        &sockets,
        connection_deadline,
    )?;
    Ok(())
}

fn read_request(
    stream: &mut TcpStream,
    stop: &AtomicBool,
    deadline: Instant,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut received = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    while received.len() < MAX_HEAD {
        let count = chunk.len().min(MAX_HEAD - received.len());
        let n = read_cancellable(stream, &mut chunk[..count], stop, deadline)?;
        if n == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..n]);
        if find_head_end(&received).is_some() {
            break;
        }
    }
    let Some(end) = find_head_end(&received) else {
        return Ok((received, Vec::new()));
    };
    let head = received[..end].to_vec();
    let mut body = received[end..].to_vec();
    let request_line_is_connect = received[..end]
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|line| line.split_ascii_whitespace().next())
        .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"));
    if request_line_is_connect {
        return Ok((head, body));
    }
    if body.len() > MAX_BODY_INSPECT {
        body.truncate(MAX_BODY_INSPECT);
    }
    let content_length = request_body_length(&head)?;
    if let Some(content_length) = content_length {
        if content_length > MAX_BODY_INSPECT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request body exceeds inspection limit",
            ));
        }
        if body.len() > content_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pipelined request bytes are not accepted",
            ));
        }
        let inspect_target = content_length;
        while body.len() < inspect_target {
            let remaining = inspect_target - body.len();
            let mut buffer = vec![0u8; remaining.min(1024)];
            let n = read_cancellable(stream, &mut buffer, stop, deadline)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buffer[..n]);
        }
        if body.len() != content_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request body ended before Content-Length",
            ));
        }
    } else if !body.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unframed HTTP request body is not accepted",
        ));
    }
    Ok((head, body))
}

fn read_cancellable(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> io::Result<usize> {
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "proxy is stopping",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request deadline elapsed",
            ));
        }
        match stream.read(buffer) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            result => return result,
        }
    }
}

fn request_body_length(head: &[u8]) -> io::Result<Option<usize>> {
    let text = std::str::from_utf8(head)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP head is not UTF-8"))?;
    let mut content_length = None;
    for line in text.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Content-Length is not accepted",
                ));
            }
            content_length = Some(value.trim().parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length")
            })?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Transfer-Encoding is not accepted",
            ));
        }
    }
    Ok(content_length)
}

fn forward_http_head(head: &[u8]) -> io::Result<Vec<u8>> {
    let end = find_head_end(head)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP head is incomplete"))?;
    let text = std::str::from_utf8(&head[..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP head is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "HTTP request line is missing")
    })?;
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP method is missing"))?;
    let target = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP target is missing"))?;
    let version = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP version is missing"))?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request line is malformed",
        ));
    }
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "only absolute HTTP URIs are accepted",
            )
        })?;
    let after_authority = rest
        .find(['/', '?', '#'])
        .map(|index| &rest[index..])
        .unwrap_or("/");
    if after_authority.starts_with('#') || after_authority.contains('#') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP fragments are not sent to the origin",
        ));
    }
    let origin = if after_authority.starts_with('?') {
        format!("/{after_authority}")
    } else {
        after_authority.to_owned()
    };
    let mut output = format!("{method} {origin} {version}\r\n").into_bytes();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line
            .split_once(':')
            .map(|(name, _)| name.trim().to_ascii_lowercase());
        if matches!(
            lower.as_deref(),
            Some("proxy-authorization" | "proxy-connection" | "connection")
        ) {
            continue;
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(output)
}

fn tunnel(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    total: Arc<AtomicU64>,
    watch: Arc<Watch>,
    stop: Arc<AtomicBool>,
    sockets: Arc<SocketRegistry>,
    deadline: Instant,
) -> io::Result<()> {
    client.set_read_timeout(Some(IO_POLL))?;
    client.set_write_timeout(Some(WRITE_TIMEOUT))?;
    upstream.set_read_timeout(Some(IO_POLL))?;
    upstream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let thread_total = Arc::clone(&total);
    let thread_stop = Arc::clone(&stop);
    let thread_watch = Arc::clone(&watch);
    let thread_sockets = Arc::clone(&sockets);
    let upload = thread::spawn(move || {
        copy_limited(
            &mut client_read,
            &mut upstream_write,
            &thread_total,
            &thread_watch,
            &thread_stop,
            &thread_sockets,
            deadline,
        )
    });
    let download = copy_limited(upstream, client, &total, &watch, &stop, &sockets, deadline);
    let _ = client.shutdown(Shutdown::Write);
    let upload = upload.join().unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "proxy upload worker panicked",
        ))
    });
    download.and(upload)
}

fn copy_limited(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    total: &AtomicU64,
    watch: &Watch,
    stop: &AtomicBool,
    sockets: &SocketRegistry,
    deadline: Instant,
) -> io::Result<()> {
    let mut buffer = [0u8; IO_CHUNK];
    let mut idle_deadline = Instant::now() + IDLE_TIMEOUT;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline || now >= idle_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tunnel lifetime elapsed",
            ));
        }
        let n = match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = writer.shutdown(Shutdown::Write);
                return Ok(());
            }
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        };
        idle_deadline = Instant::now() + IDLE_TIMEOUT;
        account_transfer(n, total, watch, stop, sockets)?;
        sockets.write_if_open(writer, &buffer[..n])?;
    }
}

fn account_transfer(
    n: usize,
    total: &AtomicU64,
    watch: &Watch,
    stop: &AtomicBool,
    sockets: &SocketRegistry,
) -> io::Result<()> {
    let after = total.fetch_add(n as u64, Ordering::SeqCst) + n as u64;
    if after > MAX_TUNNEL_BYTES {
        sockets.shutdown_all();
        watch.trip(ActivityKind::Limit, "egress proxy transfer limit exceeded");
        stop.store(true, Ordering::SeqCst);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "proxy transfer limit exceeded",
        ));
    }
    Ok(())
}

fn refuse(client: &mut TcpStream, status: &str, why: &str) -> io::Result<()> {
    let body = format!("fail2commit sandbox egress proxy: {why}\n");
    write!(
        client,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    client.shutdown(Shutdown::Both)
}

#[cfg(test)]
fn start_fixture(
    watch: Arc<Watch>,
    bait: Option<Arc<BaitSet>>,
    resolver: Arc<Resolver>,
    connector: Arc<Connector>,
) -> crate::Result<Egress> {
    start_with(watch, bait, resolver, connector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Condvar;

    fn proxy_to_fixture(
        upstream: SocketAddr,
        watch: Arc<Watch>,
        bait: Option<Arc<BaitSet>>,
    ) -> Egress {
        let resolve: Arc<Resolver> = Arc::new(|_host, port, _deadline, _stop| {
            Some(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(104, 16, 0, 35)),
                port,
            )])
        });
        let connect: Arc<Connector> =
            Arc::new(move |_address, _timeout| TcpStream::connect(upstream));
        start_fixture(watch, bait, resolve, connect).unwrap()
    }

    #[test]
    fn http_absolute_form_is_forwarded_to_fixture_as_origin_form() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let fixture = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                assert_eq!(stream.read(&mut byte).unwrap(), 1);
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET /item?q=1 HTTP/1.1\r\n"));
            assert!(!request
                .windows(b"proxy-authorization".len())
                .any(|window| window == b"proxy-authorization"));
            assert!(request
                .windows(b"Connection: close".len())
                .any(|window| window == b"Connection: close"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        let watch = Arc::new(Watch::default());
        let proxy = proxy_to_fixture(upstream_address, Arc::clone(&watch), None);
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .write_all(format!(
                "GET http://fixture.invalid:{}/item?q=1 HTTP/1.1\r\nHost: fixture.invalid\r\nProxy-Authorization: secret\r\nConnection: keep-alive\r\n\r\n",
                upstream_address.port()
            ).as_bytes())
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.ends_with(b"ok"));
        fixture.join().unwrap();
        assert_eq!(watch.take_report().events[0].kind, ActivityKind::NetAllowed);
        drop(proxy);
    }

    #[test]
    fn connect_tunnel_forwards_bytes_and_propagates_half_close() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let fixture = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            assert_eq!(&bytes, b"hello!end");
            stream.write_all(b"world").unwrap();
            let _ = stream.shutdown(Shutdown::Write);
        });
        let watch = Arc::new(Watch::default());
        let proxy = proxy_to_fixture(upstream_address, Arc::clone(&watch), None);
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .write_all(
                format!(
                    "CONNECT fixture.invalid:{} HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n",
                    upstream_address.port()
                )
                .as_bytes(),
            )
            .unwrap();
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).unwrap();
            response.push(byte[0]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200 Connection Established"));
        client.write_all(b"hello").unwrap();
        client.write_all(b"!end").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut payload = Vec::new();
        client.read_to_end(&mut payload).unwrap();
        assert!(payload.ends_with(b"world"));
        fixture.join().unwrap();
        assert!(!proxy.tripped());
    }

    #[test]
    fn mixed_public_and_private_dns_answers_are_refused_without_connecting() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let watch = Arc::new(Watch::default());
        let resolve: Arc<Resolver> = Arc::new(move |_host, _port, _deadline, _stop| {
            Some(vec![
                "104.16.0.35:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap(),
            ])
        });
        let connect: Arc<Connector> =
            Arc::new(|_, _| panic!("private mixed answer must not connect"));
        let proxy = start_fixture(Arc::clone(&watch), None, resolve, connect).unwrap();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(client, "CONNECT example.invalid:{port} HTTP/1.1\r\n\r\n").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
        assert_eq!(watch.take_report().events[0].kind, ActivityKind::NetRefused);
    }

    #[test]
    fn request_framing_rejects_ambiguous_or_unsupported_bodies() {
        assert_eq!(
            request_body_length(
                b"POST http://example.invalid/ HTTP/1.1\r\nContent-Length: 4\r\n\r\n"
            )
            .unwrap(),
            Some(4)
        );
        assert!(request_body_length(
            b"POST http://example.invalid/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n"
        )
        .is_err());
        assert!(request_body_length(
            b"POST http://example.invalid/ HTTP/1.1\r\nContent-Length: nope\r\n\r\n"
        )
        .is_err());
        assert!(request_body_length(
            b"POST http://example.invalid/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        .is_err());
    }

    #[test]
    fn bait_host_trips_the_job_and_stops_proxy_connections() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let bait = Arc::new(BaitSet::generate().unwrap());
        let bait_host = bait.env[1].1.clone();
        let watch = Arc::new(Watch::default());
        let proxy = proxy_to_fixture(upstream_address, Arc::clone(&watch), Some(bait));
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(client, "CONNECT {bait_host}:443 HTTP/1.1\r\n\r\n").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
        assert!(proxy.tripped());
        let events = watch.take_report().events;
        assert_eq!(events[0].kind, ActivityKind::Bait);
        assert!(!events[0].detail.contains(&bait_host));
        drop(proxy);
    }

    #[test]
    fn bait_in_http_body_trips_before_any_upstream_connect() {
        let bait = Arc::new(BaitSet::generate().unwrap());
        let value = bait.env[1].1.clone();
        let watch = Arc::new(Watch::default());
        let resolve: Arc<Resolver> = Arc::new(|_host, port, _deadline, _stop| {
            Some(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(104, 16, 0, 35)),
                port,
            )])
        });
        let connect: Arc<Connector> =
            Arc::new(|_, _| panic!("bait body must be rejected before connect"));
        let proxy = start_fixture(Arc::clone(&watch), Some(bait), resolve, connect).unwrap();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            client,
            "POST http://fixture.invalid:80/upload HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            value.len(),
            value
        )
        .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
        assert!(proxy.tripped());
        let events = watch.take_report().events;
        assert_eq!(events[0].kind, ActivityKind::Bait);
        assert!(!events[0].detail.contains(&value));
    }

    #[test]
    fn bait_trip_cancels_a_resolver_before_upstream_connect() {
        let bait = Arc::new(BaitSet::generate().unwrap());
        let bait_host = bait.env[1].1.clone();
        let watch = Arc::new(Watch::default());
        let resolver_state = Arc::new((Mutex::new((false, false)), Condvar::new()));
        let resolver_state_worker = Arc::clone(&resolver_state);
        let resolve: Arc<Resolver> = Arc::new(move |_host, port, _deadline, stop| {
            let (gate, changed) = &*resolver_state_worker;
            let mut state = gate.lock().unwrap();
            state.0 = true;
            changed.notify_all();
            while !state.1 && !stop.load(Ordering::SeqCst) {
                state = changed.wait(state).unwrap();
            }
            Some(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(104, 16, 0, 35)),
                port,
            )])
        });
        let connects = Arc::new(AtomicUsize::new(0));
        let connects_for_connector = Arc::clone(&connects);
        let connector: Arc<Connector> = Arc::new(move |_address, _timeout| {
            connects_for_connector.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "fixture"))
        });
        let proxy = start_fixture(Arc::clone(&watch), Some(bait), resolve, connector).unwrap();

        let mut slow = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write!(slow, "CONNECT slow.invalid:443 HTTP/1.1\r\n\r\n").unwrap();
        {
            let (gate, changed) = &*resolver_state;
            let mut state = gate.lock().unwrap();
            while !state.0 {
                state = changed.wait(state).unwrap();
            }
        }

        let mut bait_client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        bait_client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(bait_client, "CONNECT {bait_host}:443 HTTP/1.1\r\n\r\n").unwrap();
        let mut reply = Vec::new();
        bait_client.read_to_end(&mut reply).unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let (gate, changed) = &*resolver_state;
        gate.lock().unwrap().1 = true;
        changed.notify_all();
        let mut canceled_reply = Vec::new();
        let _ = slow.read_to_end(&mut canceled_reply);
        assert_eq!(connects.load(Ordering::SeqCst), 0);
        drop(proxy);
    }

    #[test]
    fn dropping_proxy_cancels_a_slow_client_with_bounded_join() {
        let watch = Arc::new(Watch::default());
        let resolver: Arc<Resolver> = Arc::new(|_host, port, _deadline, _stop| {
            Some(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(104, 16, 0, 35)),
                port,
            )])
        });
        let connector: Arc<Connector> =
            Arc::new(|_, _| Err(io::Error::new(io::ErrorKind::ConnectionRefused, "unused")));
        let proxy = start_fixture(watch, None, resolver, connector).unwrap();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        client.write_all(b"C").unwrap();
        let accepted_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let accepted = proxy
                .sockets
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .sockets
                .len();
            if accepted > 0 {
                break;
            }
            assert!(
                Instant::now() < accepted_deadline,
                "client was not accepted"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let started = Instant::now();
        drop(proxy);
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = client.shutdown(Shutdown::Both);
    }

    #[test]
    fn request_deadline_is_monotonic_across_trickled_fragments() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..8 {
                let _ = stream.write_all(b"A");
                thread::sleep(Duration::from_millis(40));
            }
        });
        let mut client = TcpStream::connect(address).unwrap();
        client.set_read_timeout(Some(IO_POLL)).unwrap();
        let started = Instant::now();
        let result = read_request(
            &mut client,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_millis(150),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(400));
        sender.join().unwrap();
    }
}
