//! AB7-T4: `attome supervise` replaces its server without refusing a
//! request. The supervisor runs this test binary's `stub_child` as its
//! server: a tiny HTTP responder on the inherited socket that answers with
//! its process id and stops when its stdin closes. Requests run before,
//! during and after a `POST /restart`, and every one must be answered 200,
//! by both the old and the new server.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "supervisor-test-token-0123456789";

/// The server half: run only by `supervisor_restart_keeps_serving`.
#[test]
#[ignore = "the server process of supervisor_restart_keeps_serving"]
fn stub_child() {
    if std::env::var(attome::cmd::supervise::SUPERVISED_VAR).as_deref() != Ok("1") {
        return;
    }
    let (listener, inherited) =
        attome::listener::bind_or_inherit("127.0.0.1:0").expect("take the inherited socket");
    assert!(inherited, "the socket came from the supervisor");
    listener.set_nonblocking(false).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let body = std::process::id().to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    let mut out = std::io::stdout();
    writeln!(out, "{}", attome::cmd::supervise::READY_LINE).unwrap();
    out.flush().unwrap();
    // The supervisor closes stdin when this server is to stop.
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}

fn free_addr() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

/// One raw HTTP exchange: the status line and the body.
fn exchange(addr: &str, request: &str) -> (String, String) {
    let mut stream = TcpStream::connect(addr).expect("the port is open");
    stream
        .set_read_timeout(Some(Duration::from_secs(150)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let status = answer.lines().next().unwrap_or_default().to_owned();
    let body = answer
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

fn get(addr: &str) -> (String, String) {
    exchange(addr, "GET / HTTP/1.1\r\nHost: test\r\n\r\n")
}

#[test]
fn supervisor_restart_keeps_serving() {
    let dir = std::env::temp_dir().join(format!("supervisor-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_file = dir.join("token");
    std::fs::write(&token_file, TOKEN).unwrap();
    let (listen, control) = (free_addr(), free_addr());
    let test_exe = std::env::current_exe().unwrap();
    let mut supervisor = Command::new(env!("CARGO_BIN_EXE_attome"))
        .arg("supervise")
        .args(["--listen", &listen, "--control-addr", &control])
        .arg("--token-file")
        .arg(&token_file)
        .arg("--server-exe")
        .arg(&test_exe)
        .args([
            "--child-arg",
            "--exact",
            "--child-arg",
            "stub_child",
            "--child-arg",
            "--ignored",
            "--child-arg",
            "--nocapture",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .expect("start the supervisor");

    // Wait for the first server.
    let deadline = Instant::now() + Duration::from_secs(60);
    while TcpStream::connect(&control).is_err() {
        assert!(Instant::now() < deadline, "the supervisor never came up");
        std::thread::sleep(Duration::from_millis(100));
    }

    // A wrong token is refused and restarts nothing.
    let (status, _) = exchange(
        &control,
        "POST /restart HTTP/1.1\r\nHost: test\r\nx-supervisor-token: wrong\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert!(status.contains(" 401 "), "{status}");

    let mut pids = BTreeSet::new();
    let mut statuses = Vec::new();
    for _ in 0..50 {
        let (status, pid) = get(&listen);
        statuses.push(status);
        pids.insert(pid);
    }
    let restart = {
        let control = control.clone();
        std::thread::spawn(move || {
            exchange(
                &control,
                &format!(
                    "POST /restart HTTP/1.1\r\nHost: test\r\nx-supervisor-token: {TOKEN}\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                ),
            )
        })
    };
    // Requests keep going while the new server starts and the old one stops.
    while !restart.is_finished() {
        let (status, pid) = get(&listen);
        statuses.push(status);
        pids.insert(pid);
    }
    let (restart_status, _) = restart.join().unwrap();
    for _ in 0..150 {
        let (status, pid) = get(&listen);
        statuses.push(status);
        pids.insert(pid);
    }

    let _ = supervisor.kill();
    let _ = supervisor.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(restart_status.contains(" 200 "), "{restart_status}");
    let refused: Vec<&String> = statuses.iter().filter(|s| !s.contains(" 200 ")).collect();
    assert!(
        refused.is_empty(),
        "every request was answered: {refused:?}"
    );
    assert!(statuses.len() >= 200, "{} requests", statuses.len());
    assert!(
        pids.len() >= 2,
        "both the old and the new server answered: {pids:?}"
    );
}
