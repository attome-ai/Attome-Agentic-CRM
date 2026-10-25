//! AB7-T3: a process given a listening socket by its parent serves on it
//! without binding. The test re-runs its own binary as the child, hands it
//! the socket and connects through the parent's address; the child would
//! fail to bind that address itself, because the parent still holds it.
//!
//! Windows only here: the Unix half takes a descriptor the supervisor keeps
//! open across `exec`, which `std::process::Command` cannot do without
//! clearing `FD_CLOEXEC` through libc.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

#[cfg(windows)]
mod windows {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::{Command, Stdio};

    use attome::listener::{LISTEN_PROTOCOL_INFO_VAR, bind_or_inherit};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    const CHILD_ADDR_VAR: &str = "ATTOME_TEST_LISTENER_ADDR";

    /// The child half: run only by `inherits_listener_from_env`.
    #[test]
    #[ignore = "the child process of inherits_listener_from_env"]
    fn listener_child() {
        let Ok(addr) = std::env::var(CHILD_ADDR_VAR) else {
            return;
        };
        let (listener, inherited) = bind_or_inherit(&addr).expect("take the inherited socket");
        assert!(inherited, "the socket came from the parent, not a bind");
        listener.set_nonblocking(false).unwrap();
        let (mut stream, _) = listener.accept().expect("accept on the inherited socket");
        stream.write_all(b"served").unwrap();
    }

    #[test]
    fn inherits_listener_from_env() {
        let parent = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = parent.local_addr().unwrap().to_string();
        assert!(
            TcpListener::bind(&addr).is_err(),
            "the address is taken, so the child cannot bind it"
        );
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::listener_child",
                "--ignored",
                "--nocapture",
            ])
            .env(LISTEN_PROTOCOL_INFO_VAR, "-")
            .env(CHILD_ADDR_VAR, &addr)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("start the child");
        let info = attome::listener::windows::duplicate_for(&parent, child.id())
            .expect("duplicate the socket for the child");
        writeln!(child.stdin.take().unwrap(), "{}", STANDARD.encode(info)).unwrap();

        let mut stream = TcpStream::connect(&addr).unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        assert_eq!(answer, "served");
        assert!(child.wait().unwrap().success(), "the child test passed");
    }
}
