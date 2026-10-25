//! AB7-T3: the server takes its listening socket from the process that
//! started it instead of binding, so a supervisor can hand the same socket to
//! the next version and no connection is refused while one replaces the
//! other.
//!
//! - Linux and other Unix: `ATTOME_LISTEN_FD` names an open listening
//!   socket's file descriptor the supervisor passed down.
//! - Windows: `ATTOME_LISTEN_PROTOCOL_INFO` is the base64 of the
//!   `WSAPROTOCOL_INFOW` the supervisor got from `WSADuplicateSocketW` for
//!   this process, or `-` to read that base64 from the first line of stdin
//!   (a supervisor only knows the process id, which `WSADuplicateSocketW`
//!   needs, once the process exists).
//!
//! Without either variable the server binds `addr` itself, as before. The
//! variable is left in place: removing it would mean `std::env::remove_var`
//! on a running multi-threaded runtime.

use std::io;
use std::net::TcpListener;

/// The Unix variable: the inherited socket's file descriptor.
pub const LISTEN_FD_VAR: &str = "ATTOME_LISTEN_FD";
/// The Windows variable: the inherited socket's protocol information.
pub const LISTEN_PROTOCOL_INFO_VAR: &str = "ATTOME_LISTEN_PROTOCOL_INFO";

/// The listening socket: inherited when the supervisor passed one, bound to
/// `addr` otherwise. Non-blocking, ready for `tokio::net::TcpListener::from_std`.
/// The flag says whether it was inherited.
pub fn bind_or_inherit(addr: &str) -> io::Result<(TcpListener, bool)> {
    let (listener, inherited) = match inherited()? {
        Some(listener) => (listener, true),
        None => (TcpListener::bind(addr)?, false),
    };
    listener.set_nonblocking(true)?;
    Ok((listener, inherited))
}

#[cfg(unix)]
fn inherited() -> io::Result<Option<TcpListener>> {
    use std::os::fd::FromRawFd;
    let Ok(raw) = std::env::var(LISTEN_FD_VAR) else {
        return Ok(None);
    };
    let fd: std::os::fd::RawFd = raw.trim().parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{LISTEN_FD_VAR} is not a file descriptor number"),
        )
    })?;
    #[allow(
        unsafe_code,
        reason = "taking ownership of a descriptor the supervisor passed"
    )]
    // SAFETY: the supervisor opened this listening socket and passed its
    // descriptor to this process alone; nothing else in the process holds it,
    // so the listener becomes its only owner from here on.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    // A descriptor that is not a socket fails here rather than at accept.
    listener.local_addr()?;
    Ok(Some(listener))
}

#[cfg(windows)]
fn inherited() -> io::Result<Option<TcpListener>> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    let Ok(value) = std::env::var(LISTEN_PROTOCOL_INFO_VAR) else {
        return Ok(None);
    };
    let encoded = if value.trim() == "-" {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line
    } else {
        value
    };
    let bytes = STANDARD.decode(encoded.trim()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{LISTEN_PROTOCOL_INFO_VAR} is not base64"),
        )
    })?;
    windows::socket_from_protocol_info(&bytes).map(Some)
}

#[cfg(not(any(unix, windows)))]
fn inherited() -> io::Result<Option<TcpListener>> {
    Ok(None)
}

#[cfg(windows)]
pub mod windows {
    //! The WinSock half: a socket's protocol information as bytes, and a
    //! listener rebuilt from them.

    use std::io;
    use std::net::TcpListener;
    use std::os::windows::io::{AsRawSocket, FromRawSocket};

    use windows_sys::Win32::Networking::WinSock::{
        FROM_PROTOCOL_INFO, INVALID_SOCKET, WSA_FLAG_OVERLAPPED, WSADATA, WSADuplicateSocketW,
        WSAGetLastError, WSAPROTOCOL_INFOW, WSASocketW, WSAStartup,
    };

    const INFO_LEN: usize = std::mem::size_of::<WSAPROTOCOL_INFOW>();

    fn last_error(what: &str) -> io::Error {
        #[allow(unsafe_code, reason = "reading WinSock's thread-local error code")]
        // SAFETY: WSAGetLastError takes no arguments and only reads the
        // calling thread's last WinSock error.
        let code = unsafe { WSAGetLastError() };
        io::Error::other(format!("{what} failed with WinSock error {code}"))
    }

    /// WinSock must be started before a raw call; `std` starts it lazily on
    /// its own first socket, which may not have happened yet. Calls nest.
    fn start_winsock() -> io::Result<()> {
        let mut data = std::mem::MaybeUninit::<WSADATA>::zeroed();
        #[allow(unsafe_code, reason = "starting WinSock before a raw socket call")]
        // SAFETY: `data` is a writable WSADATA WSAStartup fills in; version
        // 2.2 is the one std itself requests.
        let started = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
        if started == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "WSAStartup failed with WinSock error {started}"
            )))
        }
    }

    /// The protocol information that lets process `pid` open `listener`'s
    /// socket, as bytes (what a supervisor base64-encodes for the child).
    pub fn duplicate_for(listener: &TcpListener, pid: u32) -> io::Result<Vec<u8>> {
        start_winsock()?;
        let mut info = std::mem::MaybeUninit::<WSAPROTOCOL_INFOW>::zeroed();
        #[allow(
            unsafe_code,
            reason = "WSADuplicateSocketW fills a protocol info struct"
        )]
        // SAFETY: the socket is a live listener this process owns, and `info`
        // is a writable WSAPROTOCOL_INFOW.
        let done = unsafe {
            WSADuplicateSocketW(listener.as_raw_socket() as usize, pid, info.as_mut_ptr())
        };
        if done != 0 {
            return Err(last_error("WSADuplicateSocketW"));
        }
        #[allow(unsafe_code, reason = "viewing the filled struct as its bytes")]
        // SAFETY: WSADuplicateSocketW succeeded, so `info` is initialised; a
        // WSAPROTOCOL_INFOW is plain data, readable as INFO_LEN bytes.
        let bytes =
            unsafe { std::slice::from_raw_parts(info.as_ptr().cast::<u8>(), INFO_LEN).to_vec() };
        Ok(bytes)
    }

    /// A listener opened from protocol information `WSADuplicateSocketW`
    /// produced for this process.
    pub fn socket_from_protocol_info(bytes: &[u8]) -> io::Result<TcpListener> {
        if bytes.len() != INFO_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is {} bytes, not a WSAPROTOCOL_INFOW ({INFO_LEN})",
                    super::LISTEN_PROTOCOL_INFO_VAR,
                    bytes.len()
                ),
            ));
        }
        start_winsock()?;
        #[allow(unsafe_code, reason = "rebuilding the struct from its bytes")]
        // SAFETY: `bytes` has exactly the struct's size (checked above) and
        // WSAPROTOCOL_INFOW is plain data with no invalid bit patterns;
        // read_unaligned does not need the slice to be aligned.
        let info: WSAPROTOCOL_INFOW =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<WSAPROTOCOL_INFOW>()) };
        #[allow(unsafe_code, reason = "opening the duplicated socket")]
        // SAFETY: `info` is valid for the call; FROM_PROTOCOL_INFO takes the
        // family, type and protocol from it.
        let socket = unsafe {
            WSASocketW(
                FROM_PROTOCOL_INFO,
                FROM_PROTOCOL_INFO,
                FROM_PROTOCOL_INFO,
                &info,
                0,
                WSA_FLAG_OVERLAPPED,
            )
        };
        if socket == INVALID_SOCKET {
            return Err(last_error("WSASocketW"));
        }
        #[allow(
            unsafe_code,
            reason = "taking ownership of the socket WSASocketW opened"
        )]
        // SAFETY: WSASocketW returned a new socket handle that nothing else in
        // this process holds; the listener becomes its only owner.
        let listener = unsafe { TcpListener::from_raw_socket(socket as u64) };
        listener.local_addr()?;
        Ok(listener)
    }
}
