// SPDX-License-Identifier: Apache-2.0

//! Canaries for every ban in `clippy.toml`. Each function below calls one banned item under
//! `#[expect(...)]` and is never run. If a ban stops firing (its path no longer resolves, an item
//! moved upstream, a typo, a wrong kind, a first segment that names no crate), its expectation goes
//! unfulfilled, and `unfulfilled_lint_expectations` fails clippy under `-D warnings` on every
//! system that compiles the canary. Bans that exist only on some systems are compiled only there,
//! so each CI system proves its own. `cargo xtask allow-audit` keeps this file complete: it fails
//! on a ban in `clippy.toml` with no `// canary:` marker here, on a canary that does not spell its
//! item's own path in code (a method's full type path, an item in a module its whole path; a
//! module-level import does not count), and on one whose function also spells another ban of the
//! same lint by its full path (9 to 11; a ban reached through a module-level import or a shortened
//! path is not seen). `getrandom::fill` is not a dependency here; its canary lives in
//! `uaos-platform`'s tests.

#![allow(clippy::unwrap_used, reason = "test harness")]

mod canaries {
    #![allow(dead_code, reason = "canaries are compiled by clippy and never run")]

    use std::time::Duration;

    // ── Clocks, processes, files, environment ─────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn system_time_now() {
        // canary: `std::time::SystemTime::now`
        let _canary = std::time::SystemTime::now();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn instant_now() {
        // canary: `std::time::Instant::now`
        let _canary = std::time::Instant::now();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn thread_spawn() {
        // canary: `std::thread::spawn`
        let _canary = std::thread::spawn(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn command_new() {
        // canary: `std::process::Command::new`
        let _canary = std::process::Command::new("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_write() {
        // canary: `std::fs::write`
        let _canary = std::fs::write("canary", b"");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_read() {
        // canary: `std::fs::read`
        let _canary = std::fs::read("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_read_to_string() {
        // canary: `std::fs::read_to_string`
        let _canary = std::fs::read_to_string("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_remove_file() {
        // canary: `std::fs::remove_file`
        let _canary = std::fs::remove_file("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_rename() {
        // canary: `std::fs::rename`
        let _canary = std::fs::rename("canary", "canary2");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_create_dir_all() {
        // canary: `std::fs::create_dir_all`
        let _canary = std::fs::create_dir_all("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn file_create() {
        // canary: `std::fs::File::create`
        let _canary = std::fs::File::create("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn file_open() {
        // canary: `std::fs::File::open`
        let _canary = std::fs::File::open("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn open_options_open() {
        // canary: `std::fs::OpenOptions::open`
        let _canary = std::fs::OpenOptions::new().open("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_metadata() {
        // canary: `std::fs::metadata`
        let _canary = std::fs::metadata("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_symlink_metadata() {
        // canary: `std::fs::symlink_metadata`
        let _canary = std::fs::symlink_metadata("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_read_dir() {
        // canary: `std::fs::read_dir`
        let _canary = std::fs::read_dir("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_copy() {
        // canary: `std::fs::copy`
        let _canary = std::fs::copy("canary", "canary2");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_hard_link() {
        // canary: `std::fs::hard_link`
        let _canary = std::fs::hard_link("canary", "canary2");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_read_link() {
        // canary: `std::fs::read_link`
        let _canary = std::fs::read_link("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_canonicalize() {
        // canary: `std::fs::canonicalize`
        let _canary = std::fs::canonicalize("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_create_dir() {
        // canary: `std::fs::create_dir`
        let _canary = std::fs::create_dir("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_remove_dir() {
        // canary: `std::fs::remove_dir`
        let _canary = std::fs::remove_dir("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_remove_dir_all() {
        // canary: `std::fs::remove_dir_all`
        let _canary = std::fs::remove_dir_all("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_set_permissions(permissions: std::fs::Permissions) {
        // canary: `std::fs::set_permissions`
        let _canary = std::fs::set_permissions("canary", permissions);
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_exists() {
        // canary: `std::fs::exists`
        let _canary = std::fs::exists("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_file_create_new() {
        // canary: `std::fs::File::create_new`
        let _canary = std::fs::File::create_new("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn fs_dirbuilder_create() {
        // canary: `std::fs::DirBuilder::create`
        let _canary = std::fs::DirBuilder::new().create("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_exists() {
        // canary: `std::path::Path::exists`
        let _canary = std::path::Path::new("canary").exists();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_try_exists() {
        // canary: `std::path::Path::try_exists`
        let _canary = std::path::Path::new("canary").try_exists();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_metadata() {
        // canary: `std::path::Path::metadata`
        let _canary = std::path::Path::new("canary").metadata();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_symlink_metadata() {
        // canary: `std::path::Path::symlink_metadata`
        let _canary = std::path::Path::new("canary").symlink_metadata();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_read_dir() {
        // canary: `std::path::Path::read_dir`
        let _canary = std::path::Path::new("canary").read_dir();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_canonicalize() {
        // canary: `std::path::Path::canonicalize`
        let _canary = std::path::Path::new("canary").canonicalize();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_read_link() {
        // canary: `std::path::Path::read_link`
        let _canary = std::path::Path::new("canary").read_link();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_is_file() {
        // canary: `std::path::Path::is_file`
        let _canary = std::path::Path::new("canary").is_file();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_is_dir() {
        // canary: `std::path::Path::is_dir`
        let _canary = std::path::Path::new("canary").is_dir();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn path_path_is_symlink() {
        // canary: `std::path::Path::is_symlink`
        let _canary = std::path::Path::new("canary").is_symlink();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn env_set_current_dir() {
        // canary: `std::env::set_current_dir`
        let _canary = std::env::set_current_dir("canary");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    #[allow(deprecated, reason = "the canary names the deprecated call")]
    fn fs_soft_link() {
        // canary: `std::fs::soft_link`
        let _canary = std::fs::soft_link("canary", "canary2");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn env_var() {
        // canary: `std::env::var`
        let _canary = std::env::var("CANARY");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn env_var_os() {
        // canary: `std::env::var_os`
        let _canary = std::env::var_os("CANARY");
    }

    // ── Outbound connections, resolution, UDP ────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn std_tcp_connect() {
        // canary: `std::net::TcpStream::connect`
        let _canary = std::net::TcpStream::connect("canary.invalid:1");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn std_tcp_connect_timeout(addr: &std::net::SocketAddr) {
        // canary: `std::net::TcpStream::connect_timeout`
        let _canary = std::net::TcpStream::connect_timeout(addr, Duration::ZERO);
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn std_udp_bind() {
        // canary: `std::net::UdpSocket::bind`
        let _canary = std::net::UdpSocket::bind("0.0.0.0:0");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn to_socket_addrs() {
        // canary: `std::net::ToSocketAddrs::to_socket_addrs`
        use std::net::ToSocketAddrs as _;
        let _canary = "canary.invalid:1".to_socket_addrs();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_tcp_connect() {
        // canary: `tokio::net::TcpStream::connect`
        let _canary = tokio::net::TcpStream::connect("canary.invalid:1");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_lookup_host() {
        // canary: `tokio::net::lookup_host`
        let _canary = tokio::net::lookup_host("canary.invalid:1");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_tcp_socket_connect(socket: tokio::net::TcpSocket, addr: std::net::SocketAddr) {
        // canary: `tokio::net::TcpSocket::connect`
        let _canary = socket.connect(addr);
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_udp_bind() {
        // canary: `tokio::net::UdpSocket::bind`
        let _canary = tokio::net::UdpSocket::bind("0.0.0.0:0");
    }

    // ── Another HTTP client ──────────────────────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn http_connector_new() {
        // canary: `hyper_util::client::legacy::connect::HttpConnector::new`
        let _canary = hyper_util::client::legacy::connect::HttpConnector::new();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn http_connector_new_with_resolver() {
        // canary: `hyper_util::client::legacy::connect::HttpConnector::new_with_resolver`
        let _canary = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn build_http(builder: &hyper_util::client::legacy::Builder) {
        // canary: `hyper_util::client::legacy::Builder::build_http`
        let _canary = builder.build_http::<http_body_util::Empty<bytes::Bytes>>();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn gai_resolver_new() {
        // canary: `hyper_util::client::legacy::connect::dns::GaiResolver::new`
        let _canary = hyper_util::client::legacy::connect::dns::GaiResolver::new();
    }

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn tokio_executor() {
        // canary: `hyper_util::rt::TokioExecutor`
        let _canary = hyper_util::rt::TokioExecutor::new();
    }

    /// An executor that runs nothing, so a canary can name `Door::new` without spawning.
    #[derive(Clone)]
    struct NoExecutor;

    impl<F> hyper::rt::Executor<F> for NoExecutor {
        fn execute(&self, _future: F) {}
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    #[allow(clippy::no_effect_underscore_binding, reason = "the canary only names the function")]
    fn door_new() {
        // canary: `uaos_egress::Door::new`
        let _canary = uaos_egress::Door::new::<NoExecutor>;
    }

    // ── Listening ────────────────────────────────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn std_tcp_listen() {
        // canary: `std::net::TcpListener::bind`
        let _canary = std::net::TcpListener::bind("127.0.0.1:0");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_tcp_listen() {
        // canary: `tokio::net::TcpListener::bind`
        let _canary = tokio::net::TcpListener::bind("127.0.0.1:0");
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn tokio_tcp_socket_listen(socket: tokio::net::TcpSocket) {
        // canary: `tokio::net::TcpSocket::listen`
        let _canary = socket.listen(1);
    }

    // ── Spawning ─────────────────────────────────────────────────────────────────────────

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn task_spawn() {
        // canary: `tokio::task::spawn`
        let _canary = tokio::task::spawn(async {});
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn unbounded_channel() {
        // canary: `tokio::sync::mpsc::unbounded_channel`
        let _canary = tokio::sync::mpsc::unbounded_channel::<()>();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn std_channel() {
        // canary: `std::sync::mpsc::channel`
        let _canary = std::sync::mpsc::channel::<()>();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn task_spawn_blocking() {
        // canary: `tokio::task::spawn_blocking`
        let _canary = tokio::task::spawn_blocking(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn task_spawn_local() {
        // canary: `tokio::task::spawn_local`
        let _canary = tokio::task::spawn_local(async {});
    }

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn join_set() {
        // canary: `tokio::task::JoinSet`
        let _canary = tokio::task::JoinSet::<()>::new();
    }

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn local_set() {
        // canary: `tokio::task::LocalSet`
        let _canary = tokio::task::LocalSet::new();
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn(set: &mut tokio::task::JoinSet<()>) {
        // canary: `tokio::task::JoinSet::spawn`
        let _canary = set.spawn(async {});
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_blocking(set: &mut tokio::task::JoinSet<()>) {
        // canary: `tokio::task::JoinSet::spawn_blocking`
        let _canary = set.spawn_blocking(|| ());
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_on(set: &mut tokio::task::JoinSet<()>, handle: &tokio::runtime::Handle) {
        // canary: `tokio::task::JoinSet::spawn_on`
        let _canary = set.spawn_on(async {}, handle);
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_local(set: &mut tokio::task::JoinSet<()>) {
        // canary: `tokio::task::JoinSet::spawn_local`
        let _canary = set.spawn_local(async {});
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_local_on(set: &mut tokio::task::JoinSet<()>, local: &tokio::task::LocalSet) {
        // canary: `tokio::task::JoinSet::spawn_local_on`
        let _canary = set.spawn_local_on(async {}, local);
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn join_set_spawn_blocking_on(set: &mut tokio::task::JoinSet<()>, handle: &tokio::runtime::Handle) {
        // canary: `tokio::task::JoinSet::spawn_blocking_on`
        let _canary = set.spawn_blocking_on(|| (), handle);
    }

    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "canary")]
    fn local_set_spawn_local(local: &tokio::task::LocalSet) {
        // canary: `tokio::task::LocalSet::spawn_local`
        let _canary = local.spawn_local(async {});
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn handle_spawn(handle: &tokio::runtime::Handle) {
        // canary: `tokio::runtime::Handle::spawn`
        let _canary = handle.spawn(async {});
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn handle_spawn_blocking(handle: &tokio::runtime::Handle) {
        // canary: `tokio::runtime::Handle::spawn_blocking`
        let _canary = handle.spawn_blocking(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn runtime_spawn(runtime: &tokio::runtime::Runtime) {
        // canary: `tokio::runtime::Runtime::spawn`
        let _canary = runtime.spawn(async {});
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn runtime_spawn_blocking(runtime: &tokio::runtime::Runtime) {
        // canary: `tokio::runtime::Runtime::spawn_blocking`
        let _canary = runtime.spawn_blocking(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn thread_builder_spawn() {
        // canary: `std::thread::Builder::spawn`
        let _canary = std::thread::Builder::new().spawn(|| ());
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn thread_scope() {
        // canary: `std::thread::scope`
        std::thread::scope(|_| ());
    }

    // ── Deterministic collections ────────────────────────────────────────────────────────

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn hash_map() {
        // canary: `std::collections::HashMap`
        let _canary = std::collections::HashMap::<u8, u8>::new();
    }

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn hash_set() {
        // canary: `std::collections::HashSet`
        let _canary = std::collections::HashSet::<u8>::new();
    }

    // ── Local IPC and local listeners, Unix ────────────────

    #[cfg(unix)]
    mod unix {
        use std::os::unix::net::SocketAddr;

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_stream_connect() {
            // canary: `std::os::unix::net::UnixStream::connect`
            let _canary = std::os::unix::net::UnixStream::connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_stream_connect_addr(addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixStream::connect_addr`
            let _canary = std::os::unix::net::UnixStream::connect_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_bind() {
            // canary: `std::os::unix::net::UnixDatagram::bind`
            let _canary = std::os::unix::net::UnixDatagram::bind("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_bind_addr(addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixDatagram::bind_addr`
            let _canary = std::os::unix::net::UnixDatagram::bind_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_unbound() {
            // canary: `std::os::unix::net::UnixDatagram::unbound`
            let _canary = std::os::unix::net::UnixDatagram::unbound();
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_connect(socket: &std::os::unix::net::UnixDatagram) {
            // canary: `std::os::unix::net::UnixDatagram::connect`
            let _canary = socket.connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_connect_addr(socket: &std::os::unix::net::UnixDatagram, addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixDatagram::connect_addr`
            let _canary = socket.connect_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_send_to(socket: &std::os::unix::net::UnixDatagram) {
            // canary: `std::os::unix::net::UnixDatagram::send_to`
            let _canary = socket.send_to(b"", "/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_datagram_send_to_addr(socket: &std::os::unix::net::UnixDatagram, addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixDatagram::send_to_addr`
            let _canary = socket.send_to_addr(b"", addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_listener_bind() {
            // canary: `std::os::unix::net::UnixListener::bind`
            let _canary = std::os::unix::net::UnixListener::bind("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn std_listener_bind_addr(addr: &SocketAddr) {
            // canary: `std::os::unix::net::UnixListener::bind_addr`
            let _canary = std::os::unix::net::UnixListener::bind_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_stream_connect() {
            // canary: `tokio::net::UnixStream::connect`
            let _canary = tokio::net::UnixStream::connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_stream_connect_addr(addr: &tokio::net::unix::SocketAddr) {
            // canary: `tokio::net::UnixStream::connect_addr`
            let _canary = tokio::net::UnixStream::connect_addr(addr);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_socket_connect(socket: tokio::net::UnixSocket) {
            // canary: `tokio::net::UnixSocket::connect`
            let _canary = socket.connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_socket_datagram(socket: tokio::net::UnixSocket) {
            // canary: `tokio::net::UnixSocket::datagram`
            let _canary = socket.datagram();
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_socket_listen(socket: tokio::net::UnixSocket) {
            // canary: `tokio::net::UnixSocket::listen`
            let _canary = socket.listen(1);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_bind() {
            // canary: `tokio::net::UnixDatagram::bind`
            let _canary = tokio::net::UnixDatagram::bind("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_unbound() {
            // canary: `tokio::net::UnixDatagram::unbound`
            let _canary = tokio::net::UnixDatagram::unbound();
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_connect(socket: &tokio::net::UnixDatagram) {
            // canary: `tokio::net::UnixDatagram::connect`
            let _canary = socket.connect("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_send_to(socket: &tokio::net::UnixDatagram) {
            // canary: `tokio::net::UnixDatagram::send_to`
            let _canary = socket.send_to(b"", "/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_pair() {
            // canary: `tokio::net::UnixDatagram::pair`
            let _canary = tokio::net::UnixDatagram::pair();
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_from_std(socket: std::os::unix::net::UnixDatagram) {
            // canary: `tokio::net::UnixDatagram::from_std`
            let _canary = tokio::net::UnixDatagram::from_std(socket);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_try_send_to(socket: &tokio::net::UnixDatagram) {
            // canary: `tokio::net::UnixDatagram::try_send_to`
            let _canary = socket.try_send_to(b"", "/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_datagram_poll_send_to(socket: &tokio::net::UnixDatagram, cx: &mut std::task::Context<'_>) {
            // canary: `tokio::net::UnixDatagram::poll_send_to`
            let _canary = socket.poll_send_to(cx, b"", "/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_pipe_open_sender() {
            // canary: `tokio::net::unix::pipe::OpenOptions::open_sender`
            let _canary = tokio::net::unix::pipe::OpenOptions::new().open_sender("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_pipe_open_receiver() {
            // canary: `tokio::net::unix::pipe::OpenOptions::open_receiver`
            let _canary = tokio::net::unix::pipe::OpenOptions::new().open_receiver("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn unix_symlink() {
            // canary: `std::os::unix::fs::symlink`
            let _canary = std::os::unix::fs::symlink("canary", "canary2");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn unix_chown() {
            // canary: `std::os::unix::fs::chown`
            let _canary = std::os::unix::fs::chown("canary", None, None);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn unix_lchown() {
            // canary: `std::os::unix::fs::lchown`
            let _canary = std::os::unix::fs::lchown("canary", None, None);
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn unix_chroot() {
            // canary: `std::os::unix::fs::chroot`
            let _canary = std::os::unix::fs::chroot("canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_listener_bind() {
            // canary: `tokio::net::UnixListener::bind`
            let _canary = tokio::net::UnixListener::bind("/canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn tokio_listener_bind_addr(addr: &tokio::net::unix::SocketAddr) {
            // canary: `tokio::net::UnixListener::bind_addr`
            let _canary = tokio::net::UnixListener::bind_addr(addr);
        }
    }

    // ── Named pipes, Windows ─────────────────────────────────────────────────────────────

    #[cfg(windows)]
    mod windows {
        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn pipe_client_open() {
            // canary: `tokio::net::windows::named_pipe::ClientOptions::open`
            let _canary = tokio::net::windows::named_pipe::ClientOptions::new().open("canary");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn windows_symlink_file() {
            // canary: `std::os::windows::fs::symlink_file`
            let _canary = std::os::windows::fs::symlink_file("canary", "canary2");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn windows_symlink_dir() {
            // canary: `std::os::windows::fs::symlink_dir`
            let _canary = std::os::windows::fs::symlink_dir("canary", "canary2");
        }

        #[expect(clippy::disallowed_methods, reason = "canary")]
        fn pipe_server_create() {
            // canary: `tokio::net::windows::named_pipe::ServerOptions::create`
            let _canary = tokio::net::windows::named_pipe::ServerOptions::new().create("canary");
        }
    }
}
