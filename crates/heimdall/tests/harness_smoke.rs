// SPDX-License-Identifier: MIT

//! Harness self-tests (Sprint 47 task #466 AC).
//!
//! Verifies:
//! - TestServer starts and /readyz returns 200 within 2s
//! - The port is bound while the server is running
//! - Drop frees the port (no leak across tests)
//! - Drop runs even when a test panics (panic-cleanup safety)

#![allow(unsafe_code)]

#[cfg(unix)]
mod unix {
    use heimdall_e2e_harness::{TestServer, config, free_port};
    use std::net::TcpStream;
    use std::time::Duration;

    fn bin() -> &'static str {
        env!("CARGO_BIN_EXE_heimdall")
    }

    fn minimal_toml(obs_port: u16) -> String {
        config::minimal_obs(obs_port)
    }

    /// The server becomes ready within 2 seconds of spawn.
    #[test]
    fn server_becomes_ready_within_2s() {
        let obs_port = free_port();
        let toml = minimal_toml(obs_port);
        let server = TestServer::start_with_ports(bin(), &toml, 0, obs_port)
            .wait_ready(Duration::from_secs(2))
            .expect("TestServer must be ready within 2 seconds");
        assert_eq!(server.obs_port, obs_port);
    }

    /// The observability port is bound while the server runs and is free after drop.
    #[test]
    fn port_is_bound_while_running_and_free_after_drop() {
        let obs_port = free_port();
        let toml = minimal_toml(obs_port);
        let server = TestServer::start_with_ports(bin(), &toml, 0, obs_port)
            .wait_ready(Duration::from_secs(2))
            .expect("TestServer must be ready");

        // Port should be occupied: a connection must succeed.
        assert!(
            TcpStream::connect_timeout(
                &server.obs_addr(),
                Duration::from_millis(200)
            )
            .is_ok(),
            "observability port {obs_port} must be reachable while server is running"
        );

        drop(server);

        // After drop the port is free: connection must fail.
        let still_bound = (0..5).any(|_| {
            std::thread::sleep(Duration::from_millis(50));
            TcpStream::connect_timeout(
                &format!("127.0.0.1:{obs_port}").parse().unwrap(),
                Duration::from_millis(50),
            )
            .is_ok()
        });
        assert!(!still_bound, "port {obs_port} must be free after TestServer is dropped");
    }

    /// Drop runs even when a test panics — verified with `catch_unwind`.
    #[test]
    fn drop_runs_on_panic() {
        let obs_port = free_port();
        let toml = minimal_toml(obs_port);

        // Spawn the server inside a catch_unwind closure that panics after
        // constructing the TestServer, so we can observe that Drop cleaned up.
        let _ = std::panic::catch_unwind(move || {
            let _server = TestServer::start_with_ports(bin(), &toml, 0, obs_port)
                .wait_ready(Duration::from_secs(2))
                .expect("ready");
            // Simulate a test failure — Drop must still run.
            panic!("simulated test failure for panic-cleanup verification");
        });

        // After the panic the port should be free.
        std::thread::sleep(Duration::from_millis(200));
        let still_bound = TcpStream::connect_timeout(
            &format!("127.0.0.1:{obs_port}").parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok();
        assert!(
            !still_bound,
            "port {obs_port} must be free after panic-induced TestServer drop"
        );
    }
}
