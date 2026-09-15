use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("cw{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(dir.join("demo")).unwrap();
        Self(dir)
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_coulson"))
            .args(args)
            .env("COULSON_CONTROL_SOCKET", self.0.join("s"))
            .env("COULSON_APPS_ROOT", self.0.join("apps"))
            .env("XDG_CONFIG_HOME", &self.0)
            .env("RUST_LOG", "info")
            .current_dir(self.0.join("demo"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                child.kill().ok();
                child.wait().ok();
                panic!("wait CLI exceeded its deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

#[test]
fn wait_cli_json_and_exit_codes_match_final_outcome() {
    for (state, exit_code, error_code) in [
        ("ready", 0, None),
        ("failed", 1, Some("app_failed")),
        ("starting", 124, Some("timeout")),
    ] {
        let fixture = Fixture::new();
        let listener = UnixListener::bind(fixture.0.join("s")).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            let request: serde_json::Value = serde_json::from_str(&request).unwrap();
            assert_eq!(request["method"], "app.status");
            assert_eq!(request["params"]["name"], "demo");
            let response = serde_json::json!({ "ok":true, "result":{ "apps":[{
                "app_id":1, "name":"demo", "domain":"demo.coulson.local", "state":state,
                "since":null, "started_at":null, "ready_at":null, "last_error":null
            }] } });
            writeln!(stream, "{response}").unwrap();
        });
        // Omitted name resolves from CWD, and info logs must not contaminate JSON.
        let output = fixture.run(&["wait", "--timeout", "100ms", "--json"]);
        assert_eq!(output.status.code(), Some(exit_code));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["ready"], exit_code == 0);
        assert_eq!(report["app"]["state"], state);
        assert_eq!(report["error"]["code"].as_str(), error_code);
        server.join().unwrap();
    }
}

#[test]
fn wait_cli_text_error_uses_stderr_and_nonzero_exit() {
    let fixture = Fixture::new();
    let output = fixture.run(&["wait", "demo", "--timeout", "100ms"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("query_failed"));
}
