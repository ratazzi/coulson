use super::*;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

struct Server {
    socket: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    fn new(responses: Vec<serde_json::Value>, stall: bool) -> Self {
        let socket = std::env::temp_dir().join(format!("cw-{}.sock", uuid::Uuid::now_v7()));
        let listener = UnixListener::bind(&socket).unwrap();
        let task = tokio::spawn(async move {
            for response in responses {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut request = String::new();
                reader.read_line(&mut request).await.unwrap();
                let request: serde_json::Value = serde_json::from_str(&request).unwrap();
                assert_eq!(request["method"], "app.status");
                assert_eq!(request["params"]["name"], "demo");
                let mut stream = reader.into_inner();
                if stall {
                    // Keep making progress without completing an NDJSON response.
                    for byte in b"{\"ok\":true,\"result\":" {
                        if stream.write_all(&[*byte]).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(40)).await;
                    }
                    tokio::time::sleep(Duration::from_secs(60)).await;
                } else {
                    stream
                        .write_all(format!("{response}\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
        });
        Self { socket, task }
    }

    fn client(&self) -> RpcClient {
        RpcClient::new(&self.socket)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        std::fs::remove_file(&self.socket).ok();
    }
}

fn response(state: &str, id: i64) -> serde_json::Value {
    json!({ "ok": true, "result": { "apps": [{
        "app_id": id, "name": "demo", "domain": "demo.coulson.local", "state": state,
        "since": 100, "started_at": 99, "ready_at": null,
        "last_error": { "code": "process_exited", "message": "Process exited", "occurred_at": 98, "exit_code": 7 }
    }] } })
}

#[tokio::test]
async fn waits_through_sleeping_and_starting_then_returns_ready() {
    let mut server = Server::new(
        vec![
            response("sleeping", 1),
            response("starting", 1),
            response("ready", 1),
        ],
        false,
    );
    let report = wait_for_app(&server.client(), "demo", Duration::from_secs(3)).await;
    assert!(report.ready);
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.app.unwrap().state, AppState::Ready);
    assert!(report.error.is_none());
    (&mut server.task).await.unwrap();
}

#[tokio::test]
async fn terminal_states_fail_immediately_with_snapshot() {
    for (state, code) in [
        ("failed", "app_failed"),
        ("disabled", "app_disabled"),
        ("unknown", "status_unknown"),
    ] {
        let mut server = Server::new(vec![response(state, 1)], false);
        let report = wait_for_app(&server.client(), "demo", Duration::from_secs(3)).await;
        assert!(!report.ready);
        assert_eq!(report.exit_code(), 1);
        let error = report.error.unwrap();
        assert_eq!(error.code, code);
        if state == "failed" {
            assert!(error.message.contains("exit 7"));
        }
        assert_eq!(report.app.unwrap().state.label(), state);
        (&mut server.task).await.unwrap();
    }
}

#[tokio::test]
async fn timeout_preserves_last_status_and_returns_124() {
    let mut server = Server::new(vec![response("starting", 1)], false);
    let report = wait_for_app(&server.client(), "demo", Duration::from_millis(100)).await;
    assert_eq!(report.exit_code(), 124);
    assert_eq!(report.app.as_ref().unwrap().state, AppState::Starting);
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["error"]["code"], "timeout");
    assert_eq!(json["ready"], false);
    (&mut server.task).await.unwrap();
}

#[tokio::test]
async fn timeout_covers_slowly_streaming_rpc_response() {
    let server = Server::new(vec![response("ready", 1)], true);
    let report = tokio::time::timeout(
        Duration::from_secs(2),
        wait_for_app(&server.client(), "demo", Duration::from_millis(100)),
    )
    .await
    .unwrap();
    assert_eq!(report.exit_code(), 124);
    assert!(report.app.is_none());
}

#[tokio::test]
async fn missing_app_malformed_response_and_replacement_are_errors() {
    for (responses, code) in [
        (
            vec![json!({"ok":false,"error":{"message":"not found"}})],
            "query_failed",
        ),
        (
            vec![json!({"ok":true,"result":{"apps":[]}})],
            "invalid_response",
        ),
        (
            vec![response("starting", 1), response("ready", 2)],
            "app_replaced",
        ),
    ] {
        let mut server = Server::new(responses, false);
        let report = wait_for_app(&server.client(), "demo", Duration::from_secs(3)).await;
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.error.unwrap().code, code);
        (&mut server.task).await.unwrap();
    }
}

#[tokio::test]
async fn disconnected_daemon_is_an_error_not_a_success() {
    let path = std::env::temp_dir().join(format!("missing-{}.sock", uuid::Uuid::now_v7()));
    let report = wait_for_app(&RpcClient::new(&path), "demo", Duration::from_secs(1)).await;
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.error.unwrap().code, "query_failed");
}

#[test]
fn timeout_parser_validates_units_zero_and_overflow() {
    for value in ["30", "30s"] {
        assert_eq!(parse_timeout(value).unwrap(), Duration::from_secs(30));
    }
    assert_eq!(parse_timeout("2m").unwrap(), Duration::from_secs(120));
    assert_eq!(parse_timeout("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_timeout("500ms").unwrap(), Duration::from_millis(500));
    for invalid in [
        "",
        "0",
        "0ms",
        "-1s",
        "1.5s",
        "永",
        "1d",
        "18446744073709551615h",
    ] {
        assert!(parse_timeout(invalid).is_err(), "{invalid}");
    }
}
