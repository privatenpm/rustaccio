use super::*;
use crate::managed::{
    client::{ControlPlaneClient, ManagedEvent},
    events::{EventReporter, EventReporterConfig, STATUS_COMPLETE, STATUS_PARTIAL},
};
use futures::{StreamExt, stream};
use std::{sync::Arc, time::Duration};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

async fn observe(
    chunks: Vec<Result<Bytes, reqwest::Error>>,
    length: Option<u64>,
    polls: usize,
    status: &'static str,
) -> ManagedEvent {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/events"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&control_plane)
        .await;
    let reporter = EventReporter::start(
        Arc::new(ControlPlaneClient::new(&control_plane.uri(), "node-token").expect("client")),
        EventReporterConfig {
            spool_dir: None,
            max_bytes: 64 * 1024,
            flush_interval: Duration::from_millis(5),
            flush_batch: 50,
        },
    )
    .await
    .expect("reporter");
    let report = TransferReport {
        events: reporter.clone(),
        kind: "download",
        tenant_id: Some("org_1".into()),
        package: "demo".into(),
        version: Some("1.0.0".into()),
        credential_id: Some("ntok_1".into()),
        registry_id: "reg_1".into(),
        file: "demo-1.0.0.tgz".into(),
        declared_bytes: 7,
        host: "npm.example.test".into(),
        request_id: "request_1".into(),
        headers: HeaderMap::new(),
    };
    let range = (status == STATUS_PARTIAL).then_some(EventRange { start: 1, end: 3 });
    let mut download = DownloadStream::new(stream::iter(chunks), report, length, status, range);
    for _ in 0..polls {
        if !matches!(download.next().await, Some(Ok(_))) {
            assert!(
                download.report.is_none(),
                "EOF and errors report immediately"
            );
            break;
        }
    }
    drop(download);
    let events = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let requests = control_plane.received_requests().await.expect("requests");
            if let Some(request) = requests.first() {
                break request
                    .body_json::<serde_json::Value>()
                    .expect("event batch")["events"]
                    .as_array()
                    .expect("events")
                    .clone();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("usage event");
    assert_eq!(events.len(), 1, "EOF/error and Drop must not double-report");
    reporter.shutdown().await;
    control_plane.verify().await;
    serde_json::from_value(events[0].clone()).expect("event")
}

fn chunks() -> Vec<Result<Bytes, reqwest::Error>> {
    vec![
        Ok(Bytes::from_static(b"tar")),
        Ok(Bytes::from_static(b"ball")),
    ]
}

#[tokio::test]
async fn content_length_finishes_without_an_eof_poll() {
    let event = observe(chunks(), Some(7), 2, STATUS_COMPLETE).await;
    assert_eq!(event.bytes, 7);
    assert_eq!(event.status.as_deref(), Some(STATUS_COMPLETE));
}

#[tokio::test]
async fn chunked_download_reports_once_at_eof() {
    let event = observe(chunks(), None, usize::MAX, STATUS_COMPLETE).await;
    assert_eq!(event.bytes, 7);
    assert_eq!(event.status.as_deref(), Some(STATUS_COMPLETE));
}

#[tokio::test]
async fn early_drop_reports_only_streamed_bytes() {
    for length in [Some(7), None] {
        let event = observe(chunks(), length, 1, STATUS_COMPLETE).await;
        assert_eq!(event.bytes, 3);
        assert_eq!(event.status.as_deref(), Some(STATUS_ABORTED));
    }
}

#[tokio::test]
async fn upstream_error_reports_aborted_once() {
    let error = reqwest::Client::new()
        .get("://")
        .build()
        .expect_err("invalid URL");
    let event = observe(
        vec![Ok(Bytes::from_static(b"tar")), Err(error)],
        Some(7),
        usize::MAX,
        STATUS_COMPLETE,
    )
    .await;
    assert_eq!(event.bytes, 3);
    assert_eq!(event.status.as_deref(), Some(STATUS_ABORTED));
}

#[tokio::test]
async fn short_upstream_eof_is_aborted() {
    let event = observe(chunks(), Some(10), usize::MAX, STATUS_COMPLETE).await;
    assert_eq!(event.bytes, 7);
    assert_eq!(event.status.as_deref(), Some(STATUS_ABORTED));
}

#[tokio::test]
async fn range_response_keeps_partial_status_and_range() {
    let event = observe(chunks(), Some(3), 1, STATUS_PARTIAL).await;
    assert_eq!(event.bytes, 3);
    assert_eq!(event.declared_bytes, Some(7));
    assert_eq!(event.status.as_deref(), Some(STATUS_PARTIAL));
    assert_eq!(event.range, Some(EventRange { start: 1, end: 3 }));
}

#[tokio::test]
async fn empty_body_finishes_without_polling() {
    let event = observe(vec![], Some(0), 0, STATUS_COMPLETE).await;
    assert_eq!(event.bytes, 0);
    assert_eq!(event.status.as_deref(), Some(STATUS_COMPLETE));
}

#[tokio::test]
async fn unpolled_nonempty_body_is_aborted() {
    let event = observe(chunks(), Some(7), 0, STATUS_COMPLETE).await;
    assert_eq!(event.bytes, 0);
    assert_eq!(event.status.as_deref(), Some(STATUS_ABORTED));
}
