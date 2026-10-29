//! Response-body accounting must survive HTTP dropping a body at Content-Length.

use super::{client::EventRange, events::STATUS_ABORTED};
use axum::{body::Bytes, http::HeaderMap};
use futures::Stream;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

pub(super) struct TransferReport {
    pub(super) events: super::events::EventReporter,
    pub(super) kind: &'static str,
    pub(super) tenant_id: Option<String>,
    pub(super) package: String,
    pub(super) version: Option<String>,
    pub(super) credential_id: Option<String>,
    pub(super) registry_id: String,
    pub(super) file: String,
    pub(super) declared_bytes: u64,
    pub(super) host: String,
    pub(super) request_id: String,
    pub(super) headers: HeaderMap,
}

impl TransferReport {
    pub(super) fn emit(
        self,
        bytes: u64,
        status: &'static str,
        range: Option<super::client::EventRange>,
    ) {
        let mut event = super::events::EventReporter::event(
            self.kind,
            self.tenant_id.as_deref(),
            &self.package,
            self.version.as_deref(),
            bytes,
            self.credential_id.as_deref(),
        );
        super::events::apply_transfer(
            &mut event,
            super::events::TransferFacts {
                registry_id: &self.registry_id,
                file: &self.file,
                declared_bytes: self.declared_bytes,
                status,
                range,
                host: &self.host,
                request_id: &self.request_id,
                headers: &self.headers,
            },
        );
        self.events.enqueue(event);
    }
}

/// Counts the chunks handed to HTTP and reports exactly once, including when
/// HTTP stops polling at Content-Length or the client disconnects early.
/// The report only enters the existing bounded, nonblocking event handoff.
pub(super) struct DownloadStream {
    source: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    report: Option<TransferReport>,
    transferred: u64,
    expected_bytes: Option<u64>,
    status: &'static str,
    range: Option<EventRange>,
}

impl DownloadStream {
    pub(super) fn new(
        source: impl Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
        report: TransferReport,
        expected_bytes: Option<u64>,
        status: &'static str,
        range: Option<EventRange>,
    ) -> Self {
        Self {
            source: Box::pin(source),
            report: Some(report),
            transferred: 0,
            expected_bytes,
            status,
            range,
        }
    }

    fn finish(&mut self, completed: bool) {
        if let Some(report) = self.report.take() {
            let complete_length = self
                .expected_bytes
                .is_none_or(|bytes| bytes == self.transferred);
            let status = if completed && complete_length {
                self.status
            } else {
                STATUS_ABORTED
            };
            report.emit(self.transferred, status, self.range.take());
        }
    }
}

impl Stream for DownloadStream {
    type Item = Result<Bytes, reqwest::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                self.transferred = self.transferred.saturating_add(bytes.len() as u64);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finish(false);
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finish(true);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DownloadStream {
    fn drop(&mut self) {
        // Hyper need not poll EOF after consuming the declared response length.
        let completed = self.expected_bytes == Some(self.transferred);
        self.finish(completed);
    }
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
