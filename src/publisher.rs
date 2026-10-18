//! Delivery of traps to EventBridge (`PutEvents`), or to stdout in dry-run
//! mode.

/// Entries per `PutEvents` call (service limit).
const MAX_BATCH_ENTRIES: usize = 10;
/// Request and per-entry size limit (service limit).
const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// How long to wait for more traps before sending a partial batch.
const LINGER: std::time::Duration = std::time::Duration::from_millis(200);
/// `error_code` label for events that could not be serialized.
const ERROR_CODE_SERIALIZE: &str = "Serialize";
/// `error_code` label for events over the EventBridge size limit.
const ERROR_CODE_TOO_LARGE: &str = "TooLarge";

/// Where events go.
#[derive(Debug)]
pub enum Publisher {
    EventBridge(EventBridgePublisher),
    Stdout(std::sync::Arc<crate::metrics::Metrics>),
}

impl Publisher {
    /// Consume traps until every sender is dropped, then flush.
    pub async fn run(&self, mut rx: tokio::sync::mpsc::Receiver<crate::trap::Trap>) {
        let mut batch = Vec::with_capacity(MAX_BATCH_ENTRIES);
        while let Some(first) = rx.recv().await {
            batch.push(first);
            let deadline = tokio::time::Instant::now() + LINGER;
            while batch.len() < MAX_BATCH_ENTRIES {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(trap)) => batch.push(trap),
                    Ok(None) | Err(_) => break,
                }
            }
            self.publish(std::mem::take(&mut batch)).await;
        }
    }

    async fn publish(&self, traps: Vec<crate::trap::Trap>) {
        match self {
            Publisher::EventBridge(p) => p.publish(traps).await,
            Publisher::Stdout(metrics) => {
                for trap in traps {
                    match serde_json::to_string(&trap) {
                        Ok(json) => {
                            println!("{json}");
                            metrics.events_put(1);
                        }
                        Err(e) => {
                            metrics.events_failed(ERROR_CODE_SERIALIZE);
                            tracing::error!(error = %e, "failed to serialize trap");
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct EventBridgePublisher {
    client: aws_sdk_eventbridge::Client,
    event_bus: String,
    source: String,
    detail_type: String,
    metrics: std::sync::Arc<crate::metrics::Metrics>,
}

impl EventBridgePublisher {
    pub fn new(
        client: aws_sdk_eventbridge::Client,
        event_bus: String,
        source: String,
        detail_type: String,
        metrics: std::sync::Arc<crate::metrics::Metrics>,
    ) -> Self {
        Self {
            client,
            event_bus,
            source,
            detail_type,
            metrics,
        }
    }

    pub async fn publish(&self, traps: Vec<crate::trap::Trap>) {
        let mut entries = Vec::with_capacity(traps.len());
        for trap in &traps {
            match self.entry(trap) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    self.metrics.events_failed(match e {
                        crate::Error::EventTooLarge { .. } => ERROR_CODE_TOO_LARGE,
                        _ => ERROR_CODE_SERIALIZE,
                    });
                    tracing::error!(
                        error = %e,
                        trap = trap.trap.oid,
                        source = %trap.source.address,
                        "dropping trap"
                    );
                }
            }
        }
        for chunk in Self::split_by_size(entries) {
            self.put_with_retry(chunk).await;
        }
    }

    fn entry(
        &self,
        trap: &crate::trap::Trap,
    ) -> crate::Result<aws_sdk_eventbridge::types::PutEventsRequestEntry> {
        let detail = serde_json::to_string(trap)?;
        let entry = aws_sdk_eventbridge::types::PutEventsRequestEntry::builder()
            .event_bus_name(&self.event_bus)
            .source(&self.source)
            .detail_type(&self.detail_type)
            .detail(detail)
            .time(aws_sdk_eventbridge::primitives::DateTime::from(
                trap.received_at,
            ))
            .build();
        let size = Self::entry_size(&entry);
        if size > MAX_REQUEST_BYTES {
            return Err(crate::Error::EventTooLarge {
                size,
                limit: MAX_REQUEST_BYTES,
            });
        }
        Ok(entry)
    }

    /// Entry size as EventBridge counts it.
    fn entry_size(entry: &aws_sdk_eventbridge::types::PutEventsRequestEntry) -> usize {
        let time = if entry.time().is_some() { 14 } else { 0 };
        time + entry.source().map_or(0, str::len)
            + entry.detail_type().map_or(0, str::len)
            + entry.detail().map_or(0, str::len)
            + entry.resources().iter().map(String::len).sum::<usize>()
    }

    fn split_by_size(
        entries: Vec<aws_sdk_eventbridge::types::PutEventsRequestEntry>,
    ) -> Vec<Vec<aws_sdk_eventbridge::types::PutEventsRequestEntry>> {
        let mut chunks = vec![];
        let mut current = vec![];
        let mut current_size = 0;
        for entry in entries {
            let size = Self::entry_size(&entry);
            if !current.is_empty()
                && (current_size + size > MAX_REQUEST_BYTES || current.len() == MAX_BATCH_ENTRIES)
            {
                chunks.push(std::mem::take(&mut current));
                current_size = 0;
            }
            current_size += size;
            current.push(entry);
        }
        if !current.is_empty() {
            chunks.push(current);
        }
        chunks
    }

    /// Send a batch; retry the failed entries once.
    async fn put_with_retry(
        &self,
        entries: Vec<aws_sdk_eventbridge::types::PutEventsRequestEntry>,
    ) {
        let failed = self.put(entries).await;
        if failed.is_empty() {
            return;
        }
        tracing::warn!(count = failed.len(), "retrying failed PutEvents entries");
        let retry = failed.into_iter().map(|(entry, _, _)| entry).collect();
        for (_, code, message) in self.put(retry).await {
            self.metrics.events_failed(&code);
            tracing::error!(
                error_code = code,
                error_message = message,
                "failed to put event"
            );
        }
    }

    /// Returns entries that failed, with their error code and message.
    async fn put(
        &self,
        entries: Vec<aws_sdk_eventbridge::types::PutEventsRequestEntry>,
    ) -> Vec<(
        aws_sdk_eventbridge::types::PutEventsRequestEntry,
        String,
        String,
    )> {
        let count = entries.len();
        let result = self
            .client
            .put_events()
            .set_entries(Some(entries.clone()))
            .send()
            .await;
        let failed = match result {
            Ok(output) if output.failed_entry_count() == 0 => {
                tracing::debug!(count = entries.len(), "put events");
                vec![]
            }
            Ok(output) => entries
                .into_iter()
                .zip(output.entries())
                .filter_map(|(entry, result)| {
                    result.error_code().map(|code| {
                        (
                            entry,
                            code.to_owned(),
                            result.error_message().unwrap_or_default().to_owned(),
                        )
                    })
                })
                .collect(),
            Err(e) => {
                let message = aws_sdk_eventbridge::error::DisplayErrorContext(&e).to_string();
                entries
                    .into_iter()
                    .map(|entry| (entry, "RequestFailed".to_owned(), message.clone()))
                    .collect()
            }
        };
        self.metrics.events_put(count - failed.len());
        failed
    }
}

#[cfg(test)]
mod tests {
    fn trap(n: u64) -> crate::trap::Trap {
        crate::trap::Trap {
            version: crate::trap::Version::V2c,
            source: crate::trap::Source {
                address: "192.0.2.1".parse().unwrap(),
                port: 162,
            },
            pdu_type: crate::trap::PduType::Trap,
            request_id: Some(1),
            uptime: Some(n as u32),
            trap: crate::trap::NamedOid {
                oid: format!("1.3.6.1.4.1.99.0.{n}"),
                name: None,
            },
            varbinds: vec![],
            v1: None,
            v3: None,
            received_at: std::time::SystemTime::now(),
        }
    }

    fn publisher(
        client: aws_sdk_eventbridge::Client,
        metrics: std::sync::Arc<crate::metrics::Metrics>,
    ) -> crate::publisher::EventBridgePublisher {
        crate::publisher::EventBridgePublisher::new(
            client,
            "bus".to_owned(),
            "trapbridge".to_owned(),
            "SNMP Trap".to_owned(),
            metrics,
        )
    }

    #[tokio::test]
    async fn publish_splits_into_batches_of_ten() {
        let rule = aws_smithy_mocks::mock!(aws_sdk_eventbridge::Client::put_events)
            .match_requests(|req| req.entries().len() <= 10)
            .then_output(|| {
                aws_sdk_eventbridge::operation::put_events::PutEventsOutput::builder()
                    .failed_entry_count(0)
                    .build()
            });
        let client = aws_smithy_mocks::mock_client!(
            aws_sdk_eventbridge,
            aws_smithy_mocks::RuleMode::MatchAny,
            [&rule]
        );
        let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
        publisher(client, metrics.clone())
            .publish((0..15).map(trap).collect())
            .await;
        assert_eq!(rule.num_calls(), 2);
        let text = metrics.encode().unwrap();
        assert!(text.contains("trapbridge_events_put_total 15\n"), "{text}");
    }

    #[tokio::test]
    async fn publish_retries_failed_entries_once() {
        let partial = aws_smithy_mocks::mock!(aws_sdk_eventbridge::Client::put_events)
            .match_requests(|req| req.entries().len() == 2)
            .then_output(|| {
                aws_sdk_eventbridge::operation::put_events::PutEventsOutput::builder()
                    .failed_entry_count(1)
                    .entries(
                        aws_sdk_eventbridge::types::PutEventsResultEntry::builder()
                            .event_id("ok")
                            .build(),
                    )
                    .entries(
                        aws_sdk_eventbridge::types::PutEventsResultEntry::builder()
                            .error_code("ThrottlingException")
                            .build(),
                    )
                    .build()
            });
        let retry = aws_smithy_mocks::mock!(aws_sdk_eventbridge::Client::put_events)
            .match_requests(|req| {
                req.entries().len() == 1
                    && req.entries()[0]
                        .detail()
                        .is_some_and(|d| d.contains("1.3.6.1.4.1.99.0.1"))
            })
            .then_output(|| {
                aws_sdk_eventbridge::operation::put_events::PutEventsOutput::builder()
                    .failed_entry_count(0)
                    .build()
            });
        let client = aws_smithy_mocks::mock_client!(
            aws_sdk_eventbridge,
            aws_smithy_mocks::RuleMode::MatchAny,
            [&partial, &retry]
        );
        let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
        publisher(client, metrics.clone())
            .publish(vec![trap(0), trap(1)])
            .await;
        assert_eq!(partial.num_calls(), 1);
        assert_eq!(retry.num_calls(), 1);
        let text = metrics.encode().unwrap();
        assert!(text.contains("trapbridge_events_put_total 2\n"), "{text}");
        assert!(!text.contains("trapbridge_events_failed_total{"), "{text}");
    }

    #[tokio::test]
    async fn publish_counts_entries_failed_after_retry() {
        let rule =
            aws_smithy_mocks::mock!(aws_sdk_eventbridge::Client::put_events).then_output(|| {
                aws_sdk_eventbridge::operation::put_events::PutEventsOutput::builder()
                    .failed_entry_count(1)
                    .entries(
                        aws_sdk_eventbridge::types::PutEventsResultEntry::builder()
                            .error_code("ThrottlingException")
                            .build(),
                    )
                    .build()
            });
        let client = aws_smithy_mocks::mock_client!(
            aws_sdk_eventbridge,
            aws_smithy_mocks::RuleMode::MatchAny,
            [&rule]
        );
        let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
        publisher(client, metrics.clone())
            .publish(vec![trap(0)])
            .await;
        assert_eq!(rule.num_calls(), 2);
        let text = metrics.encode().unwrap();
        assert!(text.contains("trapbridge_events_put_total 0\n"), "{text}");
        assert!(
            text.contains("trapbridge_events_failed_total{error_code=\"ThrottlingException\"} 1\n"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn publish_counts_oversized_event_as_too_large() {
        let rule =
            aws_smithy_mocks::mock!(aws_sdk_eventbridge::Client::put_events).then_output(|| {
                aws_sdk_eventbridge::operation::put_events::PutEventsOutput::builder().build()
            });
        let client = aws_smithy_mocks::mock_client!(aws_sdk_eventbridge, [&rule]);
        let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
        let mut t = trap(0);
        t.trap.oid = "1".repeat(300 * 1024);
        publisher(client, metrics.clone()).publish(vec![t]).await;
        assert_eq!(rule.num_calls(), 0);
        let text = metrics.encode().unwrap();
        assert!(
            text.contains("trapbridge_events_failed_total{error_code=\"TooLarge\"} 1\n"),
            "{text}"
        );
    }

    #[test]
    fn oversized_event_is_rejected() {
        let rule =
            aws_smithy_mocks::mock!(aws_sdk_eventbridge::Client::put_events).then_output(|| {
                aws_sdk_eventbridge::operation::put_events::PutEventsOutput::builder().build()
            });
        let client = aws_smithy_mocks::mock_client!(aws_sdk_eventbridge, [&rule]);
        let mut t = trap(0);
        t.trap.oid = "1".repeat(300 * 1024);
        assert!(publisher(client, Default::default()).entry(&t).is_err());
    }
}
