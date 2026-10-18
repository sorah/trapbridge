//! Prometheus metrics, exposed in OpenMetrics text format by `crate::http`.

/// Why a received message was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// Malformed message, or a notification trapbridge cannot convert.
    Parse,
    /// v1/v2c community not accepted.
    Community,
    /// SNMPv3 user unknown, or authentication or decryption failed.
    Usm,
    /// Valid message trapbridge does not handle (SNMP version, PDU type, v3 Inform).
    Unsupported,
}

impl DropReason {
    const ALL: [DropReason; 4] = [
        DropReason::Parse,
        DropReason::Community,
        DropReason::Usm,
        DropReason::Unsupported,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            DropReason::Parse => "parse",
            DropReason::Community => "community",
            DropReason::Usm => "usm",
            DropReason::Unsupported => "unsupported",
        }
    }
}

impl prometheus_client::encoding::EncodeLabelValue for DropReason {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), std::fmt::Error> {
        std::fmt::Write::write_str(encoder, self.as_str())
    }
}

impl prometheus_client::encoding::EncodeLabelValue for crate::trap::Version {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), std::fmt::Error> {
        let value = match self {
            crate::trap::Version::V1 => "v1",
            crate::trap::Version::V2c => "v2c",
            crate::trap::Version::V3 => "v3",
        };
        std::fmt::Write::write_str(encoder, value)
    }
}

impl prometheus_client::encoding::EncodeLabelValue for crate::trap::PduType {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), std::fmt::Error> {
        let value = match self {
            crate::trap::PduType::Trap => "trap",
            crate::trap::PduType::Inform => "inform",
        };
        std::fmt::Write::write_str(encoder, value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, prometheus_client::encoding::EncodeLabelSet)]
struct ReceivedLabels {
    version: crate::trap::Version,
    pdu_type: crate::trap::PduType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, prometheus_client::encoding::EncodeLabelSet)]
struct DroppedLabels {
    reason: DropReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, prometheus_client::encoding::EncodeLabelSet)]
struct FailedLabels {
    error_code: String,
}

type CounterFamily<L> =
    prometheus_client::metrics::family::Family<L, prometheus_client::metrics::counter::Counter>;

/// Registry and metric families; shared by listeners, the publisher and the HTTP server.
#[derive(Debug)]
pub struct Metrics {
    registry: prometheus_client::registry::Registry,
    received: CounterFamily<ReceivedLabels>,
    dropped: CounterFamily<DroppedLabels>,
    events_put: prometheus_client::metrics::counter::Counter,
    events_failed: CounterFamily<FailedLabels>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = prometheus_client::registry::Registry::with_prefix("trapbridge");
        let received = CounterFamily::<ReceivedLabels>::default();
        let dropped = CounterFamily::<DroppedLabels>::default();
        let events_put = prometheus_client::metrics::counter::Counter::default();
        let events_failed = CounterFamily::<FailedLabels>::default();
        registry.register(
            "received",
            "SNMP notifications decoded successfully",
            received.clone(),
        );
        registry.register(
            "dropped",
            "SNMP messages dropped without producing an event",
            dropped.clone(),
        );
        registry.register(
            "events_put",
            "Events accepted by PutEvents, or printed in dry-run mode",
            events_put.clone(),
        );
        registry.register(
            "events_failed",
            "Events that could not be delivered",
            events_failed.clone(),
        );
        // Expose every reason from the start so rate() works on the first drop.
        for reason in DropReason::ALL {
            let _ = dropped.get_or_create(&DroppedLabels { reason });
        }
        Self {
            registry,
            received,
            dropped,
            events_put,
            events_failed,
        }
    }

    pub fn received(&self, trap: &crate::trap::Trap) {
        self.received
            .get_or_create(&ReceivedLabels {
                version: trap.version,
                pdu_type: trap.pdu_type,
            })
            .inc();
    }

    pub fn dropped(&self, reason: DropReason) {
        self.dropped.get_or_create(&DroppedLabels { reason }).inc();
    }

    pub fn events_put(&self, count: usize) {
        self.events_put.inc_by(count as u64);
    }

    pub fn events_failed(&self, error_code: &str) {
        self.events_failed
            .get_or_create(&FailedLabels {
                error_code: error_code.to_owned(),
            })
            .inc();
    }

    /// OpenMetrics text exposition.
    pub fn encode(&self) -> crate::Result<String> {
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &self.registry)
            .map_err(|e| crate::Error::Other(format!("failed to encode metrics: {e}")))?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn encode_lists_counters_with_labels() {
        let metrics = crate::metrics::Metrics::new();
        metrics.dropped(crate::metrics::DropReason::Community);
        metrics.events_put(3);
        metrics.events_failed("ThrottlingException");
        let text = metrics.encode().unwrap();
        assert!(
            text.contains("trapbridge_dropped_total{reason=\"community\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("trapbridge_dropped_total{reason=\"usm\"} 0\n"),
            "{text}"
        );
        assert!(text.contains("trapbridge_events_put_total 3\n"), "{text}");
        assert!(
            text.contains("trapbridge_events_failed_total{error_code=\"ThrottlingException\"} 1\n"),
            "{text}"
        );
        assert!(text.ends_with("# EOF\n"), "{text}");
    }
}
