//! Reverse DNS lookups for trap sender addresses. The resolver cache honours
//! record TTLs.

pub struct ReverseDns {
    resolver: hickory_resolver::TokioResolver,
}

impl std::fmt::Debug for ReverseDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReverseDns").finish_non_exhaustive()
    }
}

impl ReverseDns {
    /// Uses the system resolver configuration. `max_ttl` caps how long any
    /// answer, positive or negative, stays cached.
    pub fn new(timeout: std::time::Duration, max_ttl: std::time::Duration) -> crate::Result<Self> {
        let mut builder = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| crate::Error::Other(format!("failed to load resolver config: {e}")))?;
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 1;
        opts.positive_max_ttl = Some(max_ttl);
        opts.negative_max_ttl = Some(max_ttl);
        let resolver = builder
            .build()
            .map_err(|e| crate::Error::Other(format!("failed to build resolver: {e}")))?;
        Ok(Self { resolver })
    }

    /// Failures and timeouts yield `None`.
    pub async fn lookup(&self, addr: std::net::IpAddr) -> Option<String> {
        match self.resolver.reverse_lookup(addr).await {
            Ok(lookup) => lookup
                .answers()
                .iter()
                .find_map(|record| match &record.data {
                    hickory_resolver::proto::rr::RData::PTR(ptr) => {
                        Some(ptr.0.to_utf8().trim_end_matches('.').to_owned())
                    }
                    _ => None,
                }),
            Err(e) => {
                tracing::debug!(%addr, error = %e, "reverse DNS lookup failed");
                None
            }
        }
    }
}
