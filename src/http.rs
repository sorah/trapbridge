//! HTTP listener for health checks (`/healthz`) and Prometheus scraping (`/metrics`).

const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

pub fn router(metrics: std::sync::Arc<crate::metrics::Metrics>) -> axum::Router {
    axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/metrics", axum::routing::get(metrics_handler))
        .with_state(metrics)
}

/// Bind the HTTP listener socket.
pub async fn bind(addr: std::net::SocketAddr) -> crate::Result<tokio::net::TcpListener> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| crate::Error::Other(format!("failed to bind {addr}: {e}")))?;
    tracing::info!(addr = %listener.local_addr()?, "listening for HTTP");
    Ok(listener)
}

/// Serve until the listener fails.
pub async fn serve(
    listener: tokio::net::TcpListener,
    metrics: std::sync::Arc<crate::metrics::Metrics>,
) -> crate::Result<()> {
    axum::serve(listener, router(metrics)).await?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics_handler(
    axum::extract::State(metrics): axum::extract::State<std::sync::Arc<crate::metrics::Metrics>>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    match metrics.encode() {
        Ok(body) => (
            [(axum::http::header::CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE)],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to encode metrics");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    async fn get(
        router: axum::Router,
        path: &str,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
        use tower::ServiceExt as _;
        let response = router
            .oneshot(
                axum::http::Request::get(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let router = crate::http::router(Default::default());
        let (status, _, body) = get(router, "/healthz").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn metrics_returns_openmetrics_text() {
        let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
        metrics.events_put(2);
        let (status, headers, body) = get(crate::http::router(metrics), "/metrics").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(
            headers[axum::http::header::CONTENT_TYPE],
            crate::http::OPENMETRICS_CONTENT_TYPE
        );
        assert!(body.contains("trapbridge_events_put_total 2\n"), "{body}");
    }

    #[tokio::test]
    async fn unknown_path_is_not_found() {
        let router = crate::http::router(Default::default());
        let (status, _, _) = get(router, "/").await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }
}
