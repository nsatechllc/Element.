/*
 Telemetry & Tracing Initialization (OpenTelemetry optional)
*/
use tracing_subscriber::{layer::SubscriberExt, Registry, util::SubscriberInitExt};
#[cfg(feature = "otel")] use {opentelemetry_sdk::{trace as sdktrace, Resource, trace::TracerProvider as SdkTracerProvider}, opentelemetry::trace::TracerProvider, opentelemetry::KeyValue, tracing_opentelemetry::OpenTelemetryLayer};

pub fn init(_service_name: &'static str) {
    // If already set up, don't double init.
    if tracing::dispatcher::has_been_set() { return; }
    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    #[cfg(feature = "otel")]
    {
        let git_sha = std::env::var("GIT_SHA").unwrap_or_else(|_| "unknown".into());
        let tracer_provider = SdkTracerProvider::builder()
            .with_config(sdktrace::Config::default().with_resource(Resource::new(vec![
                KeyValue::new("service.name", service_name.to_string()),
                KeyValue::new("git.sha", git_sha),
            ])))
            .build()
            ;
        let tracer = tracer_provider.tracer(service_name);
        let otel_layer = OpenTelemetryLayer::new(tracer);
        let fmt_layer = tracing_subscriber::fmt::layer().with_target(false).with_ansi(false).with_level(true).json();
        let filter = tracing_subscriber::EnvFilter::new(env_filter);
    let _ = Registry::default().with(filter).with(fmt_layer).with(otel_layer).try_init();
        return;
    }
    #[cfg(not(feature = "otel"))]
    {
        let fmt_layer = tracing_subscriber::fmt::layer().with_target(false).with_ansi(false).with_level(true).json();
        let filter = tracing_subscriber::EnvFilter::new(env_filter);
    let _ = Registry::default().with(filter).with(fmt_layer).try_init();
    }
}

use axum::{http::Request, response::Response};
use tower::{Layer, Service};
use uuid::Uuid;
use std::task::{Context, Poll};

#[derive(Clone)] pub struct RequestIdLayer;
impl<S> Layer<S> for RequestIdLayer { type Service = RequestIdMiddleware<S>; fn layer(&self, inner: S) -> Self::Service { RequestIdMiddleware { inner } } }

#[derive(Clone)] pub struct RequestIdMiddleware<S> { inner: S }
impl<S, B> Service<Request<B>> for RequestIdMiddleware<S>
where S: Service<Request<B>, Response = Response> + Clone + Send + 'static, S::Future: Send + 'static, B: Send + 'static {
    type Response = S::Response; type Error = S::Error; type Future = S::Future;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { self.inner.poll_ready(cx) }
    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let rid = Uuid::new_v4().to_string();
        req.headers_mut().insert("x-request-id", axum::http::HeaderValue::from_str(&rid).unwrap());
        tracing::Span::current().record("request_id", &tracing::field::display(&rid));
        self.inner.call(req)
    }
}