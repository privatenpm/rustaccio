use std::io::IsTerminal;
use std::sync::OnceLock;
#[cfg(feature = "otel")]
use tracing_opentelemetry::OpenTelemetryLayer;
#[cfg(feature = "otel")]
use tracing_subscriber::Registry;
#[cfg(not(feature = "otel"))]
use tracing_subscriber::layer::Identity;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

static TRACING_INIT: OnceLock<()> = OnceLock::new();
const NOISY_DEP_TARGETS: [&str; 9] = [
    "aws_config",
    "aws_runtime",
    "aws_sdk_s3",
    "aws_smithy_runtime",
    "aws_smithy_runtime_api",
    "aws_smithy_http_client",
    "hyper_util",
    "h2",
    "rustls",
];

#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    Pretty,
    Compact,
    Json,
}

impl LogFormat {
    /// Reads `RUSTACCIO_LOG_FORMAT`. `auto` (the default) picks `pretty` for
    /// an interactive terminal and `json` otherwise, so containers and log
    /// shippers get one structured line per event without configuration.
    fn from_env() -> Self {
        Self::parse(
            load_env_value("RUSTACCIO_LOG_FORMAT").as_deref(),
            std::io::stdout().is_terminal(),
        )
    }

    fn parse(raw: Option<&str>, terminal: bool) -> Self {
        match raw
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("json") => Self::Json,
            Some("compact") => Self::Compact,
            Some("pretty") => Self::Pretty,
            _ if terminal => Self::Pretty,
            _ => Self::Json,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pretty => "pretty",
            Self::Compact => "compact",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TracingSettings {
    pub filter: String,
    pub log_format: LogFormat,
}

pub fn init_from_env(default_level: &str) -> TracingSettings {
    let base_filter = load_env_value("RUST_LOG")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("rustaccio={default_level},tower_http=info"));
    let filter = with_noisy_dependency_guards(base_filter);
    let log_format = LogFormat::from_env();

    let env_filter = EnvFilter::try_new(filter.clone())
        .unwrap_or_else(|_| EnvFilter::new("rustaccio=info,tower_http=info"));

    maybe_warn_about_otel_without_feature();

    let ansi = ansi_enabled(
        std::io::stdout().is_terminal(),
        load_env_value("NO_COLOR").as_deref(),
    );

    TRACING_INIT.get_or_init(|| match log_format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(otel_layer_from_env())
                .with(env_filter)
                .with(tracing_error::ErrorLayer::default())
                .with(
                    fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_current_span(true)
                        .with_span_list(false),
                )
                .init();
        }
        LogFormat::Compact => {
            tracing_subscriber::registry()
                .with(otel_layer_from_env())
                .with(env_filter)
                .with(tracing_error::ErrorLayer::default())
                .with(fmt::layer().compact().with_ansi(ansi).with_target(true))
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(otel_layer_from_env())
                .with(env_filter)
                .with(tracing_error::ErrorLayer::default())
                .with(
                    fmt::layer()
                        .pretty()
                        .with_ansi(ansi)
                        .with_target(true)
                        .with_line_number(true),
                )
                .init();
        }
    });

    TracingSettings { filter, log_format }
}

/// Colours only for a terminal, and never when `NO_COLOR` is set to a
/// non-empty value (https://no-color.org).
fn ansi_enabled(terminal: bool, no_color: Option<&str>) -> bool {
    terminal && no_color.is_none_or(str::is_empty)
}

#[cfg(not(feature = "otel"))]
fn maybe_warn_about_otel_without_feature() {
    let enabled = load_env_value("RUSTACCIO_OTEL_ENABLED")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);
    if enabled {
        eprintln!(
            "RUSTACCIO_OTEL_ENABLED is set, but rustaccio was not built with the `otel` feature"
        );
    }
}

#[cfg(feature = "otel")]
fn maybe_warn_about_otel_without_feature() {}

#[cfg(not(feature = "otel"))]
fn otel_layer_from_env() -> Option<Identity> {
    None
}

#[cfg(feature = "otel")]
fn otel_layer_from_env() -> Option<OpenTelemetryLayer<Registry, opentelemetry_sdk::trace::Tracer>> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;

    let enabled = load_env_value("RUSTACCIO_OTEL_ENABLED")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);
    if !enabled {
        return None;
    }

    let endpoint = load_env_value("RUSTACCIO_OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|| "http://127.0.0.1:4318/v1/traces".to_string());
    let service_name =
        load_env_value("RUSTACCIO_OTEL_SERVICE_NAME").unwrap_or_else(|| "rustaccio".to_string());

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
        .ok()?;
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer(service_name);
    opentelemetry::global::set_tracer_provider(provider);

    Some(tracing_opentelemetry::layer().with_tracer(tracer))
}

fn with_noisy_dependency_guards(filter: String) -> String {
    let verbose_dependencies = load_env_value("RUSTACCIO_VERBOSE_DEP_LOGS")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);
    if verbose_dependencies {
        return filter;
    }

    let mut directives = filter;
    for target in NOISY_DEP_TARGETS {
        if !has_target_directive(&directives, target) {
            directives.push(',');
            directives.push_str(target);
            directives.push_str("=warn");
        }
    }
    directives
}

fn load_env_value(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn has_target_directive(filter: &str, target: &str) -> bool {
    filter
        .split(',')
        .map(str::trim)
        .any(|directive| directive.starts_with(&format!("{target}=")))
}

#[cfg(test)]
mod tests {
    use super::{LogFormat, ansi_enabled, has_target_directive, with_noisy_dependency_guards};

    #[test]
    fn auto_format_follows_the_terminal() {
        assert!(matches!(LogFormat::parse(None, true), LogFormat::Pretty));
        assert!(matches!(LogFormat::parse(None, false), LogFormat::Json));
        assert!(matches!(
            LogFormat::parse(Some("auto"), false),
            LogFormat::Json
        ));
    }

    #[test]
    fn explicit_format_wins_over_the_terminal() {
        assert!(matches!(
            LogFormat::parse(Some("pretty"), false),
            LogFormat::Pretty
        ));
        assert!(matches!(
            LogFormat::parse(Some(" JSON "), true),
            LogFormat::Json
        ));
        assert!(matches!(
            LogFormat::parse(Some("compact"), true),
            LogFormat::Compact
        ));
    }

    #[test]
    fn ansi_only_on_a_terminal_without_no_color() {
        assert!(ansi_enabled(true, None));
        assert!(ansi_enabled(true, Some("")));
        assert!(!ansi_enabled(true, Some("1")));
        assert!(!ansi_enabled(false, None));
    }

    #[test]
    fn appends_dependency_guards_to_global_debug_filter() {
        let out = with_noisy_dependency_guards("debug".to_string());
        assert!(out.contains("aws_sdk_s3=warn"));
        assert!(out.contains("aws_smithy_runtime=warn"));
    }

    #[test]
    fn keeps_explicit_dependency_directive() {
        let out = with_noisy_dependency_guards("rustaccio=debug,aws_sdk_s3=debug".to_string());
        assert!(out.contains("aws_sdk_s3=debug"));
        assert!(!out.contains("aws_sdk_s3=warn"));
    }

    #[test]
    fn detects_existing_target_directive() {
        assert!(has_target_directive(
            "a=b,aws_smithy_runtime=trace",
            "aws_smithy_runtime"
        ));
        assert!(!has_target_directive(
            "a=b,aws_smithy=trace",
            "aws_smithy_runtime"
        ));
    }
}
