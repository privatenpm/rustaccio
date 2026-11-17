#![forbid(unsafe_code)]
// Large async runtime futures push rustc's layout query depth past the default
// recursion limit on recent toolchains; raise it for the binary crate.
#![recursion_limit = "256"]

use rustaccio::{
    config::Config,
    runtime::{run_from_env, run_standalone},
};
use std::{path::PathBuf, thread};

const USAGE: &str = "\
Usage: rustaccio [OPTIONS]

Options:
  -c, --config <path>  Path to Verdaccio-style YAML config file
  -h, --help           Print help
";

#[derive(Debug, Default, PartialEq, Eq)]
struct CliOptions {
    config_path: Option<PathBuf>,
    help: bool,
}

fn parse_cli_args<I>(args: I) -> Result<CliOptions, String>
where
    I: IntoIterator<Item = String>,
{
    let mut options = CliOptions::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                options.help = true;
            }
            "-c" | "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --config".to_string())?;
                options.config_path = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--config=") => {
                let value = arg.trim_start_matches("--config=");
                if value.is_empty() {
                    return Err("missing value for --config".to_string());
                }
                options.config_path = Some(PathBuf::from(value));
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    Ok(options)
}

fn parse_env_usize(key: &str, default: usize, min: usize, max: usize) -> usize {
    let raw = load_env_value(key);
    parse_usize_or_default(raw.as_deref(), default, min, max)
}

fn parse_usize_or_default(raw: Option<&str>, default: usize, min: usize, max: usize) -> usize {
    let parsed = raw
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default);
    parsed.clamp(min, max)
}

fn load_env_value(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let available_parallelism = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let worker_threads_default = available_parallelism.clamp(2, 8);
    let worker_threads = parse_env_usize(
        "RUSTACCIO_TOKIO_WORKER_THREADS",
        worker_threads_default,
        1,
        128,
    );
    let max_blocking_threads = parse_env_usize("RUSTACCIO_TOKIO_MAX_BLOCKING_THREADS", 64, 8, 512);
    let thread_stack_size = parse_env_usize(
        "RUSTACCIO_TOKIO_THREAD_STACK_SIZE",
        1024 * 1024,
        256 * 1024,
        16 * 1024 * 1024,
    );

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .thread_stack_size(thread_stack_size)
        .build()
}

fn main() {
    let options = match parse_cli_args(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(err) => {
            eprintln!("{err}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    if options.help {
        println!("{USAGE}");
        return;
    }

    let runtime = match build_runtime() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("failed to initialize tokio runtime: {err}");
            std::process::exit(2);
        }
    };

    let run_result = if let Some(config_path) = options.config_path {
        let config = match Config::from_env_with_config_file(config_path) {
            Ok(config) => config,
            Err(err) => {
                eprintln!("invalid --config value: {err}");
                std::process::exit(2);
            }
        };
        runtime.block_on(run_standalone(config))
    } else {
        runtime.block_on(run_from_env())
    };

    if let Err(err) = run_result {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_cli_args, parse_usize_or_default};
    use std::path::PathBuf;

    #[test]
    fn parses_config_flag_with_space_delimited_value() {
        let parsed = parse_cli_args(vec!["--config".to_string(), "./config.yml".to_string()])
            .expect("parse args");
        assert_eq!(parsed.config_path, Some(PathBuf::from("./config.yml")));
        assert!(!parsed.help);
    }

    #[test]
    fn parses_config_flag_with_equals_value() {
        let parsed = parse_cli_args(vec!["--config=./config.yml".to_string()]).expect("parse args");
        assert_eq!(parsed.config_path, Some(PathBuf::from("./config.yml")));
    }

    #[test]
    fn parses_short_config_flag() {
        let parsed =
            parse_cli_args(vec!["-c".to_string(), "./config.yml".to_string()]).expect("parse args");
        assert_eq!(parsed.config_path, Some(PathBuf::from("./config.yml")));
    }

    #[test]
    fn parses_help_flag() {
        let parsed = parse_cli_args(vec!["--help".to_string()]).expect("parse args");
        assert!(parsed.help);
    }

    #[test]
    fn errors_when_config_value_is_missing() {
        let err = parse_cli_args(vec!["--config".to_string()]).expect_err("missing value");
        assert_eq!(err, "missing value for --config");
    }

    #[test]
    fn errors_on_unknown_flag() {
        let err = parse_cli_args(vec!["--wat".to_string()]).expect_err("unknown arg");
        assert_eq!(err, "unknown argument: --wat");
    }

    #[test]
    fn parse_env_usize_clamps_values() {
        assert_eq!(parse_usize_or_default(Some("900"), 4, 1, 32), 32);
        assert_eq!(parse_usize_or_default(Some("0"), 4, 1, 32), 1);
    }

    #[test]
    fn parse_env_usize_uses_default_for_invalid_values() {
        assert_eq!(parse_usize_or_default(Some("invalid"), 7, 1, 32), 7);
        assert_eq!(parse_usize_or_default(None, 7, 1, 32), 7);
    }
}
