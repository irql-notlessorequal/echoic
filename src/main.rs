// echoic, a recursive DNS resolver.
// Copyright (C) IRQL_NOT_LESS_OR_EQUAL
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
use std::process::ExitCode;

use clap::Parser;
use echoic::cli::Cli;
use echoic::config::{Config, LoggingConfig};
use echoic::server::ReloadHandle;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::prelude::*;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("echoic: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    if cli.check_config {
        println!("configuration OK");
        return Ok(());
    }

    let logging_reload = init_logging(&config.logging)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("failed to build async runtime: {error}"))?;
    runtime.block_on(echoic::server::run_with_logging(
        config,
        Some(cli.config.clone()),
        Some(logging_reload),
    ))
}

fn init_logging(logging: &LoggingConfig) -> anyhow::Result<ReloadHandle> {
    logging.level_filter()?;

    let mut directives = vec![logging.level.clone()];
    if logging.level != "off" {
        let hickory_level = if logging.query_names { "info" } else { "warn" };
        for target in ["hickory_server", "hickory_proto", "hickory_net"] {
            directives.push(format!("{target}={hickory_level}"));
        }
        let resolver_level = if logging.query_names { "info" } else { "error" };
        directives.push(format!("hickory_resolver={resolver_level}"));
    }

    let filter = EnvFilter::try_new(directives.join(","))
        .map_err(|error| anyhow::anyhow!("failed to build logging filter: {error}"))?;

    let (filter, reload_handle) = tracing_subscriber::reload::Layer::new(filter);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_ansi(false)
        .with_writer(std::io::stdout);
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();

    Ok(reload_handle)
}
