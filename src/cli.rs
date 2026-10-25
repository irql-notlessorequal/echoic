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
use std::path::PathBuf;

use clap::Parser;

use crate::config::DEFAULT_CONFIG_PATH;

#[derive(Debug, Parser)]
#[command(
    name = "echoic",
    version,
    about = "A recursive DNS resolver with DNSSEC, DoT and DoH support"
)]
pub struct Cli {
    #[arg(
        long,
        value_name = "PATH",
        default_value = DEFAULT_CONFIG_PATH,
        help = "Path to the TOML configuration file"
    )]
    pub config: PathBuf,
    #[arg(
        long,
        help = "Validate the configuration file and exit without starting listeners"
    )]
    pub check_config: bool,
}
