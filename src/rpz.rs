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
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use anyhow::Context;

use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_server::proto::serialize::txt::Parser;

#[derive(Debug, Clone)]
pub enum RpzAction {
    Nxdomain,
    Nodata,
    Passthru,
    Drop,
    TcpOnly,
    Redirect(Name, u32),
    LocalData(Vec<Record>),
}

#[derive(Debug, Clone)]
pub struct RpzPolicy {
    exact: HashMap<LowerName, RpzAction>,
    wildcards: Vec<(LowerName, RpzAction)>,
}

impl RpzPolicy {
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            exact: HashMap::new(),
            wildcards: Vec::new(),
        })
    }

    pub fn load(paths: &[std::path::PathBuf], origin: Option<&str>) -> anyhow::Result<Arc<Self>> {
        let mut exact = HashMap::new();
        let mut wildcards = Vec::new();
        let configured_origin = origin
            .map(Name::from_str)
            .transpose()
            .map_err(|error| anyhow::anyhow!("invalid RPZ origin: {error}"))?;

        for path in paths {
            let contents = fs::read_to_string(path)
                .with_context(|| format!("failed to read RPZ {}", path.display()))?;
            let (parsed_origin, records) = Parser::new(
                contents,
                Some(path.to_path_buf()),
                configured_origin.clone(),
            )
            .parse()
            .map_err(|error| anyhow::anyhow!("failed to parse RPZ {}: {error}", path.display()))?;

            for (key, record_set) in records {
                let owner = key.name;
                let origin_lower = LowerName::new(&parsed_origin);

                let owner_name = owner.to_string();
                let origin_name = parsed_origin.to_string();
                let trigger_name = if owner == origin_lower {
                    ".".to_string()
                } else if parsed_origin == Name::root() {
                    owner_name.clone()
                } else {
                    let stripped = owner_name.strip_suffix(&origin_name).ok_or_else(|| {
                        anyhow::anyhow!(
                            "RPZ owner {} is not under origin {}",
                            owner_name,
                            origin_name
                        )
                    })?;
                    stripped.to_string()
                };

                let mut cname_target = None;
                let mut cname_ttl = 300u32;
                let mut local_data = Vec::new();
                for record in record_set.records_without_rrsigs() {
                    match record.record_type() {
                        RecordType::CNAME => {
                            if let RData::CNAME(cname) = &record.data {
                                cname_target = Some(cname.0.clone());
                                cname_ttl = record.ttl;
                            }
                        }
                        RecordType::SOA | RecordType::NS => {}
                        _ => local_data.push(record.clone()),
                    }
                }

                let action = if let Some(target) = cname_target {
                    if target == Name::root() {
                        RpzAction::Nxdomain
                    } else if target == Name::from_str("*.").unwrap_or_else(|_| Name::root()) {
                        RpzAction::Nodata
                    } else if target
                        == Name::from_str("rpz-passthru.").unwrap_or_else(|_| Name::root())
                    {
                        RpzAction::Passthru
                    } else if target == Name::from_str("rpz-drop.").unwrap_or_else(|_| Name::root())
                    {
                        RpzAction::Drop
                    } else if target
                        == Name::from_str("rpz-tcp-only.").unwrap_or_else(|_| Name::root())
                    {
                        RpzAction::TcpOnly
                    } else {
                        RpzAction::Redirect(target, cname_ttl)
                    }
                } else if !local_data.is_empty() {
                    RpzAction::LocalData(local_data)
                } else {
                    continue;
                };

                let trigger = LowerName::from_str(&trigger_name).map_err(|error| {
                    anyhow::anyhow!("invalid RPZ trigger {trigger_name}: {error}")
                })?;

                if let Some(stripped) = trigger_name.strip_prefix("*.") {
                    let suffix = LowerName::from_str(stripped).map_err(|error| {
                        anyhow::anyhow!("invalid RPZ wildcard {trigger_name}: {error}")
                    })?;
                    if !wildcards.iter().any(|(existing, _)| existing == &suffix) {
                        wildcards.push((suffix, action));
                    }
                } else {
                    exact.entry(trigger).or_insert(action);
                }
            }
        }

        wildcards.sort_by(|(left, _), (right, _)| {
            let left_labels = left.to_string().matches('.').count();
            let right_labels = right.to_string().matches('.').count();
            right_labels
                .cmp(&left_labels)
                .then_with(|| right.to_string().len().cmp(&left.to_string().len()))
        });

        Ok(Arc::new(Self { exact, wildcards }))
    }

    pub fn evaluate(&self, name: &Name) -> Option<RpzAction> {
        let lower = LowerName::new(name);
        if let Some(action) = self.exact.get(&lower) {
            return Some(action.clone());
        }

        for (suffix, action) in &self.wildcards {
            let name = lower.to_string();
            let suffix = suffix.to_string();
            if name != suffix
                && name.len() > suffix.len()
                && name.ends_with(&suffix)
                && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
            {
                return Some(action.clone());
            }
        }

        None
    }
}

use std::str::FromStr;
