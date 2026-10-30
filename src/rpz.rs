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
    LocalData(Arc<[Record]>),
}

fn merge_local_data(existing: &mut RpzAction, action: RpzAction) {
    if let (RpzAction::LocalData(existing), RpzAction::LocalData(new)) = (existing, action) {
        let mut records = Vec::with_capacity(existing.len() + new.len());
        records.extend(existing.iter().cloned());
        records.extend(new.iter().cloned());
        *existing = Arc::from(records);
    }
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

        let nodata_target = Name::from_str("*.").expect("valid RPZ NODATA target");
        let passthru_target = Name::from_str("rpz-passthru.").expect("valid RPZ passthru target");
        let drop_target = Name::from_str("rpz-drop.").expect("valid RPZ drop target");
        let tcp_only_target = Name::from_str("rpz-tcp-only.").expect("valid RPZ TCP-only target");

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

            let origin_lower = LowerName::new(&parsed_origin);
            let origin_name = origin_lower.to_string();

            for (key, record_set) in records {
                let owner = key.name;
                let owner_name = owner.to_string();
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
                    if !stripped.ends_with('.') {
                        return Err(anyhow::anyhow!(
                            "RPZ owner {} is not under origin {}",
                            owner_name,
                            origin_name
                        ));
                    }
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
                    } else if target == nodata_target {
                        RpzAction::Nodata
                    } else if target == passthru_target {
                        RpzAction::Passthru
                    } else if target == drop_target {
                        RpzAction::Drop
                    } else if target == tcp_only_target {
                        RpzAction::TcpOnly
                    } else {
                        RpzAction::Redirect(target, cname_ttl)
                    }
                } else if !local_data.is_empty() {
                    RpzAction::LocalData(Arc::from(local_data))
                } else {
                    continue;
                };

                let trigger = LowerName::from_str(&trigger_name).map_err(|error| {
                    anyhow::anyhow!("invalid RPZ trigger {trigger_name}: {error}")
                })?;

                if let Some(stripped) = trigger_name.strip_prefix("*.") {
                    let suffix = if stripped.is_empty() {
                        LowerName::new(&Name::root())
                    } else {
                        LowerName::from_str(stripped).map_err(|error| {
                            anyhow::anyhow!("invalid RPZ wildcard {trigger_name}: {error}")
                        })?
                    };
                    if let Some((_, existing)) = wildcards
                        .iter_mut()
                        .find(|(existing, _)| existing == &suffix)
                    {
                        merge_local_data(existing, action);
                    } else {
                        wildcards.push((suffix, action));
                    }
                } else if let Some(existing) = exact.get_mut(&trigger) {
                    merge_local_data(existing, action);
                } else {
                    exact.insert(trigger, action);
                }
            }
        }

        wildcards.sort_by(|(left, _), (right, _)| {
            right
                .num_labels()
                .cmp(&left.num_labels())
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
            if *suffix != lower && suffix.zone_of(&lower) {
                return Some(action.clone());
            }
        }

        None
    }
}

use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;

    fn write_policy(contents: &str) -> (tempfile::TempDir, Vec<std::path::PathBuf>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.rpz");
        std::fs::write(&path, contents).unwrap();
        (dir, vec![path])
    }

    #[test]
    fn origin_requires_a_label_boundary() {
        let (_dir, paths) = write_policy(
            r#"
$ORIGIN example.com.
@ 300 SOA localhost. root.localhost. 1 1h 15m 30d 2h
@ NS localhost.
notexample.com. CNAME rpz-passthru.
"#,
        );

        assert!(RpzPolicy::load(&paths, None).is_err());
    }

    #[test]
    fn root_wildcard_matches_names_outside_the_origin() {
        let (_dir, paths) = write_policy(
            r#"
$ORIGIN rpz.local.
@ 300 SOA localhost. root.localhost. 1 1h 15m 30d 2h
@ NS localhost.
* CNAME rpz-drop.
"#,
        );

        let policy = RpzPolicy::load(&paths, None).unwrap();
        let name = Name::from_ascii("example.net.").unwrap();
        assert!(matches!(policy.evaluate(&name), Some(RpzAction::Drop)));
    }

    #[test]
    fn wildcard_match_respects_label_boundaries() {
        let (_dir, paths) = write_policy(
            r#"
$ORIGIN rpz.local.
@ 300 SOA localhost. root.localhost. 1 1h 15m 30d 2h
@ NS localhost.
*.example.com.rpz.local. CNAME rpz-drop.
"#,
        );

        let policy = RpzPolicy::load(&paths, None).unwrap();
        assert!(matches!(
            policy.evaluate(&Name::from_ascii("a.example.com.").unwrap()),
            Some(RpzAction::Drop)
        ));
        assert!(
            policy
                .evaluate(&Name::from_ascii("notexample.com.").unwrap())
                .is_none()
        );
    }
}
