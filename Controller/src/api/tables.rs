/* Copyright 2022-present University of Tuebingen, Chair of Communication Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Steffen Lindner (steffen.lindner@uni-tuebingen.de)
 */

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Json, IntoResponse, Response};
use rbfrt::table;
use rbfrt::table::{MatchValue, TableEntry, ToBytes};
use serde::{Serialize, Serializer};
use crate::api::server::Error;
use crate::AppState;

fn ordered_map<S, K: Ord + Serialize, V: Serialize>(
    value: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}

#[derive(Serialize)]
pub struct Tables {
    #[serde(serialize_with = "ordered_map")]
    tables: HashMap<String, Vec<TableDescriptor>>
}

#[derive(Serialize)]
pub struct TableDescriptor {
    #[serde(serialize_with = "ordered_map")]
    key: HashMap<String, Value>,
    #[serde(serialize_with = "ordered_map")]
    data: HashMap<String, String>
}

#[derive(Serialize)]
pub struct Value {
    value: String
}

pub async fn tables(State(state): State<Arc<AppState>>) -> Response {
    let table_names = ["ingress.p4tg.monitor_forward",
        "ingress.p4tg.forward",
        "ingress.p4tg.frame_type.frame_type_monitor",
        "ingress.p4tg.frame_type.ethernet_type_monitor",
        "ingress.p4tg.tg_forward",
        "egress.frame_size_monitor",
        "egress.is_egress",
        "egress.is_tx_recirc",
        "egress.header_replace.header_replace",
        "egress.header_replace.vlan_header_replace",
        "egress.header_replace.mpls_rewrite_c.mpls_header_replace",
    "egress.is_egress"];

    // read all table entries
    let all_entries = {
        let switch = &state.switch;
        let mut all_entries: Vec<(String, Vec<TableEntry>)> = vec![];

        for t in table_names {
            let req = table::Request::new(t);
            let entries = switch.get_table_entry(req).await;

            match entries {
                Ok(e) => {
                    all_entries.push((t.to_owned(), e));
                }
                Err(err) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(Error::new(format!("Error while reading table: {}. Error: {:#?}", t, err)))).into_response();
                }
            }
        }

        all_entries
    };

    let mut table_descriptor = Tables { tables: Default::default() };

    for (table, entries) in &all_entries {
        let mut all_descriptors = vec![];

        for e in entries {
            let mut descriptor = TableDescriptor { key: Default::default(), data: Default::default() };

            // ignore default entry
            if e.default_entry {
                continue;
            }

            let key_val: Vec<(String, String)> = e.match_key.clone().into_iter().map(|(k, v)| {
                let key_val = match v {
                    MatchValue::ExactValue { bytes } => {
                        format!("{}", bytes.to_u128())
                    }
                    MatchValue::RangeValue { lower_bytes, higher_bytes } => {
                        format!("({}, {})", lower_bytes.to_u128(), higher_bytes.to_u128())
                    }
                    MatchValue::LPM { bytes, prefix_length } => {
                        format!("{}/{}", bytes.to_u128(), prefix_length)
                    }
                    MatchValue::Ternary { mask, value } => {
                        format!("{} && {}", mask.to_u128(), value.to_u128())
                    }
                };

                (k, key_val)
            }).collect();

            let mut data_val: Vec<(String, String)> = e.action_data.clone().into_iter().map(|a| {
                (a.get_name().to_owned(), format!("{}", a.get_data().to_u128()))
            }).collect();

            data_val.push(("action".to_owned(), e.action.clone()));

            for v in key_val {
                descriptor.key.insert(v.0, Value { value: v.1});
            }

            for v in data_val {
                descriptor.data.insert(v.0, v.1);
            }

            all_descriptors.push(descriptor);
        }

        table_descriptor.tables.insert(table.to_owned(), all_descriptors);
    }


    (StatusCode::OK, Json(table_descriptor.tables)).into_response()
}