use std::collections::HashSet;

use super::super::{
    context::CoverContext,
    grammar::templates,
    lexicon::{EventFamily, ReportState, Slot},
    vocabulary::{BUILD_STATES, DEPLOY_STATES, METRIC_STATES, TRACE_RESULTS},
    words, CHOICES_PER_SENTENCE,
};

#[path = "schema_policy.rs"]
mod policy;
#[path = "schema_rendering.rs"]
mod rendering;

fn assert_key_order(rendered: &str, keys: &[&str]) {
    let mut cursor = 0;
    for key in keys {
        let found = rendered[cursor..]
            .find(key)
            .unwrap_or_else(|| panic!("missing key {key:?} in {rendered}"))
            + cursor;
        assert!(found >= cursor, "out-of-order key {key:?}: {rendered}");
        cursor = found + key.len();
    }
}
