//! Enforces the format-version independence rule: the v1, v2, and v3
//! modules must never reference each other, so a change to one format can
//! never silently alter another. Neutral shared modules (memory, errors,
//! file, ...) are exempt; only cross-version references are forbidden.
//!
//! This runs as a normal test, so the rule is checked locally and in CI
//! without any extra tooling.

use std::path::Path;

const VERSIONS: &[&str] = &["v1", "v2", "v3"];

/// Collects every `.rs` file under `dir`, recursively.
fn rust_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn format_versions_never_reference_each_other() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    for version in VERSIONS {
        let mut sources = Vec::new();
        rust_sources(&src.join(version), &mut sources);
        assert!(
            !sources.is_empty(),
            "no sources found for {version} — did the layout change?"
        );

        let forbidden: Vec<String> = VERSIONS
            .iter()
            .filter(|other| *other != version)
            .flat_map(|other| {
                [
                    format!("crate::{other}"),
                    format!("shadow_crypt_core::{other}"),
                ]
            })
            .collect();

        for path in sources {
            let content = std::fs::read_to_string(&path).unwrap();
            for (line_no, line) in content.lines().enumerate() {
                // Comments may mention other versions (e.g. the module docs
                // explaining this very rule); only code references count.
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for needle in &forbidden {
                    assert!(
                        !line.contains(needle.as_str()),
                        "{}:{}: {} module references another format version: {}",
                        path.display(),
                        line_no + 1,
                        version,
                        line.trim()
                    );
                }
            }
        }
    }
}
