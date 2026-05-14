.DEFAULT_GOAL := help

VERSION ?=

.PHONY: help fmt check bump release

help:
	@printf "%-12s %s\n" "fmt"     "Format all code"
	@printf "%-12s %s\n" "check"   "Run full CI chain locally (fmt, clippy, test, audit)"
	@printf "%-12s %s\n" "bump"    "Bump version in Cargo.toml and CHANGELOG  VERSION=x.y.z"
	@printf "%-12s %s\n" "release" "check + bump + commit + tag + push         VERSION=x.y.z"

# ── Development ──────────────────────────────────────────────────────────────

fmt:
	cargo fmt --all

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	cargo audit

# ── Release ──────────────────────────────────────────────────────────────────

bump:
	@[ -n "$(VERSION)" ] || { echo "error: VERSION required — make $@ VERSION=x.y.z"; exit 1; }
	@sed -i '' 's/^version = ".*"/version = "$(VERSION)"/' Cargo.toml
	@DATE=$$(date +%Y-%m-%d); \
	awk -v ver="$(VERSION)" -v date="$$DATE" \
		'/## \[Unreleased\]/{print; print ""; print "## [" ver "] - " date; next} 1' \
		CHANGELOG.md > CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md
	@echo "→ bumped to v$(VERSION)"

release:
	@[ -n "$(VERSION)" ] || { echo "error: VERSION required — make $@ VERSION=x.y.z"; exit 1; }
	@echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' \
		|| { echo "error: VERSION must be semver (e.g. 1.2.3), got: $(VERSION)"; exit 1; }
	@git diff --quiet && git diff --cached --quiet \
		|| { echo "error: working tree is dirty — commit or stash changes first"; exit 1; }
	@$(MAKE) --no-print-directory check
	@$(MAKE) --no-print-directory bump VERSION=$(VERSION)
	git add Cargo.toml Cargo.lock CHANGELOG.md
	git commit -m "chore: bump version to v$(VERSION)"
	git tag "v$(VERSION)"
	git push origin trunk "v$(VERSION)"
