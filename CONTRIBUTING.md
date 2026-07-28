# Contributing to NetGauze

Thanks for your interest in NetGauze. This document covers the legal sign-off we
require on every commit, how to get a development environment working, and the
conventions the codebase follows.

NetGauze is licensed under the [Apache License 2.0](LICENSE). Contributions are
accepted under the same license.

---

## Developer Certificate of Origin (DCO)

Like the Linux kernel, NetGauze requires every commit to carry a `Signed-off-by`
line. This is **not** a copyright assignment; i.e., you keep your copyright. It is a
statement that you have the right to submit the code under the project's license.

By signing off, you certify the following:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

In practice this means each commit message ends with:

```
Signed-off-by: Jane Developer <jane@example.com>
```

Use your real name and a real email address. Pseudonyms and anonymous
contributions cannot be accepted, for the same reason the kernel does not accept
them: the sign-off has to mean something.

### Setting up sign-off in git

**1. Make sure git knows who you are.** The sign-off is generated from these two
values, so they must be set before you commit:

```bash
git config --global user.name "Jane Developer"
git config --global user.email "jane@example.com"
```

To use a different identity for this project only, drop `--global` while inside
the repository.

**2. Sign off when committing** with the `-s` (or `--signoff`) flag:

```bash
git commit -s -m "bgp-pkt: add support for the FQDN capability"
```

**3. Optional — make it automatic.** If you would rather not remember the flag,
install a `prepare-commit-msg` hook that adds the trailer for you:

```bash
cat > .git/hooks/prepare-commit-msg <<'EOF'
#!/bin/sh
# Append a Signed-off-by trailer unless one is already present.
NAME=$(git config user.name)
EMAIL=$(git config user.email)
grep -qs "^Signed-off-by: $NAME <$EMAIL>$" "$1" || \
    printf '\nSigned-off-by: %s <%s>\n' "$NAME" "$EMAIL" >> "$1"
EOF
chmod +x .git/hooks/prepare-commit-msg
```

Note that `.git/hooks/` is local to your clone and is not committed, so you will
need to do this once per clone.

A lighter-weight alternative is an alias:

```bash
git config --global alias.ci "commit -s"
```

### Fixing a commit that is missing the sign-off

For the most recent commit:

```bash
git commit --amend --signoff --no-edit
```

For a whole branch, re-apply every commit with a sign-off:

```bash
git rebase --signoff main
```

Then force-push your branch (`git push --force-with-lease`). Rewriting history
on your own PR branch is fine and expected here.

### Sign-off is not the same as a GPG signature

These are easy to confuse because the flags differ by one letter:

| Flag            | What it does                                                    |
|-----------------|-----------------------------------------------------------------|
| `git commit -s` | Adds the `Signed-off-by:` trailer — **this is what we require** |
| `git commit -S` | Cryptographically signs the commit with GPG/SSH — optional      |

GPG signing is welcome but not required. The DCO sign-off is required.

---

## Development environment

NetGauze is a Cargo workspace. Besides a Rust toolchain you need a working C/C++
toolchain and a few development libraries, because some dependencies build
native code.

Most of this comes from **libyang**: `netgauze-yang-push` and
`netgauze-collector` depend on `yang4`, which is declared with
`features = ["bundled"]`, so `libyang4-sys` **compiles libyang from source with
CMake** as part of `cargo build`. That is what pulls in CMake, a C/C++ compiler
and PCRE2.

**Debian / Ubuntu**

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    cmake \
    git \
    curl \
    libpcre2-dev \
    libcurl4-openssl-dev \
    libssl-dev
```

**Fedora / RHEL**

```bash
sudo dnf install -y \
    gcc \
    gcc-c++ \
    pcre2-devel \
    perl-core \
    cmake \
    git \
    libcurl-devel \
    openssl-devel
```

**macOS**

```bash
brew install cmake pcre2 pkg-config
```

On macOS you may also need to point the compiler at Homebrew's headers, which is, what the CI does:

```bash
export C_INCLUDE_PATH="$C_INCLUDE_PATH:$HOMEBREW_PREFIX/include"
```

What each dependency is for:

| Dependency                               | Needed by                                                                                                |
|------------------------------------------|----------------------------------------------------------------------------------------------------------|
| C/C++ compiler, `cmake`                  | building bundled libyang (`libyang4-sys`)                                                                |
| `libpcre2-dev` / `pcre2-devel`           | libyang links against PCRE2                                                                              |
| `pkg-config`                             | locating PCRE2 and OpenSSL during builds                                                                 |
| `libssl-dev` / `openssl-devel`           | `openssl-sys`, via `rdkafka` in the collector                                                            |
| `perl` / `perl-core`                     | building the vendored OpenSSL (`openssl-src`); already present on most Debian images, explicit on Fedora |
| `libcurl4-openssl-dev` / `libcurl-devel` | `curl-sys`                                                                                               |
| `git`                                    | fetching sources at build time                                                                           |

You do **not** need `libclang`: `libyang4-sys` ships pre-generated bindings and
only uses `bindgen` behind an opt-in feature.

If you are only working on the protocol crates, you can skip libyang entirely by
building just what you need — the native dependencies are per-package:

```bash
cargo build -p netgauze-bgp-pkt      # no libyang, no CMake
cargo test  -p netgauze-flow-pkt --features codec
```

A full `cargo build --workspace` will build libyang, which takes a few minutes
on a cold cache.

CI deliberately uses **three different toolchains**, and you will get confusing
results locally if you use the wrong one:

| Task                         | Toolchain                | Why                                                                                                            |
|------------------------------|--------------------------|----------------------------------------------------------------------------------------------------------------|
| `cargo fmt`                  | **nightly**              | `rustfmt.toml` uses `wrap_comments`, `format_code_in_doc_comments` and `imports_granularity`, all nightly-only |
| `cargo clippy`               | **beta**                 | Catches lints before they reach stable                                                                         |
| `cargo build` / `cargo test` | stable, beta and nightly | The test matrix runs all three                                                                                 |
| `cargo doc`                  | nightly                  | Doc-link checking                                                                                              |

Install them with:

```bash
rustup toolchain install nightly beta stable
```

If you run plain `cargo fmt` on stable you will see
`Warning: can't set 'wrap_comments = true'…` and the formatting will not match
what CI expects. Always use `cargo +nightly fmt`.

## Before you open a pull request

Run what CI runs:

```bash
cargo +nightly fmt --check
cargo +beta clippy --locked --tests --all-features -- -D warnings
cargo test --locked --features iana-upstream-build
cargo +nightly doc --locked --no-deps --all-features
```

Notes:

- `--locked` is used throughout CI, so commit `Cargo.lock` changes when your
  change affects dependencies.
- The `iana-upstream-build` feature fetches the IANA registries over HTTP at
  build time. Without it, the bundled registry snapshots under
  `crates/flow-pkt/registry/` are used, which is faster and works offline.
- There is no MSRV policy yet — the test matrix pins nothing older than stable.

## Commit conventions

Commits are prefixed with the crate they touch, followed by an imperative
summary:

```
bgp-pkt: add support for the FQDN capability
flow-pkt: remove nom usage and improve error messages
parse-utils: add additional helper methods to SliceReader
chore: update IANA IPFIX registry
```

Keep the subject under ~72 characters. Use the body to explain **why** the
change is needed, not what the diff already shows — and cite the relevant RFC
and section when implementing a protocol feature.

Prefer a series of small, self-contained commits over one large one. Each commit
should build and pass tests on its own, so that `git bisect` stays useful.

## Code conventions

**License header.** Every new source file starts with the Apache header used
throughout the tree:

```rust
// Copyright (C) 2022-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
```

**Cite the spec.** Protocol code references the RFC and section it implements,
as a doc comment or an inline comment. Reviewers use these to check the wire
format against the text, and the citations are what make a compliance audit
possible.

**Parsing.** PDUs implement the `ParseFrom*` traits from `netgauze-parse-utils`
and read through `SliceReader`. See [`docs/pdu_serde.md`](docs/pdu_serde.md) for
the full model and a worked example.

**Errors.** Parsing errors are `thiserror` enums following a consistent shape:

- every domain variant carries an `offset: usize` pointing at the first byte of
  the offending field — read the offset *before* consuming, so it points at the
  field start rather than past it;
- buffer-level failures are folded in with `Parse(#[from] ParseError)`;
- nested errors read `in <context>: {0}`, so a deep failure prints its full
  path:

  ```text
  in set: in data record: in field: invalid UTF-8 for IE interfaceName
  at byte offset 32: invalid utf-8 sequence of 1 bytes from index 0
  ```

**No panics in library code.** Avoid `unwrap()` and `expect()` outside tests.
Return an error instead — these crates parse untrusted input off the network.

**Model types are immutable.** Fields are private with public getters, and
values are constructed through `new()`. This keeps invariants checkable at
construction.

## Testing

- **Unit tests** use the helpers behind the `test-helpers` feature of
  `netgauze-parse-utils` — `test_parsed_completely_bytes_reader`,
  `test_parse_error_bytes_reader`, `test_write` and their variants. The
  `*_completely_*` helpers also assert that the parser consumed all input.
- **Golden pcap tests** parse captures under `assets/pcaps/` and compare the
  JSON representation line by line. If your change alters the JSON output you
  must regenerate the goldens — and call that out explicitly in the PR, since it
  is a wire-visible or API-visible change.
- **Fuzzing** targets live in `fuzz/`. If you add a parser for a new PDU,
  consider adding a target for it.
- Adding a test that reproduces a bug before fixing it is always welcome.

## Adding support for a new protocol feature

A rough checklist:

1. Add or extend the model type, with private fields and a `new()` constructor.
2. Add the IANA codepoint to `netgauze-iana` (or the crate's `iana.rs`) so the
   name can be reported faithfully, even when the feature is not fully modelled.
3. Implement the deserializer, then the serializer.
4. Add round-trip tests from real bytes, plus at least one malformed-input test
   asserting the exact error and offset.
5. Cite the RFC and section throughout.

## Pull requests

Open PRs against `main`. In the description, say what changed and why, note any
breaking changes to public API or wire behavior, and mention whether golden
files were regenerated.

CI must be green before merge. If a job fails for a reason unrelated to your
change, say so in the PR rather than silently re-running it — flaky jobs are
bugs we want to know about.

## Reporting bugs

For parser bugs, the most useful report includes the bytes. A pcap or a hex dump
that reproduces the failure lets us turn your report directly into a regression
test.

For security-sensitive issues, please do not open a public issue — contact the
maintainers directly.
