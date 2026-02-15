# Rocket SQLite Task Tracker

[![Autobuild](https://github.com/lowks/test_jules_with_rust/actions/workflows/autobuild.yml/badge.svg)](https://github.com/lowks/test_jules_with_rust/actions/workflows/autobuild.yml)

A modern web application built with the **Rocket** Rust framework and **SQLite** (via `rusqlite`). This application allows you to manage tasks with a name, status, and date.

## Features

- **Modern UI**: Styled with Tailwind CSS and Flowbite components.
- **SQLite Integration**: Robust data persistence using `rocket_sync_db_pools` and `rusqlite`.
- **Dual Interface**: Supports both HTML form submissions and a JSON API.
- **Auto-Migrations**: Automatically creates the database schema on startup.
- **Tested**: Comprehensive integration tests for all major features.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- SQLite (bundled by default, no separate installation required)

## Running Locally

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd rocket-sqlite-app
   ```

2. **Run the application**:
   ```bash
   cargo run
   ```
   The server will start at `http://127.0.0.1:8000`.

3. **Open in Browser**:
   Navigate to `http://127.0.0.1:8000` to use the Task Tracker.

## Development

### Running Tests
To run the integration tests:
```bash
cargo test
```

### Linting and Formatting
To ensure code quality and style:
```bash
cargo clippy -- -D warnings
cargo fmt
```

## GitHub Integration

### GitHub Actions (CI)
To automate building and testing on every push, you can add a `.github/workflows/rust.yml` file:

```yaml
name: Rust

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

env:
  CARGO_TERM_COLOR: always

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build
      run: cargo build --verbose
    - name: Run tests
      run: cargo test --verbose
```

### GitHub Container Registry (Publishing)
Since this is a backend application, you can publish it as a Docker container using GitHub Packages (GHCR). A basic `Dockerfile` might look like:

```dockerfile
FROM rust:1.75 as builder
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libsqlite3-0 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/rocket-sqlite-app /usr/local/bin/app
COPY --from=builder /usr/src/app/templates /templates
COPY --from=builder /usr/src/app/Rocket.toml /Rocket.toml
CMD ["app"]
```

## License

MIT
