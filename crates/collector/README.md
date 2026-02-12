# NetGauze collector daemon

Work in progress for telemetry collection. Currently supports:

1. IPFIX and NetFlow v9
2. UDP Notif
3. YANG Push

With publisher towards Kafka and HTTP endpoints.

## Installation

### From RPM (Recommended for RHEL/Rocky/Alma Linux)

Pre-built RPM packages are available on the [GitHub Releases](https://github.com/NetGauze/NetGauze/releases) page.

1. Download the latest RPM for your architecture (e.g., `netgauze-collector-X.Y.Z-1.el8.x86_64.rpm`).
2. Install using `dnf` or `rpm`:
   ```bash
   sudo dnf install ./netgauze-collector-*.rpm
   ```
   The RPM installs the binary to `/usr/bin/netgauze-collector` and sets the necessary capabilities (`cap_net_raw+ep`).

### From Source

To build from source, you need a Rust toolchain installed. We recommend using [rustup](https://rustup.rs/).

1. Clone the repository:
   ```bash
   git clone https://github.com/NetGauze/NetGauze.git
   cd NetGauze
   ```
2. Run using cargo:
   ```bash
   cargo run -p netgauze-collector --release -- crates/collector/config.yaml
   ```
   *Note: You might need to install development libraries such as `libcurl-devel` (or `libcurl4-openssl-dev` on Debian/Ubuntu) depending on your OS.*

## Running the Collector

Run the collector with a specific config file:
```bash
netgauze-collector /path/to/config.yaml

# Or if running from source:
cargo run -p netgauze-collector -- /path/to/config.yaml
```

## Configuration

See example configuration files in collector crate root.

Key configuration sections:

- `logging`: Log level configuration
- `runtime`: Tokio runtime settings (thread count)
- `telemetry`: OpenTelemetry exporter settings
- `flow`: IPFIX/NetFlow v9 collection and publishing
- `udp_notif`: UDP Notification collection and publishing

### Logging Configuration

The collector uses `tracing` with `EnvFilter` for flexible log level control.

#### Basic Usage

Set the default log level in your `config.yaml`:

```yaml
logging:
  level: "info" # Valid: trace, debug, info, warn, error
```

#### Runtime Override with `RUST_LOG`

Override the log level at runtime using the `RUST_LOG` environment variable:

```bash
# Set global log level
RUST_LOG=debug cargo run -p netgauze-collector -- config.yaml

# Filter specific modules
RUST_LOG=netgauze_collector=trace,tokio=info cargo run -p netgauze-collector -- config.yaml

# Complex filtering (enable trace for flow, debug for UDP notif)
RUST_LOG="warn,netgauze_collector::flow=trace,netgauze_collector::yang_push=debug" \
  cargo run -p netgauze-collector -- config.yaml
```

#### Filter Syntax Examples

The `EnvFilter` supports powerful filtering directives:

- `debug` - Set global level to debug
- `my_crate=trace` - Enable trace logs for specific crate
- `my_crate::module=info` - Enable info logs for specific module
- `[span_name]=debug` - Enable debug logs within specific span
- `[{field_name}]=trace` - Enable trace logs for events/spans with specific field
- `warn,tokio::net=debug` - Global warn, but debug for tokio::net

#### Precedence

1. **`RUST_LOG` environment variable** (highest priority)
2. **Config file `logging.level`**

**Note**: Invalid log levels or EnvFilters file will cause the collector to exit immediately with a clear error message.

### Telemetry Configuration

The collector exports OpenTelemetry metrics via OTLP/gRPC:

```yaml
telemetry:
  id: "collector-01"
  host: "localhost"
  port: 4317
  exporter_timeout: "10s"
  reader_interval: "30s"
```

Metrics include:

- Message processing rates
- Buffer sizes and backpressure
- Error counts
- Publisher health

## Graceful Shutdown

The collector handles `Ctrl+C` (SIGINT) gracefully:

1. Stops accepting new connections
2. Drains in-flight messages from buffers
3. Shuts down publishers (1s timeout each)
4. Exits cleanly

## Memory Allocator

The collector uses **jemalloc** for better memory efficiency on Linux (via `tikv-jemallocator`).

## Build Information

On startup, the collector logs:

- Git commit hash, branch, and tag
- Build timestamp
- Rust version and toolchain
- Operating system

This is powered by the `shadow-rs` crate.
