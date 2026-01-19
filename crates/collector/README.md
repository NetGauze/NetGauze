# NetGauze collector daemon

Work in progress for telemetry collection. Currently supports:

1. IPFIX and NetFlow v9
2. UDP Notif
3. YANG Push

With publisher towards Kafka and HTTP endpoints.

## Running the Collector

```bash
# Run with a config file
cargo run -p netgauze-collector -- /path/to/config.yaml
```

## Logging Configuration

The collector uses `tracing` with `EnvFilter` for flexible log level control.

### Basic Usage

Set the default log level in your `config.yaml`:

```yaml
logging:
  level: "info" # Valid: trace, debug, info, warn, error
```

### Runtime Override with `RUST_LOG`

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

### Filter Syntax Examples

The `EnvFilter` supports powerful filtering directives:

- `debug` - Set global level to debug
- `my_crate=trace` - Enable trace logs for specific crate
- `my_crate::module=info` - Enable info logs for specific module
- `[span_name]=debug` - Enable debug logs within specific span
- `[{field_name}]=trace` - Enable trace logs for events/spans with specific field
- `warn,tokio::net=debug` - Global warn, but debug for tokio::net

### Precedence

1. **`RUST_LOG` environment variable** (highest priority)
2. **Config file `logging.level`**

**Note**: Invalid log levels or EnvFilters file will cause the collector to exit immediately with a clear error message.

## Telemetry

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

## Configuration

See example configuration files in collector crate root.

Key configuration sections:

- `logging`: Log level configuration
- `runtime`: Tokio runtime settings (thread count)
- `telemetry`: OpenTelemetry exporter settings
- `flow`: IPFIX/NetFlow v9 collection and publishing
- `udp_notif`: UDP Notification collection and publishing

## Memory Allocator

The collector uses **jemalloc** for better memory efficiency on Linux (via `tikv-jemallocator`).

## Build Information

On startup, the collector logs:

- Git commit hash, branch, and tag
- Build timestamp
- Rust version and toolchain
- Operating system

This is powered by the `shadow-rs` crate.
