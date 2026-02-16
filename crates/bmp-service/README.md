# BMP Monitoring Protocol Service to receive BMP packets

This crate provides a scalable, actor-based architecture for handling BGP Monitoring Protocol (BMP) sessions.

## Components

### BmpActor
The core unit of computation that handles TCP connections from one or more BMP routers.
- **Concurrency**: Handles multiple TCP connections asynchronously.
- **Subscriptions**: Supports push-based message delivery to subscribers (e.g., Kafka producers, loggers).
- **Sharding**: Can distribute messages across multiple subscriber channels based on the peer's IP address hash.
- **Management**: Provides commands to list connected peers and forcibly disconnect them.

### BmpSupervisor
A management layer that orchestrates multiple `BmpActor` instances.
- **Scaling**: Spawns multiple actors on the same listening port (using `SO_REUSEPORT`) to utilize multi-core systems.
- **Aggregation**: Broadcasts commands (like subscriptions) to all managed actors and aggregates their responses.
- **Lifecycle**: Manages the startup and shutdown of worker actors.

## Examples

### 1. Simple Print (Stateless)
A basic example that listens for connections and prints decoded packets to the console.

```bash
cargo run --example print-bmp
```

### 2. BMP Actor with REST API
Demonstrates how to run a single `BmpActor` integrated with a REST API for basic management.
- Listens on port `1792`.
- Exposes an HTTP API on port `31313`.
- Supports disconnecting peers via `POST /api/disconnect`.

```bash
cargo run --example bmp-actor-example
```

### 3. BMP Supervisor
Demonstrates the `BmpSupervisor` managing multiple actors for high availability and load balancing.
- Spawns 2 workers on port `1790`.
- Aggregates streams from all workers into a single subscriber.
- Periodically logs connected peer statistics.

```bash
cargo run --example bmp-supervisor-example
```