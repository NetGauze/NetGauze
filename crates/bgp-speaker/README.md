# BGP Speaker Library

Handle BGP connection and FSM machine and generate a stream of (FSM state, BGP Event).

### Example: Listener that logs incoming messages

```cargo run --example log_listener -- 600 192.168.56.1```