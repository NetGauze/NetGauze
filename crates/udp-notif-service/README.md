# Services to receive udp-notif packets

Building blocks to develop udp-notif collectors.
See [print-udp-notif](examples/udp_notif_print.rs) for a simple
example to receive udp-notif packets from the network.

## Run example

Simple server that will listen to udp-notif packets.
It decodes the packets and prints them out to the console.

```cargo run --example udp_notif_print```
