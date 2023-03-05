# Services to receive IPFIX/Netflow packets

Building blocks to develop IPFIX/Netflow collectors.
See [print-flow](examples/print-flow.rs) for a simple code to receive IPFIX and Netflow packets from the network.

## Run example

Simple server that will listen to IPFIX/Netflow V9 UDP packets. It handles decoding packets according the template map
per client and print them out to the console.

``` cargo run --example print-flow```