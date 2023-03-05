# BMP Monitoring Protocol Service to receive BMP packets

Building blocks to develop BMP collectors.
See [print-bmp](examples/print-bmp.rs) for a simple code to receive BMP packets from the network.

## Run example

Simple server that will listen to IPFIX/Netflow V9 UDP packets. It handles decoding packets according the template map
per client and print them out to the console.

``` cargo run --example print-bmp```