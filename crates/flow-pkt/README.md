# NetGauze flow reporting pkt (Netflow V9 and IPFIX)

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]


[crates-badge]: https://img.shields.io/crates/v/netgauze-flow-pkt.svg

[crates-url]: https://crates.io/crates/netgauze-flow-pkt

[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg

[apache-url]: https://github.com/NetGauze/NetGauze/blob/main/LICENSE

[docs-badge]: https://docs.rs/netgauze-flow-pkt/badge.svg

[docs-url]: https://docs.rs/netgauze-flow-pkt

## Supported RFCs

1. Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of Flow
   Information [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011)
2. Information Model for IP Flow Information Export [RFC 5102](https://www.rfc-editor.org/rfc/rfc5102)
3. Cisco Systems NetFlow Services Export Version 9 [RFC 3954](https://www.rfc-editor.org/rfc/rfc3954)
4. Information Elements are generated at compile time from the
   [IP Flow Information Export (IPFIX) Entities](https://www.iana.org/assignments/ipfix/ipfix.xhtml) registry. The crate
   that reads the registry and generates the necessary rust code
   is [`netgauze-ipfix-code-generator`](../ipfix-code-generator/README.md).

   By default the build uses the registry snapshot bundled under [`registry/`](registry), taken at the time of the
   crate's release, so generation is reproducible and needs no network access. Enable the `iana-upstream-build` feature
   to fetch the registries from IANA over HTTP at build time instead — note that generation may then fail if IANA
   introduces a change the generator does not yet handle, such as a new data type.

   Users can also define one or more custom local registries, allowing NetGauze to generate the necessary code at build
   time. To use this functionality, the `custom-upstream-build` feature must be enabled and the environment variable
   `NETGAUZE_CUSTOM_XML_PATHS` must be set. `NETGAUZE_CUSTOM_XML_PATHS`
   takes the paths and PENs with the format `NETGAUZE_CUSTOM_XML_PATHS="path=pen"` or to specify more registries
   `NETGAUZE_CUSTOM_XML_PATHS="path=pen,path2=pen2,path3=pen3"`.

## Examples

Each example builds a packet, prints its JSON representation, serializes it to the wire format, and parses it back.

1. IPFIX [ipfix.rs](examples/ipfix.rs)

   ```cargo run --example ipfix```

2. Netflow V9 [netflow.rs](examples/netflow.rs)

   ```cargo run --example netflow```

3. IPFIX with IANA sub-registry values, i.e. Information Elements whose values are themselves an enum
   (`classificationEngineId`, `biflowDirection`, ...) [ipfix-subregs.rs](examples/ipfix-subregs.rs)

   ```cargo run --example ipfix-subregs```

4. The same sub-registry values over Netflow V9 [netflow-subregs.rs](examples/netflow-subregs.rs)

   ```cargo run --example netflow-subregs```

5. IPFIX with vendor (non-IANA) Information Elements from a private enterprise
   number, plus a variable-length field [ipfix-vmware.rs](examples/ipfix-vmware.rs)

   ```cargo run --example ipfix-vmware```
