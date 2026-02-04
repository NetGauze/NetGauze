# NetGauze flow reporting pkt (Netflow V9 and IPFIX)

## Supported RFCs

1. Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of Flow
   Information [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011)
2. Information Model for IP Flow Information Export [RFC 5102](https://www.rfc-editor.org/rfc/rfc5102)
3. Cisco Systems NetFlow Services Export Version 9 [RFC 3954](https://www.rfc-editor.org/rfc/rfc3954)
4. Information Elements are pulled automatically at compile time from IANA
   registry [IP Flow Information Export (IPFIX) Entities](https://www.iana.org/assignments/ipfix/ipfix.xhtml). The crate
   to download and generate the necessary rust code
   is [`netgauze-ipfix-code-generator`](../ipfix-code-generator/README.md)
   When the IANA registry introduces changes, such as a new data type, generation may fail.
   If your project depends on this crate and requires stable generation, you can enable the
   backwards-compatibility-snapshot feature in your Cargo.toml file. This feature uses a snapshot of registry
   files taken at the time of the crate's release, ensuring reliable generation even if the registry is updated. In addition to this, users can define a single custom local registry or multiple custom local registries, allowing NetGauze to generate the necessary code at build time. To use this functionality, the `custom-upstream-build` feature must be enabled and the environment variable `NETGAUZE_CUSTOM_XML_PATHS` must be set. `NETGAUZE_CUSTOM_XML_PATHS` takes the paths and PENs with the format `NETGAUZE_CUSTOM_XML_PATHS="path=pen"` or to specify more registries `NETGAUZE_CUSTOM_XML_PATHS="path=pen,path2=pen2,path3=pen3"`.

## Examples

1. IPFIX [ipfix.rs](examples/ipfix.rs)

   ```cargo run --example ipfix```

2. Netflow V9 [netflow.rs](examples/netflow.rs)

   ```cargo run --example netflow```
