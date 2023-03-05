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

## Examples

1. IPFIX [ipfix.rs](examples/ipfix.rs)

   ```cargo run --example ipfix```

2. Netflow V9 [netflow.rs](examples/netflow.rs)

   ```cargo run --example netflow```