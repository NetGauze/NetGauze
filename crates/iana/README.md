# NetGauze IANA package

Collection of generic IANA definitions that are not specific to a single protocol.

# Developer documentation

## Adding support for new address and subsequent address families

### Adding support for Address Family (AFI) or Subsequent Address Family (SAFI)

1. New address families are added to the `pub enum AddressFamily` or `pub enum SubsequentAddressFamily` located
   at `src/address_family.rs`.
2. We use `CamelCase` convention for address families.
3. Please document the RFC and IANA codes for the address family.

### Adding support for Address Type

Since not all `AddressFamily` and `SubsequentAddressFamily` are valid combinations, we introduce an
enum `pub enum AddressType` that defines a set of valid combination to ensure only
valid AFI/SAFI are used at compile time.

1. Add the name to `pub enum AddressType` located at `src/address_family.rs`.
2. The name is convention is as follow: `{$AddressFamily}{$SubsequentAddressFamily}`.
3. In `impl AddressType` adjust `pub const fn address_family` and `pub const fn subsequent_address_family` to return the
   correct AddressFamily and $SubsequentAddressFamily for the new type. If not, the compiler will throw an error.
4. In `impl AddressType` adjust `from_afi_safi` to return the newly defined `{$AddressFamily}{$SubsequentAddressFamily}`
   for the given AFI and SAFI.
5. Write tests! See `test_address_type_check_ret_afi_safi` and `test_address_type_try_from`.
