BGP-4 Protocol representation and serde.

## Supported BGP-4 Protocol features

### Supported message types
| Message Type | RFC                                                                                                                     | notes                                         |
|--------------|-------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| Open         | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | See below for the supported capabilities      |
| Update       | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | See below for the supported path attributes   |
| Notification | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               | See below for the supported notif sub-codes   |
| KeepAlive    | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)                                                               |                                               |
| RouteRefresh | [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918) and [RFC 7313](https://datatracker.ietf.org/doc/html/rfc7313) | See below for the supported Route refresh ops |


### Support Capabilities In BGP Open message

| Capability                       | RFC                                                        | Notes                                                                                       |
|----------------------------------|------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| MultiProtocolExtensions (MP-BGP) | [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760)  | See MP-BGP supported address families below                                                 |
 | RouteRefresh                     | [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918)  |                                                                                             |
| EnhancedRouteRefresh             | [RFC 7313](https://datatracker.ietf.org/doc/html/rfc7313)  |                                                                                             |
 | Add Path                         | [RFC 7911](https://datatracker.ietf.org/doc/html/RFC7911)  |                                                                                             |
 | Extended Message                 | [RFC 8654](https://datatracker.ietf.org/doc/html/RFC8654)  |                                                                                             |
 | Four Octet AS Number             | [RFC 6793](https://datatracker.ietf.org/doc/html/RFC6793)  |                                                                                             |
 | Extended Next Hop Encoding       | [RFC 8950](https://datatracker.ietf.org/doc/html/rfc8950)  |                                                                                             |
 | Experimental                     | [RF C8810](https://datatracker.ietf.org/doc/html/RFC8810)  | Capabilities with codes 239-254 are marked as experimental, we read their values as Vec<u8> |
 | Unrecognized                     | [RFC 5492](https://datatracker.ietf.org/doc/html/rfc5492)  | We carry the capability code and the `u8` vector for it's value                             |
