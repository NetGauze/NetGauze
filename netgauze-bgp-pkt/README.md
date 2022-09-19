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

| Capability                             | RFC                                                       | Notes                                                            |
|----------------------------------------|-----------------------------------------------------------|------------------------------------------------------------------|
| (WIP) MultiProtocolExtensions (MP-BGP) | [RFC 2858](https://datatracker.ietf.org/doc/html/rfc2858) | See MP-BGP supported address families below                      |
 | RouteRefresh                           | [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918) |                                                                  |
| EnhancedRouteRefres                    | [RFC 7313](https://datatracker.ietf.org/doc/html/rfc7313) |                                                                  |
 | Unrecognized                           | [RFC 5492](https://datatracker.ietf.org/doc/html/rfc5492) | We carry the capability code and the `u8` vectore for it's value |
