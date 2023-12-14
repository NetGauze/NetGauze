// Copyright (C) 2023-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use netgauze_bgp_pkt::{
    notification::{
        BgpNotificationMessage, MessageHeaderError, OpenMessageError, UpdateMessageError,
    },
    open::BgpOpenMessage,
    update::BgpUpdateMessage,
    BgpMessage,
};

use crate::codec::BgpCodecDecoderError;
use netgauze_bgp_pkt::{
    route_refresh::BgpRouteRefreshMessage,
    wire::deserializer::{
        open::{BgpOpenMessageParsingError, BgpParameterParsingError},
        path_attribute::PathAttributeParsingError,
        update::BgpUpdateMessageParsingError,
        BgpMessageParsingError,
    },
};
use tokio::sync::mpsc;

pub type BgpMsgReceiver = mpsc::Receiver<BgpMessage>;
pub type BgpMsgSender = mpsc::Sender<BgpMessage>;

#[derive(Debug, Eq, PartialEq, strum_macros::Display)]
pub enum BgpEvent<A> {
    /// **Event 1:** Local system administrator manually starts the peer
    /// connection.
    ///
    /// **Status:** Mandatory
    ///
    /// **Optional Attribute Status:**
    ///    * The
    ///      [`PassiveTcpEstablishment`](crate::peer::config::BgpPeerConfig::passive_tcp_establishment)
    ///      attribute *SHOULD* be set to _FALSE_.
    ManualStart,

    /// ***Event 2:*** Local system administrator manually stops the peer
    /// connection.
    ///
    /// **Status:** Mandatory
    ///
    /// **Optional Attribute Status:**
    ///    * No interaction with any optional attributes.
    ManualStop,

    /// **Event 3:** Local system automatically starts the BGP connection.
    ///
    /// **Status:** Optional, depending on local system
    ///
    /// **Optional Attribute Status:**
    ///    * The [`AllowAutomaticStart`](crate::peer::config::BgpPeerConfig::allow_auto_start)
    ///      attribute *SHOULD* be set to _TRUE_ is this event occurs.
    ///    * The [`DampPeerOscillations`](crate::peer::config::BgpPeerConfig::damp_peer_oscillation)
    ///      attribute *SHOULD* be set to _FALSE_ is this event occurs.
    AutomaticStart,

    /// **Event 4:** Local system administrator manually starts the peer
    /// connection, but has
    /// [`PassiveTcpEstablishment`](crate::peer::config::BgpPeerConfig::passive_tcp_establishment)
    /// enabled. The _PassiveTcpEstablishment_ optional attribute indicates
    /// that the peer will listen prior to establishing the connection.
    ///
    /// **Status:** Optional, depending on local system
    ///
    /// **Optional Attribute Status:**
    ///    * The
    ///      [`PassiveTcpEstablishment`](crate::peer::config::BgpPeerConfig::passive_tcp_establishment)
    ///      attribute *SHOULD* be set to _TRUE_ is this event occurs.
    ///    * The
    ///      [`DampPeerOscillations`](crate::peer::config::BgpPeerConfig::damp_peer_oscillation)
    ///      attribute *SHOULD* be set to _FALSE_ is this event occurs.
    ManualStartWithPassiveTcp,

    /// Event 5: AutomaticStart_with_PassiveTcpEstablishment
    AutomaticStartWithPassiveTcp,

    /// Event 6: AutomaticStart_with_DampPeerOscillations
    AutomaticStartWithDampPeerOscillations,

    /// Event 7: AutomaticStart_with_DampPeerOscillations_and_PassiveTcpEstablishment
    AutomaticStartWithDampPeerOscillationsPassiveTcp,

    /// Event 8: AutomaticStop
    AutomaticStop,

    /// Event 9: ConnectRetryTimer_Expires
    ConnectRetryTimerExpires,

    /// ***Event 10***: HoldTimer_Expires an event generated when the HoldTimer
    /// expires.
    ///
    /// **Status:** Mandatory
    HoldTimerExpires,

    /// ***Event 11***: KeepaliveTimer_Expires an event generated when the
    /// KeepaliveTimer expires.
    ///
    /// **Status:** Mandatory
    KeepAliveTimerExpires,

    /// ***Event 12:*** DelayOpenTimer_Expires triggered when
    /// [Connection::open_delay_timer] expires.
    ///
    /// **Status:** Optional
    ///
    /// **Optional Attribute Status:**
    /// If this event occurs,
    ///     * DelayOpen attribute SHOULD be set to _TRUE_.
    ///     * DelayOpenTime attribute SHOULD be supported,
    ///     * DelayOpenTimer SHOULD be supported
    DelayOpenTimerExpires,

    /// **Event 13:** IdleHoldTimer_Expires An event generated when the
    /// IdleHoldTimer expires, indicating that the BGP connection has
    /// completed waiting for the back-off period to prevent BGP peer
    /// oscillation.
    ///
    /// The IdleHoldTimer is only used when the persistent
    /// peer oscillation damping function is enabled by
    /// setting the DampPeerOscillations optional attribute
    /// to _TRUE_.
    ///
    /// Implementations not implementing the persistent
    /// peer oscillation damping function may not have the
    /// IdleHoldTimer
    ///
    /// **Status:** Optional
    ///
    /// **Optional Attribute Status:**
    ///    * DampPeerOscillations attribute SHOULD be set to _TRUE_.
    ///    * IdleHoldTimer SHOULD have just expired.
    IdleHoldTimerExpires,

    /// **Event 14:** Event indicating the local system reception of a TCP
    /// connection request with a valid source IP address, TCP port, destination
    /// IP address, and TCP Port. The definition of invalid source and invalid
    /// destination IP address is determined by the implementation.
    ///
    /// BGP's destination port SHOULD be port 179, as defined by IANA.
    ///
    /// TCP connection request is denoted by the local system receiving a TCP
    /// SYN.
    ///
    /// **Status:** Optional
    ///
    /// **Optional Attribute Status:**
    ///   * The TrackTcpState attribute SHOULD be set to TRUE if this event
    ///     occurs.
    TcpConnectionValid(A),

    /// **Event 15:** _Tcp_CR_Invalid_ Event indicating the local system
    /// reception of a TCP connection request with either an invalid source
    /// address or port number, or an invalid destination address or port
    /// number.
    ///
    /// BGP destination port number SHOULD be 179, as defined by IANA.
    ///
    /// A TCP connection request occurs when the local system receives a TCP
    /// SYN.
    ///
    /// **Status:** Optional
    ///
    /// **Optional Attribute Status:**
    ///   * The TrackTcpState attribute SHOULD be set to TRUE if this event
    ///     occurs.
    TcpConnectionRequestInvalid,

    /// **Event 16:** _Tcp_CR_Acked_ Event indicating the local system's request
    /// to establish a TCP connection to the remote peer.
    ///
    /// The local system's TCP connection sent a TCP SYN, received a TCP SYN/ACK
    /// message, and sent a TCP ACK.
    ///
    /// **Status:** Mandatory
    TcpConnectionRequestAcked(A),

    /// **Event 17:** Event indicating that the local system has received a
    /// confirmation that the TCP connection has been established by the remote
    /// site.
    ///
    /// The remote peer's TCP engine sent a TCP SYN. The local peer's TCP engine
    /// sent a SYN, ACK message and now has received a final ACK.
    ///
    /// **Status:** Mandatory
    TcpConnectionConfirmed(A),

    /// **Event 18:** Event indicating that the local system has received a TCP
    /// connection failure notice.
    ///
    /// The remote BGP peer's TCP machine could have sent a FIN. The local peer
    /// would respond with a FIN-ACK. Another possibility is that the local peer
    /// indicated a timeout in the TCP connection and downed the connection.
    ///
    /// **Status:** Mandatory
    TcpConnectionFails,

    /// Event 19: BGPOpen
    BGPOpen(BgpOpenMessage),

    /// Event 20: BGPOpen with DelayOpenTimer running
    BGPOpenWithDelayOpenTimer(BgpOpenMessage),

    /// Event 21: BGPHeaderErr
    BGPHeaderErr(MessageHeaderError),

    /// Event 22: BGPOpenMsgErr
    BGPOpenMsgErr(OpenMessageError),

    /// Event 23: OpenCollisionDump
    OpenCollisionDump,

    /// Event 24: NotifMsgVerErr
    NotifMsgVerErr,

    /// Event 25: NotifMsg
    NotifMsg(BgpNotificationMessage),

    /// Event 26: KeepAliveMsg
    KeepAliveMsg,

    /// Event 27: UpdateMsg
    UpdateMsg(BgpUpdateMessage),

    /// Event 28: UpdateMsgErr
    UpdateMsgErr(UpdateMessageError),

    RouteRefresh(BgpRouteRefreshMessage),
}

/// Subset of BGP Events defined [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271) that
/// are related to the events occurring after connection is successfully made in
/// [crate::fsm::FsmState::Connect] or [crate::fsm::FsmState::Active] states.
#[derive(Debug, Clone, Eq, PartialEq, strum_macros::Display)]
pub enum ConnectionEvent<A> {
    /// ***Event 10***: HoldTimer_Expires an event generated when the HoldTimer
    /// expires.
    ///
    /// **Status:** Mandatory
    HoldTimerExpires,

    /// ***Event 11***: KeepaliveTimer_Expires an event generated when the
    /// KeepaliveTimer expires.
    ///
    /// **Status:** Mandatory
    KeepAliveTimerExpires,

    /// ***Event 12:*** DelayOpenTimer_Expires triggered when
    /// [Connection::open_delay_timer] expires.
    ///
    /// **Status:** Optional
    ///
    /// **Optional Attribute Status:**
    ///
    /// If this event occurs,
    ///     * DelayOpen attribute SHOULD be set to _TRUE_.
    ///     * DelayOpenTime attribute SHOULD be supported,
    ///     * DelayOpenTimer SHOULD be supported
    DelayOpenTimerExpires,

    /// **Event 16:** _Tcp_CR_Acked_ Event indicating the local system's request
    /// to establish a TCP connection to the remote peer.
    ///
    /// The local system's TCP connection sent a TCP SYN, received a TCP SYN/ACK
    /// message, and sent a TCP ACK.
    ///
    /// **Status:** Mandatory
    TcpConnectionRequestAcked(A),

    /// **Event 17:** Event indicating that the local system has received a
    /// confirmation that the TCP connection has been established by the remote
    /// site.
    ///
    /// The remote peer's TCP engine sent a TCP SYN. The local peer's TCP engine
    /// sent a SYN, ACK message and now has received a final ACK.
    ///
    /// **Status:** Mandatory
    TcpConnectionConfirmed(A),

    /// **Event 18:** Event indicating that the local system has received a TCP
    /// connection failure notice.
    ///
    /// The remote BGP peer's TCP machine could have sent a FIN. The local peer
    /// would respond with a FIN-ACK. Another possibility is that the local peer
    /// indicated a timeout in the TCP connection and downed the connection.
    ///
    /// **Status:** Mandatory
    TcpConnectionFails,

    /// Event 19: BGPOpen
    BGPOpen(BgpOpenMessage),

    /// Event 20: BGPOpen with DelayOpenTimer running
    BGPOpenWithDelayOpenTimer(BgpOpenMessage),

    /// Event 21: BGPHeaderErr
    BGPHeaderErr(MessageHeaderError),

    /// Event 22: BGPOpenMsgErr
    BGPOpenMsgErr(OpenMessageError),

    /// Event 24: NotifMsgVerErr
    NotifMsgVerErr,

    /// Event 25: NotifMsg
    NotifMsg(BgpNotificationMessage),

    /// Event 26: KeepAliveMsg
    KeepAliveMsg,

    /// Event 27: UpdateMsg
    UpdateMsg(BgpUpdateMessage),

    /// Event 28: UpdateMsgErr
    UpdateMsgErr(UpdateMessageError),

    RouteRefresh(BgpRouteRefreshMessage),
}

impl<A> From<BgpCodecDecoderError> for ConnectionEvent<A> {
    fn from(err: BgpCodecDecoderError) -> Self {
        match err {
            BgpCodecDecoderError::IoError(_) => ConnectionEvent::TcpConnectionFails,
            BgpCodecDecoderError::Incomplete(_) => {
                ConnectionEvent::BGPHeaderErr(MessageHeaderError::BadMessageLength {
                    value: vec![],
                })
            }
            BgpCodecDecoderError::BgpMessageParsingError(parse_err) => match parse_err {
                BgpMessageParsingError::NomError(_) => {
                    ConnectionEvent::BGPHeaderErr(MessageHeaderError::Unspecific { value: vec![] })
                }
                BgpMessageParsingError::ConnectionNotSynchronized(header) => {
                    ConnectionEvent::BGPHeaderErr(MessageHeaderError::ConnectionNotSynchronized {
                        value: header.to_be_bytes().to_vec(),
                    })
                }
                BgpMessageParsingError::UndefinedBgpMessageType(t) => {
                    ConnectionEvent::BGPHeaderErr(MessageHeaderError::BadMessageType {
                        value: vec![t.0],
                    })
                }
                BgpMessageParsingError::BadMessageLength(length) => {
                    ConnectionEvent::BGPHeaderErr(MessageHeaderError::BadMessageLength {
                        value: length.to_be_bytes().to_vec(),
                    })
                }
                BgpMessageParsingError::BgpOpenMessageParsingError(err) => match err {
                    BgpOpenMessageParsingError::NomError(_) => {
                        ConnectionEvent::BGPOpenMsgErr(OpenMessageError::Unspecific {
                            value: vec![],
                        })
                    }
                    BgpOpenMessageParsingError::UnsupportedVersionNumber(version) => {
                        ConnectionEvent::BGPOpenMsgErr(OpenMessageError::UnsupportedVersionNumber {
                            value: vec![version],
                        })
                    }
                    BgpOpenMessageParsingError::ParameterError(param_err) => match param_err {
                        BgpParameterParsingError::NomError(_) => {
                            ConnectionEvent::BGPOpenMsgErr(OpenMessageError::Unspecific {
                                value: vec![],
                            })
                        }
                        BgpParameterParsingError::UndefinedParameterType(t) => {
                            ConnectionEvent::BGPOpenMsgErr(
                                OpenMessageError::UnsupportedOptionalParameter { value: vec![t.0] },
                            )
                        }
                        BgpParameterParsingError::CapabilityError(_) => {
                            ConnectionEvent::BGPOpenMsgErr(
                                OpenMessageError::UnsupportedCapability { value: vec![] },
                            )
                        }
                    },
                },
                BgpMessageParsingError::BgpUpdateMessageParsingError(update_err) => {
                    match update_err {
                        BgpUpdateMessageParsingError::NomError(_) => {
                            ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                value: vec![],
                            })
                        }
                        BgpUpdateMessageParsingError::PathAttributeError(path_err) => {
                            match path_err {
                                PathAttributeParsingError::NomError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::OriginError(_) => {
                                    ConnectionEvent::UpdateMsgErr(
                                        UpdateMessageError::InvalidOriginAttribute {
                                            value: vec![],
                                        },
                                    )
                                }
                                PathAttributeParsingError::AsPathError(_) => {
                                    ConnectionEvent::UpdateMsgErr(
                                        UpdateMessageError::MalformedAsPath { value: vec![] },
                                    )
                                }
                                PathAttributeParsingError::NextHopError(_) => {
                                    ConnectionEvent::UpdateMsgErr(
                                        UpdateMessageError::InvalidNextHopAttribute {
                                            value: vec![],
                                        },
                                    )
                                }
                                PathAttributeParsingError::MultiExitDiscriminatorError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::LocalPreferenceError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::AtomicAggregateError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::AggregatorError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::CommunitiesError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::ExtendedCommunitiesError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::ExtendedCommunitiesErrorIpv6(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::LargeCommunitiesError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::OriginatorError(_) => {
                                    ConnectionEvent::UpdateMsgErr(
                                        UpdateMessageError::InvalidOriginAttribute {
                                            value: vec![],
                                        },
                                    )
                                }
                                PathAttributeParsingError::ClusterListError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::MpReachErrorError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::MpUnreachErrorError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::OnlyToCustomerError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::AigpError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::UnknownAttributeError(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                                PathAttributeParsingError::InvalidPathAttribute(_) => {
                                    ConnectionEvent::UpdateMsgErr(UpdateMessageError::Unspecific {
                                        value: vec![],
                                    })
                                }
                            }
                        }
                        BgpUpdateMessageParsingError::Ipv4UnicastError(_) => {
                            ConnectionEvent::UpdateMsgErr(UpdateMessageError::InvalidNetworkField {
                                value: vec![],
                            })
                        }
                        BgpUpdateMessageParsingError::Ipv4UnicastAddressError(_) => {
                            ConnectionEvent::UpdateMsgErr(UpdateMessageError::InvalidNetworkField {
                                value: vec![],
                            })
                        }
                    }
                }
                BgpMessageParsingError::BgpNotificationMessageParsingError(_) => {
                    ConnectionEvent::NotifMsgVerErr
                }
                BgpMessageParsingError::BgpRouteRefreshMessageParsingError(_) => {
                    ConnectionEvent::NotifMsgVerErr
                }
            },
        }
    }
}

impl<A> From<ConnectionEvent<A>> for BgpEvent<A> {
    fn from(value: ConnectionEvent<A>) -> Self {
        match value {
            ConnectionEvent::HoldTimerExpires => BgpEvent::HoldTimerExpires,
            ConnectionEvent::KeepAliveTimerExpires => BgpEvent::KeepAliveTimerExpires,
            ConnectionEvent::DelayOpenTimerExpires => BgpEvent::DelayOpenTimerExpires,
            ConnectionEvent::TcpConnectionRequestAcked(socket) => {
                BgpEvent::TcpConnectionRequestAcked(socket)
            }
            ConnectionEvent::TcpConnectionConfirmed(socket) => {
                BgpEvent::TcpConnectionConfirmed(socket)
            }
            ConnectionEvent::TcpConnectionFails => BgpEvent::TcpConnectionFails,
            ConnectionEvent::BGPOpen(open) => BgpEvent::BGPOpen(open),
            ConnectionEvent::BGPOpenWithDelayOpenTimer(open) => {
                BgpEvent::BGPOpenWithDelayOpenTimer(open)
            }
            ConnectionEvent::BGPHeaderErr(err) => BgpEvent::BGPHeaderErr(err),
            ConnectionEvent::BGPOpenMsgErr(err) => BgpEvent::BGPOpenMsgErr(err),
            ConnectionEvent::NotifMsgVerErr => BgpEvent::NotifMsgVerErr,
            ConnectionEvent::NotifMsg(msg) => BgpEvent::NotifMsg(msg),
            ConnectionEvent::KeepAliveMsg => BgpEvent::KeepAliveMsg,
            ConnectionEvent::UpdateMsg(msg) => BgpEvent::UpdateMsg(msg),
            ConnectionEvent::UpdateMsgErr(msg) => BgpEvent::UpdateMsgErr(msg),
            ConnectionEvent::RouteRefresh(msg) => BgpEvent::RouteRefresh(msg),
        }
    }
}
