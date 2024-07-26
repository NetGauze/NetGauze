// Copyright (C) 2022-present The NetGauze Authors.
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

//!
//! Handling TCP Parameters registered at [TCP Parameters](https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xml)
//!
//! ```rust
//! use netgauze_iana::tcp::*;
//! use serde_json;
//!
//! let value: u8 = 71;
//! let flags = TCPHeaderFlags::from(value);
//! println!("{:?}", flags);
//! // output: TCPHeaderFlags { FIN: true, SYN: true, RST: true, PSH: false, ACK: false, URG: false, ECE: true, CWR: false }
//! let flags_json = serde_json::to_string(&flags).unwrap();
//! println!("{}", flags_json);
//! // output: {"FIN":true,"SYN":true,"RST":true,"PSH":false,"ACK":false,"URG":false,"ECE":true,"CWR":false}
//! let value2: u8 = u8::from(flags);
//!   
//! assert_eq!(value, value2);
//! ```

use serde::{Deserialize, Serialize};

/// TCP Header Flags registered at IANA
/// [TCP Parameters](https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xml)
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct TCPHeaderFlags {
    /// No more data from sender (FIN)
    /// [RFC9293](https://datatracker.ietf.org/doc/html/RFC9293)
    FIN: bool,
    /// Synchronize sequence numbers (SYN)
    /// [RFC9293](https://datatracker.ietf.org/doc/html/RFC9293)
    SYN: bool,
    /// Reset the connection (RST)
    /// [RFC9293](https://datatracker.ietf.org/doc/html/RFC9293)
    RST: bool,
    /// Push Function (PSH)
    /// [RFC9293](https://datatracker.ietf.org/doc/html/RFC9293)
    PSH: bool,
    /// Acknowledgment field is significant (ACK)
    /// [RFC9293](https://datatracker.ietf.org/doc/html/RFC9293)
    ACK: bool,
    /// Urgent Pointer field is significant (URG)
    /// [RFC9293](https://datatracker.ietf.org/doc/html/RFC9293)
    URG: bool,
    /// ECN (ECN-Echo)
    /// [RFC3168](https://datatracker.ietf.org/doc/html/RFC3168)
    ECE: bool,
    /// CWR (Congestion Window Reduced)
    /// [RFC3168](https://datatracker.ietf.org/doc/html/RFC3168)
    CWR: bool,
}

#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
impl TCPHeaderFlags {
    pub fn new(
        FIN: bool,
        SYN: bool,
        RST: bool,
        PSH: bool,
        ACK: bool,
        URG: bool,
        ECE: bool,
        CWR: bool,
    ) -> Self {
        TCPHeaderFlags {
            FIN,
            SYN,
            RST,
            PSH,
            ACK,
            URG,
            ECE,
            CWR,
        }
    }
}

impl From<u16> for TCPHeaderFlags {
    fn from(value: u16) -> Self {
        TCPHeaderFlags::from(value as u8)
    }
}

impl From<TCPHeaderFlags> for u16 {
    fn from(flags: TCPHeaderFlags) -> Self {
        u8::from(flags) as u16
    }
}

impl From<u8> for TCPHeaderFlags {
    fn from(value: u8) -> Self {
        TCPHeaderFlags {
            FIN: (value & 0x0001) != 0,
            SYN: (value & 0x0002) != 0,
            RST: (value & 0x0004) != 0,
            PSH: (value & 0x0008) != 0,
            ACK: (value & 0x0010) != 0,
            URG: (value & 0x0020) != 0,
            ECE: (value & 0x0040) != 0,
            CWR: (value & 0x0080) != 0,
        }
    }
}

impl From<TCPHeaderFlags> for u8 {
    fn from(flags: TCPHeaderFlags) -> Self {
        let mut value: u8 = 0;
        if flags.FIN {
            value |= 0x01;
        }
        if flags.SYN {
            value |= 0x02;
        }
        if flags.RST {
            value |= 0x04;
        }
        if flags.PSH {
            value |= 0x08;
        }
        if flags.ACK {
            value |= 0x10;
        }
        if flags.URG {
            value |= 0x20;
        }
        if flags.ECE {
            value |= 0x40;
        }
        if flags.CWR {
            value |= 0x80;
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::TCPHeaderFlags;

    #[test]
    fn test_fin_u8() {
        let value: u8 = 1;
        let flags = TCPHeaderFlags::from(value);
        assert_eq!(
            flags,
            TCPHeaderFlags {
                FIN: true,
                SYN: false,
                RST: false,
                PSH: false,
                ACK: false,
                URG: false,
                ECE: false,
                CWR: false,
            }
        );

        let value2: u8 = flags.into();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_psh_ack_u16() {
        let value: u16 = 24;
        let flags = TCPHeaderFlags::from(value);
        assert_eq!(
            flags,
            TCPHeaderFlags {
                FIN: false,
                SYN: false,
                RST: false,
                PSH: true,
                ACK: true,
                URG: false,
                ECE: false,
                CWR: false,
            }
        );

        let value2: u16 = flags.into();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_syn_ack_u8() {
        let value: u8 = 18;
        let flags = TCPHeaderFlags::from(value);
        assert_eq!(
            flags,
            TCPHeaderFlags {
                FIN: false,
                SYN: true,
                RST: false,
                PSH: false,
                ACK: true,
                URG: false,
                ECE: false,
                CWR: false,
            }
        );

        let value2: u8 = flags.into();
        assert_eq!(value, value2);
    }
}
