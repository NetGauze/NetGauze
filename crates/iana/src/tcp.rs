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
//! let value: u8 = 0b01000111;
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
use std::{
    fmt::{Display, Formatter},
    ops::{BitOr, BitOrAssign},
};

/// TCP Header Flags registered at IANA
/// [TCP Parameters](https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xml)
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default, Hash, Serialize, Deserialize)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

    pub fn to_vec(&self) -> Vec<String> {
        let mut flags = Vec::new();
        if self.FIN {
            flags.push("FIN".to_string());
        }
        if self.SYN {
            flags.push("SYN".to_string());
        }
        if self.RST {
            flags.push("RST".to_string());
        }
        if self.PSH {
            flags.push("PSH".to_string());
        }
        if self.ACK {
            flags.push("ACK".to_string());
        }
        if self.URG {
            flags.push("URG".to_string());
        }
        if self.ECE {
            flags.push("ECE".to_string());
        }
        if self.CWR {
            flags.push("CWR".to_string());
        }
        flags
    }
}

impl BitOr for TCPHeaderFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        TCPHeaderFlags {
            FIN: self.FIN | rhs.FIN,
            SYN: self.SYN | rhs.SYN,
            RST: self.RST | rhs.RST,
            PSH: self.PSH | rhs.PSH,
            ACK: self.ACK | rhs.ACK,
            URG: self.URG | rhs.URG,
            ECE: self.ECE | rhs.ECE,
            CWR: self.CWR | rhs.CWR,
        }
    }
}

impl BitOrAssign for TCPHeaderFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.FIN |= rhs.FIN;
        self.SYN |= rhs.SYN;
        self.RST |= rhs.RST;
        self.PSH |= rhs.PSH;
        self.ACK |= rhs.ACK;
        self.URG |= rhs.URG;
        self.ECE |= rhs.ECE;
        self.CWR |= rhs.CWR;
    }
}

impl Display for TCPHeaderFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut flags = Vec::new();
        if self.FIN {
            flags.push("FIN");
        }
        if self.SYN {
            flags.push("SYN");
        }
        if self.RST {
            flags.push("RST");
        }
        if self.PSH {
            flags.push("PSH");
        }
        if self.ACK {
            flags.push("ACK");
        }
        if self.URG {
            flags.push("URG");
        }
        if self.ECE {
            flags.push("ECE");
        }
        if self.CWR {
            flags.push("CWR");
        }
        write!(f, "{:?}", flags)
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
        let value: u8 = 0b00000001;
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
        let value: u16 = 0b00011000;
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
        let value: u8 = 0b00010010;
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

    #[test]
    fn test_bitor() {
        let flags1 = TCPHeaderFlags {
            FIN: true,
            SYN: false,
            RST: false,
            PSH: false,
            ACK: false,
            URG: true,
            ECE: false,
            CWR: false,
        };
        let mut flags2 = TCPHeaderFlags {
            FIN: false,
            SYN: true,
            RST: false,
            PSH: false,
            ACK: false,
            URG: false,
            ECE: false,
            CWR: false,
        };
        let flags3 = flags1 | flags2;
        assert_eq!(
            flags3,
            TCPHeaderFlags {
                FIN: true,
                SYN: true,
                RST: false,
                PSH: false,
                ACK: false,
                URG: true,
                ECE: false,
                CWR: false,
            }
        );
        flags2 |= flags1;
        assert_eq!(flags2, flags3)
    }

    #[test]
    fn test_display() {
        let flags = TCPHeaderFlags {
            FIN: true,
            SYN: true,
            RST: true,
            PSH: false,
            ACK: false,
            URG: false,
            ECE: true,
            CWR: false,
        };
        assert_eq!(format!("{}", flags), "[\"FIN\", \"SYN\", \"RST\", \"ECE\"]");
    }

    #[test]
    fn test_to_vec() {
        let flags = TCPHeaderFlags {
            FIN: true,
            SYN: true,
            RST: true,
            PSH: false,
            ACK: false,
            URG: false,
            ECE: true,
            CWR: false,
        };
        let expected = vec![
            "FIN".to_string(),
            "SYN".to_string(),
            "RST".to_string(),
            "ECE".to_string(),
        ];
        assert_eq!(flags.to_vec(), expected);
    }
}
