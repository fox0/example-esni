use std::convert::{TryInto, TryFrom};

use base64;
use byteorder::{BigEndian, ByteOrder};
use sha2::{self, Digest};


// https://github.com/mordyovits/esnitool/blob/master/esni.go
// https://tools.ietf.org/html/rfc8446#section-4.1.4
/// https://tools.ietf.org/html/draft-ietf-tls-esni-02#page-6


/// enum {
///     /* Elliptic Curve Groups (ECDHE) */
///     secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
///     x25519(0x001D), x448(0x001E),
///
///     /* Finite Field Groups (DHE) */
///     ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
///     ffdhe6144(0x0103), ffdhe8192(0x0104),
///
///     /* Reserved Code Points */
///     ffdhe_private_use(0x01FC..0x01FF),
///     ecdhe_private_use(0xFE00..0xFEFF),
///     (0xFFFF)
/// } NamedGroup;
#[derive(Debug)]
pub enum NamedGroup {
    //todo
    X25519 = 0x001D,
    //todo
}

impl TryFrom<u16> for NamedGroup {
    type Error = ();
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == NamedGroup::X25519 as u16 => Ok(NamedGroup::X25519),
            _ => Err(()),
        }
    }
}


/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
pub struct KeyShareEntry {
    group: NamedGroup,
}


#[derive(Debug)]
/// struct {
///     uint16 version;
///     uint8 checksum[4];
///     KeyShareEntry keys<4..2^16-1>;
///     CipherSuite cipher_suites<2..2^16-2>;
///     uint16 padded_length;
///     uint64 not_before;
///     uint64 not_after;
///     Extension extensions<0..2^16-1>;
/// } ESNIKeys;
pub struct ESNIKeys {
    version: u16,
    checksum: [u8; 4],

    //todo
}

impl ESNIKeys {
    pub fn parse_from_base64(data: String /*&[u8]*/) -> Result<ESNIKeys, &'static str> {
        let data = base64::decode(data).unwrap();
        // println!("{:?}", data);
        ESNIKeys::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<ESNIKeys, &'static str> {
        let version = BigEndian::read_u16(&data[..2]);
        if version != 0xff01 {
            return Err("version invalid");
        }

        let mut copy = data.clone();
        copy[2..6].clone_from_slice(&[0u8; 4]); //copy[2:6] = [0] * 4
        let hash = sha2::Sha256::digest(&copy);
        let hash = hash.as_slice();
        if data[2..6] != hash[..4] {
            return Err("checksum invalid");
        }

        let length = BigEndian::read_u16(&data[6..8]) as usize;
        dbg!(length);

        let subdata = &data[8..8 + length];
        // dbg!(subdata);
        // todo for
        let group: NamedGroup = match BigEndian::read_u16(&subdata[..2]).try_into() {
            Ok(x) => x,
            Err(e) => return Err("group invalid"),
        };
        dbg!(group);

        let v = BigEndian::read_u16(&subdata[2..4]);
        // dbg!(v);

        let v = BigEndian::read_u16(&subdata[4..6]);
        dbg!(v);

        Ok(ESNIKeys {
            version,
            checksum: data[2..6].try_into().unwrap(),

        })
    }
}
