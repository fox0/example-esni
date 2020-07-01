use std::convert::TryInto;

use base64;
use byteorder::{BigEndian, ByteOrder};
use sha2::{self, Digest};


#[derive(Debug)]
/// https://tools.ietf.org/html/draft-ietf-tls-esni-02#page-6
///
/// // Copied from TLS 1.3
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
///
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
    pub fn parse_from_base64(txt: String) -> Result<ESNIKeys, &'static str> {
        let data = base64::decode(txt).unwrap();
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

        let r = BigEndian::read_u16(&data[7..9]);
        dbg!(r);

        // https://github.com/mordyovits/esnitool/blob/master/esni.go

        Ok(ESNIKeys {
            version,
            checksum: data[2..6].try_into().unwrap(),

        })
    }
}
