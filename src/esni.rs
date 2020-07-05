use std::convert::{TryInto, TryFrom};

use byteorder::{BigEndian, ByteOrder};
use sha2::{self, Digest};


// https://tools.ietf.org/html/rfc8446#section-4.1.4
// https://tools.ietf.org/html/draft-ietf-tls-esni-02#page-6


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
#[derive(Debug, PartialEq)]
pub enum NamedGroup {
    //todo
    X25519 = 0x001D,
    //todo
}


///               +------------------------------+-------------+
///               | Description                  | Value       |
///               +------------------------------+-------------+
///               | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
///               |                              |             |
///               | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
///               |                              |             |
///               | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
///               |                              |             |
///               | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
///               |                              |             |
///               | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
///               +------------------------------+-------------+
#[derive(Debug, PartialEq)]
pub enum CipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    //todo
}


/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
#[derive(Debug)]
pub struct KeyShareEntry {
    group: NamedGroup,
    key_exchange: [u8; 32],  //todo
}


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
#[derive(Debug)]
pub struct ESNIKeys {
    version: u16,
    checksum: [u8; 4],
    keys: Vec<KeyShareEntry>,
    cipher_suites: Vec<CipherSuite>,
    padded_length: u16,
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

impl TryFrom<u16> for CipherSuite {
    type Error = ();
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == CipherSuite::TlsAes128GcmSha256 as u16 =>
                Ok(CipherSuite::TlsAes128GcmSha256),
            _ => Err(()),
        }
    }
}

impl ESNIKeys {
    pub fn parse(data: &[u8]) -> Result<ESNIKeys, &'static str> {
        let mut pos = 0;

        // version
        let version = BigEndian::read_u16(&data[pos..pos + 2]);
        if version != 0xff01 {
            return Err("version invalid");
        }
        pos += 2;

        // checksum
        let checksum = data[pos..pos + 4].try_into().unwrap();
        let mut copy = data.to_owned(); // (?)
        copy[pos..pos + 4].clone_from_slice(&[0u8; 4]); //copy[2:6] = [0] * 4
        let hash = sha2::Sha256::digest(&copy);
        let hash = hash.as_slice();
        if checksum != hash[..4] {
            return Err("checksum invalid");
        }
        pos += 4;

        // keys
        let mut keys: Vec<KeyShareEntry> = Vec::new();
        let len = BigEndian::read_u16(&data[pos..pos + 2]) as usize;
        pos += 2;
        let end = pos + len;
        // dbg!(len,end);
        while pos < end {
            let group: NamedGroup = match BigEndian::read_u16(&data[pos..pos + 2]).try_into() {
                Ok(x) => x,
                Err(_e) => return Err("group invalid"),
            };
            pos += 2;

            let len = BigEndian::read_u16(&data[pos..pos + 2]) as usize;
            pos += 2;
            assert_eq!(len, 32); // todo

            let key_exchange = &data[pos..pos + len];
            pos += len;

            let key_exchange = key_exchange.try_into().unwrap();
            keys.push(KeyShareEntry { group, key_exchange });
        }

        // cipher_suites
        let mut cipher_suites: Vec<CipherSuite> = Vec::new();
        let len = BigEndian::read_u16(&data[pos..pos + 2]) as usize;
        pos += 2;
        let end = pos + len;
        while pos < end {
            cipher_suites.push(match BigEndian::read_u16(&data[pos..pos + 2]).try_into() {
                Ok(x) => x,
                Err(_e) => return Err("cipher_suite invalid"),
            });
            pos += 2;
        }

        // padded_length
        let padded_length = BigEndian::read_u16(&data[pos..pos + 2]);
        pos += 2;

        //todo

        Ok(ESNIKeys { version, checksum, keys, cipher_suites, padded_length })
    }
}


#[cfg(test)]
mod test {
    use crate::esni::{ESNIKeys, NamedGroup, CipherSuite};

    #[test]
    fn parse() {
        static DATA: &'static [u8] = &[
            255, 1, 162, 90, 17, 124, 0, 36, 0, 29, 0, 32, 20, 10, 20, 161, 155, 152, 45, 184, 222,
            180, 113, 14, 192, 173, 73, 157, 20, 233, 218, 93, 165, 233, 201, 244, 153, 153, 225,
            36, 121, 33, 15, 115, 0, 2, 19, 1, 1, 4, 0, 0, 0, 0, 94, 253, 176, 32, 0, 0, 0, 0, 95,
            5, 153, 32, 0, 0];
        let result = ESNIKeys::parse(DATA).unwrap();
        assert_eq!(result.version, 0xff01);
        assert_eq!(result.checksum, [162, 90, 17, 124]);
        assert_eq!(result.keys.len(), 1);
        assert_eq!(result.keys[0].group, NamedGroup::X25519);
        assert_eq!(result.keys[0].key_exchange, [
            20, 10, 20, 161, 155, 152, 45, 184, 222, 180, 113, 14, 192, 173, 73, 157, 20, 233, 218,
            93, 165, 233, 201, 244, 153, 153, 225, 36, 121, 33, 15, 115]);
        assert_eq!(result.cipher_suites.len(), 1);
        assert_eq!(result.cipher_suites[0], CipherSuite::TlsAes128GcmSha256);
        assert_eq!(result.padded_length, 260);

    }
}
