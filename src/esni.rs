use std::convert::{TryInto, TryFrom};
use std::marker::PhantomData;

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
pub struct ESNIKeys<'a> {
    // version: u16,
    // checksum: [u8; 4],
    keys: KeyShareEntry/*<'a>*/, //Vec<KeyShareEntry<'a>>,

    phantom: PhantomData<&'a u8>,
    //todo
}

impl<'a> ESNIKeys<'a> {
    pub fn parse(data: &[u8]) -> Result<ESNIKeys<'a>, &'static str> {
        let mut pos = 0;

        // version
        let version = BigEndian::read_u16(&data[pos..pos + 2]);
        if version != 0xff01 {
            return Err("version invalid");
        }
        pos += 2;

        // checksum
        let mut copy = data.to_owned(); // (?)
        copy[pos..pos + 4].clone_from_slice(&[0u8; 4]); //copy[2:6] = [0] * 4
        let hash = sha2::Sha256::digest(&copy);
        let hash = hash.as_slice();
        if data[pos..pos + 4] != hash[..4] {
            return Err("checksum invalid");
        }
        pos += 4;

        let len = BigEndian::read_u16(&data[pos..pos + 2]) as usize;
        pos += 2;
        dbg!(len);

        // keys
        let mut keys = Vec::new();
        let end = pos + len;
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
        // dbg!(keys);
        dbg!(pos, data.len());


        Err("stub")

        //Ok(//ESNIKeys {
        // version,
        // checksum: data[2..6].try_into().unwrap(),
        // keys: key1,//vec![key1],
        //})
    }
}
