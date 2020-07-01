extern crate base64;

use sha2::{Sha256, Digest};


#[derive(Debug)]
pub struct ESNIKeys {
    header: [u8; 2],
    checksum: [u8; 4],

    //todo
}

impl ESNIKeys {
    pub fn parse_from_base64(txt: String) -> ESNIKeys {
        let bytes = base64::decode(txt).unwrap();
        //dbg!(bytes);

        // https://github.com/mordyovits/esnitool/blob/master/esni.go
        // copy(data[2:7], []byte{0, 0, 0, 0})
        // sum := sha256.Sum256(data)
        // if bytes.Equal(sum[0:4], k.checksum[:]) {
        // k.checksum_valid = true
        // }

        let mut copy_bytes = bytes.clone();
        for i in 2..6 {
            copy_bytes[i] = 0;
        }
        let output = sha2::Sha256::digest(&copy_bytes);
        let output = output.as_slice();
        dbg!(output, bytes);//ok

        ESNIKeys {
            header: [0u8, 0u8],
            checksum: [0u8, 0u8, 0u8, 0u8],
        }
    }
}
