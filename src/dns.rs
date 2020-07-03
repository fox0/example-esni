// #![feature(const_generics)]
use std::str;
use std::net::UdpSocket;
// use std::mem::{self, MaybeUninit};

use dns_parser::{Builder, QueryType, QueryClass, Packet};
use dns_parser::rdata::RData;


// #[derive(Debug)]
// //use dns_parser::rdata::txt::Record;
// pub struct MyRecord<'a> {
//     pub bytes: &'a [u8],
// }


//todo class с сокетом

/// вернуть txt-запись для
pub fn get_txt(host: &str) -> Result<String /*&[u8]*/, &'static str> {
    const DNS: &str = "127.0.0.53:53";
    let mut b = Builder::new_query(0x0000, true);
    b.add_question(
        host,
        false,
        QueryType::TXT,
        QueryClass::IN);
    let packet = b.build().unwrap();
    let packet = packet.as_slice();

    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.send_to(packet, DNS).unwrap();

    let mut packet = [0u8; 1024];
    // let aaa = get_uninit_array::<u8, 1024>();
    s.recv_from(&mut packet).unwrap();

    let packet = Packet::parse(&packet).unwrap();
    if packet.answers.len() == 0 {
        return Err("no answers");
    }
    match packet.answers[0].data {
        RData::TXT(ref record) => {
            //todo
            // let result: &MyRecord = unsafe { std::mem::transmute(record) };
            // Ok(result.bytes)
            Ok(record.iter()
                .map(|x| str::from_utf8(x).unwrap())
                .collect::<Vec<_>>()
                .concat())
        }
        ref _x => Err("Wrong rdata"),
    }
}

// http://adventures.michaelfbryan.com/posts/const-arrayvec/
// fn get_uninit_array<U, const size: usize>() -> [U; size]{
//     const SIZE: usize = 100500;
//     type U = u8;
//     unsafe {
//         mem::transmute::<[MaybeUninit<U>; size], [U; size]>(
//             MaybeUninit::uninit().assume_init())
//     }
// }


#[cfg(test)]
mod test {
    use crate::dns::get_txt;

    const BASE64: &str = "/wHaaNeDACQAHQAgiz5G/knn0s9DJ4ZFg/l4QrUhtqSraam+gjcOA4/EpwEAAhMBAQQAAAAAX\
    vhcEAAAAABfAEUQAAA=";

    #[test]
    fn get_esni_cloudflare() {
        assert_eq!(get_txt("_esni.cloudflare.com").unwrap(), BASE64);
    }

    #[test]
    fn get_esni_derpibooru() {
        assert_eq!(get_txt("_esni.derpibooru.org").unwrap(), BASE64);
    }

    #[test]
    fn get_esni2() {
        assert_eq!(get_txt("derpibooru.org").unwrap(), "v=spf1 +mx -all");
    }

    #[test]
    fn get_esni_error() {
        assert_eq!(get_txt("derpibooru.or").unwrap_err(), "no answers");
    }
}
