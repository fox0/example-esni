use std::str;
use std::net::UdpSocket;

use dns_parser;

/// вернуть txt-запись для
pub fn get_esni(host: &str) -> String {
    //todo Result
    const DNS: &str = "127.0.0.53:53";

    let mut b = dns_parser::Builder::new_query(0x0000, true);
    b.add_question(
        format!("_esni.{}", host).as_str(),
        false,
        dns_parser::QueryType::TXT,
        dns_parser::QueryClass::IN);
    let packet = b.build().unwrap();
    let packet = packet.as_slice();

    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.send_to(packet, DNS).unwrap();

    let mut buf = [0u8; 1024];
    s.recv_from(&mut buf).unwrap();

    let packet = dns_parser::Packet::parse(&buf).unwrap();
    match packet.answers[0].data {
        dns_parser::rdata::RData::TXT(ref text) =>
            text.iter()
                .map(|x| str::from_utf8(x).unwrap())
                .collect::<Vec<_>>()
                .concat(),
        ref x => panic!("Wrong rdata {:?}", x),
    }
}


#[cfg(test)]
mod test {
    use crate::dns::get_esni;

    const BASE64: &str = "/wGwMqOgACQAHQAgDM1kPDS/QlPaOglqcs6Qj13o9KlkrNpPwXKIM7+6iCEAAhMBAQQAAAAA\
    XvhOAAAAAABfADcAAAA=";

    #[test]
    fn get_esni_cloudflare() {
        assert_eq!(get_esni("cloudflare.com"), BASE64);
    }

    #[test]
    fn get_esni_derpibooru() {
        assert_eq!(get_esni("derpibooru.org"), BASE64);
    }

    #[test]
    fn get_esni2() {
        assert_eq!(get_esni("derpibooru.or"), "");//todo
    }
}
