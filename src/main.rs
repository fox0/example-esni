use std::sync::Arc;
use std::str;
use std::net::UdpSocket;

// use rustls;
// use webpki;
// use webpki_roots;
// use trust_dns_resolver::Resolver;
// use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
// use trust_dns_resolver::lookup::Lookup;

use dns_parser;

// use resolve::config::DnsConfig;
// use resolve::resolver::DnsResolver;
// use resolve::record::Record;

/// вернуть txt-запись для
fn get_esni(host: &str) -> String {//todo Result
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
    use crate::get_esni;

    #[test]
    fn get_esni1() {
        assert_eq!(get_esni("derpibooru.org"), "/wF5SzEIACQAHQAg5aYKojoE8kXfSQ8QFA92ojGJr\
        FlXzqf8qOnDhLXf8g4AAhMBAQQAAAAAXvdtAAAAAABe/1YAAAA=");
    }

    #[test]
    fn get_esni2() {
        assert_eq!(get_esni("derpibooru.or"), "");//todo
    }
}


fn make_config() -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(
        &webpki_roots::TLS_SERVER_ROOTS);
    let mut versions = Vec::new();
    versions.push(rustls::ProtocolVersion::TLSv1_3);
    config.versions = versions;
    config.enable_sni = false;
    Arc::new(config)
}


fn main() {
    let host = "derpibooru.org";
    let r = get_esni(host);
    println!("{}", r);

    //
    // let arc = make_config();
    // let dns_name = webpki::DNSNameRef::try_from_ascii_str("derpibooru.org").unwrap();
    // let mut client = rustls::ClientSession::new(&arc, dns_name);
    //
    // let mut socket = std::net::TcpStream::connect("derpibooru.org:443").unwrap();
    // let mut stream = rustls::Stream::new(&mut client, &mut socket); // Create stream
    // // Instead of writing to the client, you write to the stream
    // match stream.write(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n") {
    //     Ok(_) => {}
    //     Err(e) => {
    //         println!("Error: {}", e);
    //         return;
    //     }
    // }
    // let mut plaintext = Vec::new();
    // stream.read_to_end(&mut plaintext).unwrap();
    // io::stdout().write_all(&plaintext).unwrap();
}


// There can be many addresses associated with the name,
//  this can return IPv4 and/or IPv6 addresses
// let address = response.next().expect("no addresses returned!");
// if address.is_ipv4() {
//     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
// } else {
//     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
// }
// }
