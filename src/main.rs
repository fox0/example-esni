use std::sync::Arc;

use io::Read;
use io::Write;
use std::io;

// use std::net::*;

use rustls;
use webpki;
use webpki_roots;
// use trust_dns_resolver::Resolver;
// use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};


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
    let arc = make_config();
    let dns_name = webpki::DNSNameRef::try_from_ascii_str("derpibooru.org").unwrap();
    let mut client = rustls::ClientSession::new(&arc, dns_name);

    let mut socket = std::net::TcpStream::connect("derpibooru.org:443").unwrap();
    let mut stream = rustls::Stream::new(&mut client, &mut socket); // Create stream
    // Instead of writing to the client, you write to the stream
    match stream.write(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n") {
        Ok(_) => {}
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    }
    let mut plaintext = Vec::new();
    stream.read_to_end(&mut plaintext).unwrap();
    io::stdout().write_all(&plaintext).unwrap();
}


//
//
// fn main() {
//     let mut config = rustls::ClientConfig::new();
//     config.root_store.add_server_trust_anchors(
//         &webpki_roots::TLS_SERVER_ROOTS);
//

// let resolver = Resolver::new(ResolverConfig::cloudflare_tls(),
//                                  ResolverOpts::default()).unwrap();
//
// let response = resolver.lookup_ip("derpibooru.org").unwrap();
// for i in response.iter() {
//     dbg!(i);
//     break;
// }


// There can be many addresses associated with the name,
//  this can return IPv4 and/or IPv6 addresses
// let address = response.next().expect("no addresses returned!");
// if address.is_ipv4() {
//     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
// } else {
//     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
// }
// }
