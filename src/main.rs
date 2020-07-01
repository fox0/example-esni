use std::sync::Arc;

// use rustls;
// use webpki;
// use webpki_roots;
// use trust_dns_resolver::Resolver;
// use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
// use trust_dns_resolver::lookup::Lookup;
// use resolve::config::DnsConfig;
// use resolve::resolver::DnsResolver;
// use resolve::record::Record;

extern crate base64;

mod dns;


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
    let txt = dns::get_txt(format!("_esni.{}", host).as_str()).unwrap();
    let bytes = base64::decode(txt).unwrap();
    println!("{:?}", bytes);

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
