// use std::net::*;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};


fn main() {
    let resolver = Resolver::new(ResolverConfig::cloudflare_tls(),
                                     ResolverOpts::default()).unwrap();

    let response = resolver.lookup_ip("derpibooru.org").unwrap();
    let ip;
    for i in response.iter() {
        ip = i;
        break;
    }
    dbg!(ip);

    // There can be many addresses associated with the name,
    //  this can return IPv4 and/or IPv6 addresses
    // let address = response.next().expect("no addresses returned!");
    // if address.is_ipv4() {
    //     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    // } else {
    //     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
    // }
}
