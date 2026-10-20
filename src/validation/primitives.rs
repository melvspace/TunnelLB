use std::net::{IpAddr, Ipv4Addr};

pub(super) fn destination_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();

    // Pod and Service networks may legitimately use shared address space, unlike
    // public Machines. Callers must still validate the corresponding API objects.
    a != 0 && a != 127 && a < 224 && !(a == 169 && b == 254)
}

pub(super) fn parse_ipv4_or_mapped(value: &str) -> Option<Ipv4Addr> {
    match value.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    }
}

pub(super) fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
}

pub(super) fn dns_subdomain(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(dns_label)
}
