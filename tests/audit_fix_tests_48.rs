//! Audit fix tests — round 48.
//!
//! Finding 2: IPv6 routability — `is_routable` must reject all non-globally-routable
//!            IPv6 address ranges.

use exfer::network::protocol::is_routable;

// ── Finding 2: Behavioral — IPv6 routability runtime ──

#[test]
fn ipv6_loopback_not_routable() {
    assert!(!is_routable(&"[::1]:9333".parse().unwrap()));
}

#[test]
fn ipv6_ula_not_routable() {
    assert!(!is_routable(&"[fc00::1]:9333".parse().unwrap()));
    assert!(!is_routable(&"[fd12::1]:9333".parse().unwrap()));
}

#[test]
fn ipv6_multicast_not_routable() {
    assert!(!is_routable(&"[ff02::1]:9333".parse().unwrap()));
}

#[test]
fn ipv6_discard_not_routable() {
    assert!(!is_routable(&"[100::]:9333".parse().unwrap()));
}

#[test]
fn ipv6_documentation_not_routable() {
    assert!(!is_routable(&"[2001:db8::1]:9333".parse().unwrap()));
}

#[test]
fn ipv6_teredo_not_routable() {
    assert!(!is_routable(&"[2001::1]:9333".parse().unwrap()));
}

#[test]
fn ipv6_nat64_not_routable() {
    assert!(!is_routable(&"[64:ff9b::1]:9333".parse().unwrap()));
}

#[test]
fn ipv6_global_is_routable() {
    assert!(is_routable(
        &"[2607:f8b0:4004:800::200e]:9333".parse().unwrap()
    ));
    assert!(is_routable(
        &"[2a00:1450:4001:802::200e]:9333".parse().unwrap()
    ));
}
