use crate::{ConnectRequest, LeaseNetworkBinding, NetworkAuthorizer, NetworkError, NetworkLimits};
use runtrue_workflow_ir::{DnsPolicy, NetworkDestination, NetworkPermission, NetworkProtocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn policy(deny_private_ranges: bool) -> NetworkPermission {
    NetworkPermission::Allow {
        dns: DnsPolicy::Restricted,
        deny_private_ranges,
        destinations: vec![
            NetworkDestination {
                host: "*.packages.example".to_owned(),
                port: 443,
                protocol: NetworkProtocol::Tcp,
            },
            NetworkDestination {
                host: "api.example".to_owned(),
                port: 443,
                protocol: NetworkProtocol::Tcp,
            },
        ],
        listen: vec![8080],
    }
}

fn binding() -> LeaseNetworkBinding {
    LeaseNetworkBinding {
        run_id: "run-1".to_owned(),
        job_id: "build".to_owned(),
        job_attempt: 1,
        step_id: "download".to_owned(),
        execution_lease_id: "lease-1".to_owned(),
        fencing_generation: 3,
    }
}

fn request(host: &str, addresses: Vec<IpAddr>) -> ConnectRequest {
    ConnectRequest {
        host: host.to_owned(),
        port: 443,
        protocol: NetworkProtocol::Tcp,
        resolved_addresses: addresses,
        dns_ttl_seconds: 60,
    }
}

#[test]
fn exact_destination_and_dns_pins_are_fence_and_time_bound() {
    let authorizer =
        NetworkAuthorizer::new(policy(true), NetworkLimits::default()).expect("policy");
    let address = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let ticket = authorizer
        .authorize_connect(&binding(), request("api.example", vec![address]), 100)
        .expect("ticket");
    assert_eq!(ticket.host(), "api.example");
    assert_eq!(ticket.pinned_addresses(), &[address]);
    authorizer
        .authorize_ticket_use(&ticket, &binding(), address, 159)
        .expect("use");
    assert!(matches!(
        authorizer.authorize_ticket_use(
            &ticket,
            &binding(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            159
        ),
        Err(NetworkError::AddressNotPinned(_))
    ));
    assert!(matches!(
        authorizer.authorize_ticket_use(&ticket, &binding(), address, 160),
        Err(NetworkError::TicketExpired)
    ));
    let mut stale = binding();
    stale.fencing_generation = 4;
    assert!(matches!(
        authorizer.authorize_ticket_use(&ticket, &stale, address, 120),
        Err(NetworkError::StaleFence)
    ));
    let mut stale_attempt = binding();
    stale_attempt.job_attempt = 2;
    assert!(matches!(
        authorizer.authorize_ticket_use(&ticket, &stale_attempt, address, 120),
        Err(NetworkError::StaleFence)
    ));
}

#[test]
fn wildcard_matching_has_a_dns_label_boundary() {
    let authorizer =
        NetworkAuthorizer::new(policy(true), NetworkLimits::default()).expect("policy");
    let address = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert!(authorizer
        .authorize_connect(&binding(), request("a.packages.example", vec![address]), 1)
        .is_ok());
    for host in ["packages.example", "badpackages.example", "example"] {
        assert!(matches!(
            authorizer.authorize_connect(&binding(), request(host, vec![address]), 1),
            Err(NetworkError::DestinationDenied { .. })
        ));
    }
}

#[test]
fn any_private_or_special_rebinding_address_rejects_the_resolution() {
    let authorizer =
        NetworkAuthorizer::new(policy(true), NetworkLimits::default()).expect("policy");
    let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    for private in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        "fd00::1".parse().expect("IPv6"),
        "2001:db8::1".parse().expect("IPv6"),
    ] {
        assert!(matches!(
            authorizer.authorize_connect(
                &binding(),
                request("api.example", vec![public, private]),
                1
            ),
            Err(NetworkError::AddressDenied(address)) if address == private
        ));
    }
}

#[test]
fn explicit_private_range_policy_can_admit_loopback_but_not_unspecified() {
    let authorizer =
        NetworkAuthorizer::new(policy(false), NetworkLimits::default()).expect("policy");
    assert!(authorizer
        .authorize_connect(
            &binding(),
            request("api.example", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            1
        )
        .is_ok());
    assert!(matches!(
        authorizer.authorize_connect(
            &binding(),
            request("api.example", vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]),
            1
        ),
        Err(NetworkError::AddressDenied(_))
    ));
}

#[test]
fn restricted_dns_and_listen_are_independently_enforced() {
    let authorizer =
        NetworkAuthorizer::new(policy(true), NetworkLimits::default()).expect("policy");
    assert!(authorizer.authorize_dns_query("api.example").is_ok());
    assert!(authorizer.authorize_dns_query("x.packages.example").is_ok());
    assert!(matches!(
        authorizer.authorize_dns_query("metadata.internal"),
        Err(NetworkError::DnsDenied(_))
    ));
    assert!(authorizer.authorize_listen(8080).is_ok());
    assert!(matches!(
        authorizer.authorize_listen(8081),
        Err(NetworkError::ListenDenied(8081))
    ));
}

#[test]
fn deny_policy_and_noncanonical_policy_fail_closed() {
    let denied = NetworkAuthorizer::new(NetworkPermission::Deny, NetworkLimits::default())
        .expect("deny policy");
    assert!(matches!(
        denied.authorize_connect(
            &binding(),
            request(
                "api.example",
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
            ),
            1
        ),
        Err(NetworkError::NetworkDenied)
    ));

    let mut noncanonical = policy(true);
    let NetworkPermission::Allow { destinations, .. } = &mut noncanonical else {
        unreachable!()
    };
    destinations.reverse();
    assert!(matches!(
        NetworkAuthorizer::new(noncanonical, NetworkLimits::default()),
        Err(NetworkError::NonCanonicalPolicy)
    ));

    let authorizer =
        NetworkAuthorizer::new(policy(true), NetworkLimits::default()).expect("policy");
    let mut invalid_attempt = binding();
    invalid_attempt.job_attempt = 0;
    assert!(matches!(
        authorizer.authorize_connect(
            &invalid_attempt,
            request(
                "api.example",
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
            ),
            1
        ),
        Err(NetworkError::InvalidJobAttempt)
    ));
}

#[test]
fn ticket_subject_tampering_is_detected() {
    let authorizer =
        NetworkAuthorizer::new(policy(true), NetworkLimits::default()).expect("policy");
    let address = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let mut ticket = authorizer
        .authorize_connect(&binding(), request("api.example", vec![address]), 100)
        .expect("ticket");
    ticket.host = "other.example".to_owned();
    assert!(matches!(
        authorizer.authorize_ticket_use(&ticket, &binding(), address, 120),
        Err(NetworkError::InvalidTicket)
    ));
}
