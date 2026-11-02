use std::net::IpAddr;

use poem::Request;
use poem::http::header::HOST;
use poem::http::uri::Scheme;
use warpgate_common::http_headers::{X_FORWARDED_HOST, X_FORWARDED_PROTO};

use crate::{
    X_WARPGATE_CLUSTER_CLIENT_HOST, X_WARPGATE_CLUSTER_CLIENT_IP, X_WARPGATE_CLUSTER_CLIENT_PROTO,
    is_cluster_peer_request,
};

// proxies append to the end of XFF header
pub fn last_forwarded_header_value(value: &str) -> Option<&str> {
    value
        .rsplit(',')
        .map(str::trim)
        .find(|value| !value.is_empty())
}

/// The host the client asked for: an authenticated cluster peer's word, else
/// `X-Forwarded-Host` when trusted, else the `Host` header.
pub fn trusted_host_header(should_trust_x_forwarded: bool, req: &Request) -> Option<String> {
    if is_cluster_peer_request(req)
        && let Some(host) = req
            .header(&X_WARPGATE_CLUSTER_CLIENT_HOST)
            .map(str::trim)
            .filter(|host| !host.is_empty())
    {
        return Some(host.to_string());
    }

    if should_trust_x_forwarded
        && let Some(host) = req
            .header(&X_FORWARDED_HOST)
            .and_then(last_forwarded_header_value)
    {
        return Some(host.to_string());
    }

    req.header(HOST).map(ToString::to_string).or_else(|| {
        let uri = req.original_uri();
        uri.authority().map(|authority| authority.to_string())
    })
}

/// Request data from the HTTP listener: whether it serves plain HTTP
/// (`http.plain_http_on_loopback`). A request without it came over TLS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlainHttpListener(pub bool);

/// The scheme the client used: an authenticated cluster peer's word, else
/// `X-Forwarded-Proto` when trusted, else the request's own scheme.
pub fn trusted_proto(should_trust_x_forwarded: bool, req: &Request) -> Scheme {
    if is_cluster_peer_request(req)
        && let Some(proto) = req
            .header(&X_WARPGATE_CLUSTER_CLIENT_PROTO)
            .and_then(|proto| Scheme::try_from(proto.trim()).ok())
    {
        proto
    } else if should_trust_x_forwarded
        && let Some(proto) = req
            .header(&X_FORWARDED_PROTO)
            .and_then(last_forwarded_header_value)
        && let Ok(s) = Scheme::try_from(proto)
    {
        s
    } else {
        req.original_uri().scheme().cloned().unwrap_or_else(|| {
            if req
                .data::<PlainHttpListener>()
                .is_some_and(|listener| listener.0)
            {
                Scheme::HTTP
            } else {
                Scheme::HTTPS
            }
        })
    }
}

/// The client address for a web request: an authenticated cluster peer's
/// word, else the header the operator named in `client_ip_header`,
/// else the socket peer. `X-Forwarded-For` is never read here: the caller writes
/// it, so it cannot say who the caller is. A proxy in front of Warpgate names
/// the header it sets itself (e.g. `CF-Connecting-IP`, `X-Real-IP`).
pub fn trusted_client_ip(
    req: &Request,
    remote_ip: Option<String>,
    client_ip_header: Option<&str>,
) -> Option<String> {
    if is_cluster_peer_request(req)
        && let Some(ip) = req.header(&X_WARPGATE_CLUSTER_CLIENT_IP)
    {
        Some(ip.to_string())
    } else if let Some(name) = client_ip_header {
        req.header(name)
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_string())
            .or(remote_ip)
    } else {
        remote_ip
    }
}

#[cfg(test)]
mod tests {
    use poem::Request;
    use poem::http::header::HOST;
    use uuid::Uuid;
    use warpgate_common::NodeId;
    use warpgate_common::http_headers::X_FORWARDED_FOR;

    use super::*;
    use crate::ClusterPeer;

    fn trusted_header_request(
        forwarded_host: Option<&str>,
        forwarded_proto: Option<&str>,
    ) -> Request {
        let mut builder = Request::builder()
            .uri_str("http://internal.example")
            .header(HOST, "fallback.example");

        if let Some(value) = forwarded_host {
            builder = builder.header(&X_FORWARDED_HOST, value);
        }
        if let Some(value) = forwarded_proto {
            builder = builder.header(&X_FORWARDED_PROTO, value);
        }

        builder.finish()
    }

    #[test]
    fn trusted_host_uses_last_forwarded_host() {
        let req = trusted_header_request(Some("client.example, public.example"), None);

        assert_eq!(
            trusted_host_header(true, &req),
            Some("public.example".to_string())
        );
    }

    #[test]
    fn trusted_host_header_preserves_port() {
        let req = Request::builder()
            .uri_str("http://internal.example")
            .header(HOST, "vm.example.com:3000")
            .finish();

        assert_eq!(
            trusted_host_header(false, &req),
            Some("vm.example.com:3000".to_string())
        );
    }

    #[test]
    fn trusted_host_falls_back_when_forwarded_host_is_empty() {
        let req = trusted_header_request(Some(" , "), None);

        assert_eq!(
            trusted_host_header(true, &req),
            Some("fallback.example".to_string())
        );
    }

    #[test]
    fn trusted_proto_is_https_by_default() {
        for listener in [None, Some(PlainHttpListener(false))] {
            let mut builder = Request::builder().header(HOST, "warpgate.example");
            if let Some(listener) = listener {
                builder = builder.extension(listener);
            }
            assert_eq!(trusted_proto(false, &builder.finish()), Scheme::HTTPS);
        }
    }

    #[test]
    fn trusted_proto_is_http_on_a_plain_http_listener() {
        let req = Request::builder()
            .header(HOST, "localhost:8888")
            .extension(PlainHttpListener(true))
            .finish();

        assert_eq!(trusted_proto(false, &req), Scheme::HTTP);
    }

    #[test]
    fn trusted_proto_uses_last_forwarded_proto() {
        let req = trusted_header_request(None, Some("http, https"));

        assert_eq!(trusted_proto(true, &req), Scheme::HTTPS);
    }

    #[test]
    fn last_forwarded_header_value_skips_empty_items() {
        assert_eq!(
            last_forwarded_header_value("client.example, public.example, "),
            Some("public.example")
        );
        assert_eq!(last_forwarded_header_value(" , "), None);
    }

    #[test]
    fn client_ip_never_comes_from_forwarded_for() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "198.51.100.7, 203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), None),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn trusted_client_ip_ignores_a_forwarded_for_that_is_not_an_address() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "203.0.113.10, not-an-ip")
            .finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), None),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn trusted_client_ip_falls_back_when_forwarded_for_is_empty() {
        let req = Request::builder().header(&X_FORWARDED_FOR, " , ").finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), None),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn client_ip_ignores_forwarded_for_when_not_trusted() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), None),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn client_ip_takes_the_forwarding_peers_word_for_it() {
        let mut req = Request::builder()
            .header(&X_WARPGATE_CLUSTER_CLIENT_IP, "203.0.113.10")
            .finish();
        // What cluster_peer_extension attaches for a connection the acceptor
        // authenticated as a pinned node
        req.extensions_mut().insert(ClusterPeer {
            node_id: NodeId(Uuid::new_v4()),
        });

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), None),
            Some("203.0.113.10".to_string())
        );
    }

    #[test]
    fn client_ip_ignores_a_cluster_client_ip_from_a_non_peer() {
        let req = Request::builder()
            .header(&X_WARPGATE_CLUSTER_CLIENT_IP, "203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), None),
            Some("10.0.0.1".to_string())
        );
    }

    fn cluster_peer_request(host: Option<&str>, proto: Option<&str>, peer: bool) -> Request {
        let mut builder = Request::builder()
            .uri_str("http://internal.example")
            .header(HOST, "node-sni.example");
        if let Some(value) = host {
            builder = builder.header(&X_WARPGATE_CLUSTER_CLIENT_HOST, value);
        }
        if let Some(value) = proto {
            builder = builder.header(&X_WARPGATE_CLUSTER_CLIENT_PROTO, value);
        }
        let mut req = builder.finish();
        if peer {
            req.extensions_mut().insert(ClusterPeer {
                node_id: NodeId(Uuid::new_v4()),
            });
        }
        req
    }

    #[test]
    fn host_and_proto_take_the_forwarding_peers_word_for_them() {
        let req = cluster_peer_request(Some("client.example:8888"), Some("https"), true);

        assert_eq!(
            trusted_host_header(false, &req),
            Some("client.example:8888".to_string())
        );
        assert_eq!(trusted_proto(false, &req), Scheme::HTTPS);
    }

    #[test]
    fn host_and_proto_ignore_cluster_headers_from_a_non_peer() {
        let req = cluster_peer_request(Some("client.example"), Some("https"), false);

        assert_eq!(
            trusted_host_header(false, &req),
            Some("node-sni.example".to_string())
        );
        assert_eq!(trusted_proto(false, &req), Scheme::HTTP);
    }

    #[test]
    fn peer_request_without_cluster_host_falls_back_to_the_host_header() {
        let req = cluster_peer_request(None, Some("not a scheme"), true);

        assert_eq!(
            trusted_host_header(false, &req),
            Some("node-sni.example".to_string())
        );
        assert_eq!(trusted_proto(false, &req), Scheme::HTTP);
    }

    #[test]
    fn client_ip_header_wins_over_forwarded_for() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "198.51.100.66")
            .header("cf-connecting-ip", "203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                Some("10.244.1.5".to_string()),
                Some("CF-Connecting-IP")
            ),
            Some("203.0.113.10".to_string())
        );
    }

    #[test]
    fn client_ip_header_missing_falls_back_to_peer_not_forwarded_for() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "198.51.100.66")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                Some("10.244.1.5".to_string()),
                Some("CF-Connecting-IP")
            ),
            Some("10.244.1.5".to_string())
        );
    }

    #[test]
    fn client_ip_header_rejects_a_value_that_is_not_an_address() {
        let req = Request::builder()
            .header("cf-connecting-ip", "203.0.113.10, 198.51.100.66")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                Some("10.244.1.5".to_string()),
                Some("CF-Connecting-IP")
            ),
            Some("10.244.1.5".to_string())
        );
    }

    #[test]
    fn client_ip_header_accepts_ipv6() {
        let req = Request::builder()
            .header("cf-connecting-ip", "2001:db8::7")
            .finish();

        assert_eq!(
            trusted_client_ip(&req, None, Some("CF-Connecting-IP")),
            Some("2001:db8::7".to_string())
        );
    }
}
