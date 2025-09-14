use std::{collections::HashMap, str::FromStr};

use advmac::MacAddr6;
use compact_str::ToCompactString;
use tracing::{debug, info};

use crate::Option82;

pub type Option82ExtractorFn = fn(opt: &Option82) -> Option<Option82>;

/// Extract the Remote-ID only if it exists.
pub fn remote_only(opt: &Option82) -> Option<Option82> {
    opt.remote.as_ref().map(|remote| Option82 {
        circuit: None,
        remote: Some(remote.clone()),
        subscriber: None,
    })
}

/// Trim the Remote-ID and remove any trailing null characters.
pub fn remote_only_trim(opt: &Option82) -> Option<Option82> {
    opt.remote.as_ref().map(|remote| Option82 {
        circuit: None,
        remote: Some(remote.trim().trim_end_matches('\0').to_compact_string()),
        subscriber: None,
    })
}

/// Extract the Circuit-ID only if it exists.
pub fn circuit_only(opt: &Option82) -> Option<Option82> {
    opt.circuit.as_ref().map(|circuit| Option82 {
        circuit: Some(circuit.clone()),
        remote: None,
        subscriber: None,
    })
}

/// Extract the Circuit-ID and Remote-ID if both exist.
pub fn circuit_and_remote(opt: &Option82) -> Option<Option82> {
    if opt.circuit.is_some() && opt.remote.is_some() {
        Some(Option82 {
            circuit: opt.circuit.clone(),
            remote: opt.remote.clone(),
            subscriber: None,
        })
    } else {
        None
    }
}

/// Extract the Subscriber-ID only if it exists.
pub fn subscriber_only(opt: &Option82) -> Option<Option82> {
    opt.subscriber.as_ref().map(|subscriber| Option82 {
        circuit: None,
        remote: None,
        subscriber: Some(subscriber.clone()),
    })
}

/// Read the first 12 characters of Remote-ID and parse as a MacAddr6.
/// Then format the MacAddr6 with dash format for lookup in reservations.
pub fn remote_first_12(opt: &Option82) -> Option<Option82> {
    let mac = opt.remote.as_ref().and_then(|remote| {
        remote
            .get(0..12)
            .and_then(|substring| MacAddr6::from_str(substring).ok())
    });

    match mac {
        Some(mac) => {
            info!(%mac, "Extracted MAC with remote_first_12 extractor");
            Some(Option82 {
                circuit: None,
                remote: Some(mac.to_compact_string()),
                subscriber: None,
            })
        }
        None => None,
    }
}

/// Parse the entire Remote-ID as a MAC address and re-encode to a MAC address formatted with dashes.
pub fn normalize_remote_mac(opt: &Option82) -> Option<Option82> {
    let mac = opt
        .remote
        .as_ref()
        .and_then(|remote| MacAddr6::from_str(remote).ok());

    match mac {
        Some(mac) => {
            info!(%mac, "Normalized remote MAC");
            Some(Option82 {
                circuit: None,
                remote: Some(mac.to_compact_string()),
                subscriber: None,
            })
        }
        None => {
            debug!("Normalize remote MAC didn't find a parseable MAC");
            None
        }
    }
}

pub fn get_all_extractors() -> HashMap<&'static str, Option82ExtractorFn> {
    let mut extractors = HashMap::new();
    extractors.insert("remote_only", remote_only as Option82ExtractorFn);
    extractors.insert("remote_only_trim", remote_only_trim as Option82ExtractorFn);
    extractors.insert("subscriber_only", subscriber_only as Option82ExtractorFn);
    extractors.insert(
        "circuit_and_remote",
        circuit_and_remote as Option82ExtractorFn,
    );
    extractors.insert("circuit_only", circuit_only as Option82ExtractorFn);
    extractors.insert("remote_first_12", remote_first_12 as Option82ExtractorFn);
    extractors.insert(
        "normalize_remote_mac",
        normalize_remote_mac as Option82ExtractorFn,
    );

    extractors
}

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::ToCompactString;

    #[test]
    fn test_remote_only() {
        let wire_opt = Option82 {
            circuit: Some("eth0".to_compact_string()),
            remote: Some("001122334455".to_compact_string()),
            subscriber: Some("id1".to_compact_string()),
        };
        let extracted = remote_only(&wire_opt);
        assert_eq!(
            extracted,
            Some(Option82 {
                circuit: None,
                remote: Some("001122334455".to_compact_string()),
                subscriber: None
            })
        );
    }

    #[test]
    fn test_remote_only_trim() {
        let wire_opt = Option82 {
            circuit: Some("eth0".to_compact_string()),
            remote: Some("001122334455".to_compact_string()),
            subscriber: Some("id1".to_compact_string()),
        };

        let wire_opt_space = Option82 {
            circuit: Some("eth0".to_compact_string()),
            remote: Some("001122334455 ".to_compact_string()),
            subscriber: Some("id1".to_compact_string()),
        };

        let wire_opt_null = Option82 {
            circuit: Some("eth0".to_compact_string()),
            remote: Some("001122334455\0".to_compact_string()),
            subscriber: Some("id1".to_compact_string()),
        };

        let desired = Some(Option82 {
            circuit: None,
            remote: Some("001122334455".to_compact_string()),
            subscriber: None,
        });
        assert_eq!(remote_only_trim(&wire_opt), desired);
        assert_eq!(remote_only_trim(&wire_opt_space), desired);
        assert_eq!(remote_only_trim(&wire_opt_null), desired);
    }

    #[test]
    fn test_circuit_only() {
        let wire_opt = Option82 {
            circuit: Some("eth0".to_compact_string()),
            remote: Some("001122334455".to_compact_string()),
            subscriber: Some("id1".to_compact_string()),
        };
        let extracted = circuit_only(&wire_opt);
        assert_eq!(
            extracted,
            Some(Option82 {
                circuit: Some("eth0".to_compact_string()),
                remote: None,
                subscriber: None
            })
        );
    }

    #[test]
    fn test_subscriber_only() {
        let wire_opt = Option82 {
            circuit: Some("eth0".to_compact_string()),
            remote: Some("001122334455".to_compact_string()),
            subscriber: Some("id1".to_compact_string()),
        };
        let extracted = subscriber_only(&wire_opt);
        assert_eq!(
            extracted,
            Some(Option82 {
                circuit: None,
                remote: None,
                subscriber: Some("id1".to_compact_string()),
            })
        );
    }

    #[test]
    fn test_circuit_and_remote() {
        let wire_opt = Option82 {
            circuit: Some("eth0".to_compact_string()),
            remote: Some("001122334455".to_compact_string()),
            subscriber: Some("id1".to_compact_string()),
        };
        let extracted = circuit_and_remote(&wire_opt);
        assert_eq!(
            extracted,
            Some(Option82 {
                circuit: Some("eth0".to_compact_string()),
                remote: Some("001122334455".to_compact_string()),
                subscriber: None
            })
        );
    }

    #[test]
    fn test_extract_ubiquiti_ufiber() {
        // TODO: create extractor for capitalization?
        let wire_opt = Option82 {
            circuit: Some("b4fbe4501fda/1/ac8ba9e217f8".to_compact_string()),
            remote: Some("ac8ba9e217f8".to_compact_string()),
            subscriber: None,
        };
        let extracted = remote_first_12(&wire_opt);
        assert_eq!(
            extracted,
            Some(Option82 {
                circuit: None,
                remote: Some("AC-8B-A9-E2-17-F8".to_compact_string()),
                subscriber: None
            })
        );
    }

    #[test]
    fn test_normalize_remote_mac() {
        let wire_opt = Option82 {
            circuit: None,
            remote: Some("001122334455".to_compact_string()),
            subscriber: None,
        };
        let extracted = normalize_remote_mac(&wire_opt);
        assert_eq!(
            extracted,
            Some(Option82 {
                circuit: None,
                remote: Some("00-11-22-33-44-55".to_compact_string()),
                subscriber: None
            })
        );
    }
}
