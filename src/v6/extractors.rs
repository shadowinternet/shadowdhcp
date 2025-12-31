use std::collections::HashMap;

use shadowdhcp::Option1837;

pub type Option1837ExtractorFn = fn(opt: &Option1837) -> Option<Option1837>;

/// A named extractor tuple: (name, function)
pub type NamedOption1837Extractor = (&'static str, Option1837ExtractorFn);

/// Extract the Interface-ID (Option 18) only if it exists.
pub fn interface_only(opt: &Option1837) -> Option<Option1837> {
    opt.interface.as_ref().map(|interface| Option1837 {
        interface: Some(interface.clone()),
        remote: None,
        enterprise_number: None,
    })
}

/// Extract the Remote-ID (Option 37) only if it exists.
pub fn remote_only(opt: &Option1837) -> Option<Option1837> {
    opt.remote.as_ref().map(|remote| Option1837 {
        interface: None,
        remote: Some(remote.clone()),
        enterprise_number: None,
    })
}

/// Extract Interface-ID and Remote-ID if both exist.
pub fn interface_and_remote(opt: &Option1837) -> Option<Option1837> {
    if opt.interface.is_some() && opt.remote.is_some() {
        Some(Option1837 {
            interface: opt.interface.clone(),
            remote: opt.remote.clone(),
            enterprise_number: None,
        })
    } else {
        None
    }
}

/// Extract Remote-ID with enterprise number if both exist.
pub fn remote_with_enterprise(opt: &Option1837) -> Option<Option1837> {
    if opt.remote.is_some() && opt.enterprise_number.is_some() {
        Some(Option1837 {
            interface: None,
            remote: opt.remote.clone(),
            enterprise_number: opt.enterprise_number,
        })
    } else {
        None
    }
}

/// Extract all fields if at least interface or remote exists.
pub fn all_fields(opt: &Option1837) -> Option<Option1837> {
    if opt.interface.is_some() || opt.remote.is_some() {
        Some(opt.clone())
    } else {
        None
    }
}

pub fn get_all_extractors() -> HashMap<&'static str, Option1837ExtractorFn> {
    let mut extractors = HashMap::new();
    extractors.insert("interface_only", interface_only as Option1837ExtractorFn);
    extractors.insert("remote_only", remote_only as Option1837ExtractorFn);
    extractors.insert(
        "interface_and_remote",
        interface_and_remote as Option1837ExtractorFn,
    );
    extractors.insert(
        "remote_with_enterprise",
        remote_with_enterprise as Option1837ExtractorFn,
    );
    extractors.insert("all_fields", all_fields as Option1837ExtractorFn);

    extractors
}

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::ToCompactString;

    #[test]
    fn test_interface_only() {
        let opt = Option1837 {
            interface: Some("eth0/1".to_compact_string()),
            remote: Some("remote-id".to_compact_string()),
            enterprise_number: Some(12345),
        };
        let extracted = interface_only(&opt);
        assert_eq!(
            extracted,
            Some(Option1837 {
                interface: Some("eth0/1".to_compact_string()),
                remote: None,
                enterprise_number: None,
            })
        );
    }

    #[test]
    fn test_remote_only() {
        let opt = Option1837 {
            interface: Some("eth0/1".to_compact_string()),
            remote: Some("remote-id".to_compact_string()),
            enterprise_number: Some(12345),
        };
        let extracted = remote_only(&opt);
        assert_eq!(
            extracted,
            Some(Option1837 {
                interface: None,
                remote: Some("remote-id".to_compact_string()),
                enterprise_number: None,
            })
        );
    }

    #[test]
    fn test_interface_and_remote() {
        let opt = Option1837 {
            interface: Some("eth0/1".to_compact_string()),
            remote: Some("remote-id".to_compact_string()),
            enterprise_number: Some(12345),
        };
        let extracted = interface_and_remote(&opt);
        assert_eq!(
            extracted,
            Some(Option1837 {
                interface: Some("eth0/1".to_compact_string()),
                remote: Some("remote-id".to_compact_string()),
                enterprise_number: None,
            })
        );

        // Should return None if either is missing
        let opt_no_remote = Option1837 {
            interface: Some("eth0/1".to_compact_string()),
            remote: None,
            enterprise_number: None,
        };
        assert_eq!(interface_and_remote(&opt_no_remote), None);
    }

    #[test]
    fn test_remote_with_enterprise() {
        let opt = Option1837 {
            interface: Some("eth0/1".to_compact_string()),
            remote: Some("remote-id".to_compact_string()),
            enterprise_number: Some(12345),
        };
        let extracted = remote_with_enterprise(&opt);
        assert_eq!(
            extracted,
            Some(Option1837 {
                interface: None,
                remote: Some("remote-id".to_compact_string()),
                enterprise_number: Some(12345),
            })
        );

        // Should return None if enterprise_number is missing
        let opt_no_enterprise = Option1837 {
            interface: None,
            remote: Some("remote-id".to_compact_string()),
            enterprise_number: None,
        };
        assert_eq!(remote_with_enterprise(&opt_no_enterprise), None);
    }
}
