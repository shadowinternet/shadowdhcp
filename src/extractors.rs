use std::{collections::HashMap, str::FromStr};

use advmac::MacAddr6;

use crate::Option82;

pub type Option82ExtractorFn = fn(opt: &Option82) -> Option<Option82>;

/// Read the first 12 characters of Remote-ID and parse as a MacAddr6.
/// Then format the MacAddr6 with dash format for lookup in reservations.
/// ```
/// use shadow_dhcpv6::Option82;
/// use shadow_dhcpv6::extractors;
///
/// let wire_opt = Option82 {
///     circuit: Some("11-11-22-33-44-55".to_string()),
///     remote: Some("001122334455/eth0/gi1/eth0:100".to_string()),
///     subscriber: None,
/// };
/// assert_eq!(extractors::extract_ubiquiti_ufiber(&wire_opt), Some(
///     Option82{
///         circuit: None,
///         remote: Some("00-11-22-33-44-55".to_string()),
///         subscriber: None
/// }));
/// ```
pub fn extract_ubiquiti_ufiber(opt: &Option82) -> Option<Option82> {
    let mac = opt.remote.as_ref().and_then(|remote| {
        remote
            .get(0..12)
            .and_then(|substring| MacAddr6::from_str(substring).ok())
    });

    match mac {
        Some(mac) => {
            println!("Extracted MAC with ubiquiti ufiber extractor: {}", mac);
            Some(Option82 {
                circuit: None,
                remote: Some(mac.to_string()),
                subscriber: None,
            })
        }
        None => {
            println!("ubiquiti ufiber extractor didn't find MAC");
            None
        }
    }
}

/// Parse the entire Remote-ID as a MAC address and re-encode to a MAC address formatted with dashes.
///
/// ```
/// use shadow_dhcpv6::Option82;
/// use shadow_dhcpv6::extractors;
///
/// let wire_opt1 = Option82 {
///     circuit: None,
///     remote: Some("00:11:22:33:44:55".to_string()),
///     subscriber: None,
/// };
///
/// let wire_opt2 = Option82 {
///     circuit: None,
///     remote: Some("00-11-22-33-44-55".to_string()),
///     subscriber: None,
/// };
///
/// let wire_opt3 = Option82 {
///     circuit: None,
///     remote: Some("001122334455".to_string()),
///     subscriber: None,
/// };
///
/// let output = Some(Option82 {
///     circuit: None,
///     remote: Some("00-11-22-33-44-55".to_string()),
///     subscriber: None,
/// });
///
/// assert_eq!(extractors::normalize_remote_mac(&wire_opt1), output);
/// assert_eq!(extractors::normalize_remote_mac(&wire_opt2), output);
/// assert_eq!(extractors::normalize_remote_mac(&wire_opt3), output);
/// ```
pub fn normalize_remote_mac(opt: &Option82) -> Option<Option82> {
    let mac = opt
        .remote
        .as_ref()
        .and_then(|remote| MacAddr6::from_str(remote).ok());

    match mac {
        Some(mac) => {
            println!("Normalized remote MAC {}", mac);
            Some(Option82 {
                circuit: None,
                remote: Some(mac.to_string()),
                subscriber: None,
            })
        }
        None => {
            println!("Normalize remote MAC didn't find a parseable MAC");
            None
        }
    }
}

pub fn get_all_extractors() -> HashMap<&'static str, Option82ExtractorFn> {
    let mut extractors = HashMap::new();
    extractors.insert(
        "ubiquiti_ufiber",
        extract_ubiquiti_ufiber as Option82ExtractorFn,
    );
    extractors.insert(
        "normalize_remote_mac",
        normalize_remote_mac as Option82ExtractorFn,
    );
    extractors
}
