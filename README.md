# shadowdhcp

A reservation only DHCPv4 and DHCPv6 server designed for internet service providers.

⚠⚠ Please use the [Kea DHCP server](https://www.isc.org/kea/) for more options and features! ⚠⚠

shadowdhcp:

* Reservation only
* In memory only, no database backend
* No high availability
* Only responds to relayed or unicast requests
* IPv6 IA_NA and IA_PD are required for each reservation
* Supports dynamic IPv4 Option82 to IPv6 mappings. When a client receives an IPv4 address via Option82, the server remembers their MAC address and can use the MAC to deliver IPv6 address information

## Option82 extractors

Multiple extractors are defined and can be enabled in the config file to try and parse Option82 data from the circuit, remote, and subscriber fields.

## Example config:

```json
{
    "dns_v4": [
        "8.8.8.8",
        "8.8.4.4"
    ],
    "subnets_v4": [
        {
            "net": "100.100.1.0/24",
            "gateway": "100.100.1.1"
        },
        {
            "net": "100.100.2.0/24",
            "gateway": "100.100.3.1"
        }
    ],
    "option82_extractors": [
        "remote_only",
        "subscriber_only",
        "circuit_and_remote",
        "remote_first_12"
    ]
}
```

## Example reservations

Reservations must contain:
 * ipv4
 * ipv6_na
 * ipv6_pd
 * At least one source for IPv4 and IPv6. Some sources can be used for both
   * mac - can be used for both
   * option82 - can be used for both. Should be formatted in all caps dash format: AA-BB-CC-DD-EE-FF
   * duid - IPv6 only

Reservations with multiple sources will be evaluated in the following order:

IPv4: mac -> option82

IPv6: duid -> option 18 / option 37 -> mac -> option82

`reservations.json`:
```json
[
    {
        "ipv4": "192.168.1.109",
        "ipv6_na": "2001:db8:1:2::1",
        "ipv6_pd": "2001:db8:1:3::/56",
        "mac": "00-11-22-33-44-55"
    },
    {
        "ipv4": "192.168.1.110",
        "ipv6_na": "2001:db8:1:4::1",
        "ipv6_pd": "2001:db8:1:5::/56",
        "mac": "00-11-22-33-44-57"
    },
    {
        "ipv4": "192.168.1.111",
        "ipv6_na": "2001:db8:1:6::1",
        "ipv6_pd": "2001:db8:1:7::/56",
        "option82": {"circuit": "99-11-22-33-44-55", "remote": "eth2:100"}
    },
    {
        "ipv4": "192.168.1.112",
        "ipv6_na": "2001:db8:1:8::1",
        "ipv6_pd": "2001:db8:1:9::/56",
        "duid": "29:30:31:32:33:34:35:36:37:38:39:40:41:42:43:44",
        "option82": {"subscriber": "subscriber:1020"}
    },
    {
        "ipv4": "100.110.1.2",
        "ipv6_na": "2001:db8:1::1",
        "ipv6_pd": "2001:db8:2::/56",
        "option82": {"remote": "AC-8B-A9-E2-17-F8"}
    }
]
```
