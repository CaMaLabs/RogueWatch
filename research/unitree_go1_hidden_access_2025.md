# Unitree Go1 hidden-access case: defensive lessons for RogueWatch

Updated: 2026-09-17

## Why this case matters

CVE-2025-2894 documents an undocumented remote-control channel in the Unitree Go1.
The published CVE classifies it as CWE-912 Hidden Functionality. The AHA disclosure
describes a CloudSail/Oray remote-access tunnel that started automatically and could
provide complete remote control to a party with valid service authorization material.

RogueWatch uses this case as a **pattern source**, not as a device blacklist.

## Known case indicators

Public reporting identifies the following high-confidence Go1-specific artifacts:

- service name: `CSClientDaemon`
- client path: `/usr/local/zhexi/cloudsail/csclient`
- vendor remediation package: `Go1_rmTunnel_2025_04_18_e5adb412.zip`
- published affected version in the CVE record: `2022_05_11_e0d0e617`

RogueWatch intentionally does not store or reproduce credential values, API keys,
passwords, or access tokens from historical reports.

## Generalized detection model

The important pattern is a conjunction rather than a single IOC:

1. a remote-access or NAT-traversal tunnel;
2. startup/boot persistence;
3. embedded or static authorization material;
4. privileged remote control or command execution;
5. functionality that is undocumented, undeclared, or bypasses owner approval.

A second pattern comes from factory/autoconnect networking:

1. a static network profile or factory Wi-Fi profile;
2. automatic connection/persistence;
3. access to a control plane or privileged service.

The scanner therefore records individual low/medium confidence features and raises
stronger composite markers only when independent components co-occur.

## Implemented RogueWatch markers

`roguewatch/backdoor_signatures.py` adds:

- `remote_tunnel_service`
- `boot_persistence`
- `embedded_auth_material`
- `privileged_remote_control`
- `hidden_functionality_language`
- `factory_wifi_autoconnect`
- `go1_cloudsail_known_ioc`
- `persistent_hidden_remote_access_pattern`
- `credential_gated_remote_control_pattern`
- `persistent_factory_network_ingress_pattern`
- `known_cve_2025_2894_artifact`

The artifact hunter includes these as `backdoor_markers` alongside the existing
swarm `incident_markers`.

## Vendor remediation

Unitree's current Go1 download page lists
`Go1_rmTunnel_2025_04_18_e5adb412.zip` and describes it as an incremental repair
patch that completely removes tunnel services for greater security.

That is useful provenance: finding the patch filename is evidence of remediation
material, not evidence that the vulnerable tunnel remains active. RogueWatch keeps
that distinction explicit.

## Safety and false-positive controls

Legitimate products use SSH, remote support, VPNs, reverse tunnels, API tokens, and
systemd services. None of those alone is evidence of a backdoor.

RogueWatch prefers combinations such as:

- tunnel + boot persistence + privileged remote control;
- tunnel + static authorization + privileged control;
- factory network autoconnect + persistence;
- any of the above plus explicit hidden/undocumented-functionality language.

The scanner hashes and classifies artifacts but does not execute retrieved material.
Public URL hunting is GET-only, rejects mutation-like paths/query parameters, and
Wayback searches retrieve archived captures rather than probing the historical origin.

## Sources

- CVE record: https://www.cve.org/CVERecord?id=CVE-2025-2894
- AHA disclosure: https://takeonme.org/cves/cve-2025-2894/
- Unitree Go1 download/remediation page: https://www.unitree.com/download/
- Public Go1 research notes: https://github.com/MAVProxyUser/YushuTechUnitreeGo1
