# PacGate Documentation Index

| Category | Document | Description | Audience |
|----------|----------|-------------|----------|
| Design | [Architecture](design/architecture.md) | System architecture, module hierarchy, data flow | Engineers |
| Design | [Design Decisions](design/design-decisions.md) | All design decisions with rationale | Engineers, Architects |
| Design | [CI Pipeline](design/ci-pipeline.md) | Continuous integration pipeline design | DevOps, Engineers |
| Verification | [Verification Strategy](verification/verification-strategy.md) | Multi-layer verification philosophy | Engineers, Management |
| Verification | [Test Plan](verification/test-plan.md) | Complete test matrix with status | Engineers, QA |
| Verification | [Test Harness Architecture](verification/test-harness-architecture.md) | Auto-generated verification framework | Engineers |
| Verification | [Coverage Model](verification/coverage-model.md) | Functional coverage definitions | Engineers |
| Verification | [Test Guide](verification/TEST_GUIDE.md) | Test and verification guide | Engineers |
| User Guide | [Getting Started](user-guide/getting-started.md) | Quick start (5 minutes) | All |
| User Guide | [User's Guide](user-guide/USERS_GUIDE.md) | Comprehensive guide with 11+ examples | All |
| User Guide | [Rule Language Reference](user-guide/rule-language-reference.md) | Complete YAML syntax reference | All |
| User Guide | [Workshops](WORKSHOPS.md) | 8 hands-on workshops (beginner to advanced) | All |
| API | [Compiler API](api/compiler-api.md) | CLI, internal modules, verification framework | Engineers |
| Management | [Executive Summary](management/executive-summary.md) | Problem, solution, ROI, status | Leadership |
| Management | [Innovation Analysis](management/innovation-analysis.md) | Competitive landscape, IP, roadmap | Leadership, Strategy |
| Management | [Roadmap](management/roadmap.md) | Phase timeline through 2027 | Leadership, PM |
| Management | [Companion Product Proposal](management/companion-product-proposal.md) | Scope proposal for PacLab system-verification companion | Leadership, PM, Architects |
| Management | [PacLab Schema Draft](management/paclab/README.md) | Draft scenario schema and example for PacLab orchestration | Engineers, Architects |
| Management | [Slideshow](management/SLIDESHOW.md) | 13-slide product overview presentation | Leadership |
| Management | [Why PacGate?](WHY_PACGATE.md) | Value proposition for skeptics and decision-makers | Leadership, Architects |
| Research | [Research Report](RESEARCH.md) | cocotb, coverage, mutation testing, formal verification | Engineers, Academics |
| Diagrams | [System Diagrams](diagrams/system-diagrams.md) | Architecture, data flow, FSM, verification | All |

## Examples

42 production-quality YAML examples covering real-world deployments:

| Example | Rules | Category | Description |
|---------|:-----:|----------|-------------|
| `allow_arp.yaml` | 1 | Basic | Minimal — allow ARP only |
| `enterprise.yaml` | 7 | Campus | Multi-rule enterprise firewall |
| `blacklist.yaml` | 5 | Security | Threat blocking (blacklist mode) |
| `datacenter.yaml` | 8 | Data Center | Multi-tenant data center |
| `stateful_sequence.yaml` | 2 | Stateful | Stateful FSM: ARP → IPv4 sequence |
| `industrial_ot.yaml` | 8 | Industrial | OT/SCADA boundary (EtherCAT, PROFINET, PTP) |
| `automotive_gateway.yaml` | 7 | Automotive | Automotive Ethernet gateway (AVB/TSN, ADAS) |
| `5g_fronthaul.yaml` | 7 | Telecom | 5G fronthaul filtering (eCPRI, PTP, Sync-E) |
| `campus_access.yaml` | 8 | Campus | Campus access control |
| `iot_gateway.yaml` | 7 | IoT | IoT edge gateway |
| `syn_flood_detect.yaml` | 3 | Security | SYN flood detection (stateful FSM) |
| `arp_spoof_detect.yaml` | 3 | Security | ARP spoofing detection (stateful FSM) |
| `l3l4_firewall.yaml` | 7 | Firewall | L3/L4 firewall (SSH, HTTP/S, DNS, ICMP) |
| `byte_match.yaml` | 3 | Advanced | Byte-offset matching (IPv4 version, TCP SYN flag) |
| `hsm_conntrack.yaml` | 3 | Stateful | Hierarchical state machine + connection tracking |
| `ipv6_firewall.yaml` | 6 | Firewall | IPv6 firewall (ICMPv6, CIDR, link-local) |
| `rate_limited.yaml` | 5 | Security | Rate-limited rules (HTTP/DNS/SSH token-bucket) |
| `vxlan_datacenter.yaml` | 6 | Tunnel | VXLAN datacenter (multi-tenant VNI isolation) |
| `gtp_5g.yaml` | 5 | Tunnel | GTP-U 5G mobile core (TEID-based filtering) |
| `mpls_network.yaml` | 5 | Provider | MPLS provider network (label stack matching) |
| `multicast.yaml` | 5 | Multicast | IGMP/MLD multicast filtering |
| `dynamic_firewall.yaml` | 5 | Dynamic | Runtime-updateable flow table (`--dynamic`) |
| `qos_classification.yaml` | 7 | QoS | DSCP/ECN QoS classification |
| `rewrite_actions.yaml` | 5 | Rewrite | Packet rewrite (MAC/IP/TTL/DSCP) |
| `tcp_flags_icmp.yaml` | 7 | Security | TCP SYN/Xmas/ICMP detection |
| `arp_security.yaml` | 5 | Security | ARP security (opcode/spa/tpa) |
| `icmpv6_firewall.yaml` | 5 | Firewall | ICMPv6 NDP/echo filtering |
| `qinq_provider.yaml` | 5 | Carrier | QinQ (802.1ad) provider edge |
| `fragment_security.yaml` | 5 | Security | IPv4 fragmentation attack detection |
| `port_rewrite.yaml` | 5 | Rewrite | L4 port rewrite (PAT/port forwarding) |
| `gre_tunnel.yaml` | 5 | Tunnel | GRE tunnel matching (IP proto 47) |
| `conntrack_firewall.yaml` | 5 | Stateful | Stateful connection tracking firewall |
| `mirror_redirect.yaml` | 5 | Egress | Mirror/redirect egress actions |
| `flow_counters.yaml` | 5 | Counters | Per-flow packet/byte counters |
| `oam_monitoring.yaml` | 5 | OAM | IEEE 802.1ag OAM/CFM monitoring |
| `nsh_sfc.yaml` | 5 | SFC | NSH/SFC service function chaining (RFC 8300) |
| `geneve_datacenter.yaml` | 5 | Tunnel | Geneve cloud overlay (RFC 8926) |
| `ttl_security.yaml` | 5 | Security | TTL-based security + runt frame detection |
| `ipv6_routing.yaml` | 5 | Rewrite | IPv6 routing (hop limit + ECN rewrite) |
| `qos_rewrite.yaml` | 5 | Rewrite | VLAN PCP remarking + QinQ outer tag rewrite |
| `opennic_l3l4.yaml` | 5 | Platform | OpenNIC Shell platform target |
| `corundum_datacenter.yaml` | 5 | Platform | Corundum NIC platform target |
