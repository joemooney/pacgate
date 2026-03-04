use std::collections::HashMap;
use anyhow::{Result, bail};
use crate::model::{FilterConfig, MatchCriteria, Action, PortMatch, Ipv4Prefix, Ipv6Prefix, MacAddress, ByteMatch, parse_ethertype};

/// Represents a simulated packet with all match-field values
#[derive(Debug, Clone, Default)]
pub struct SimPacket {
    pub ethertype: Option<u16>,
    pub dst_mac: Option<String>,
    pub src_mac: Option<String>,
    pub vlan_id: Option<u16>,
    pub vlan_pcp: Option<u8>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub ip_protocol: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub vxlan_vni: Option<u32>,
    pub src_ipv6: Option<String>,
    pub dst_ipv6: Option<String>,
    pub ipv6_next_header: Option<u8>,
    pub raw_bytes: Option<Vec<u8>>,
    pub gtp_teid: Option<u32>,
    pub mpls_label: Option<u32>,
    pub mpls_tc: Option<u8>,
    pub mpls_bos: Option<bool>,
    pub igmp_type: Option<u8>,
    pub mld_type: Option<u8>,
    pub ip_dscp: Option<u8>,
    pub ip_ecn: Option<u8>,
    pub ipv6_dscp: Option<u8>,
    pub ipv6_ecn: Option<u8>,
    pub tcp_flags: Option<u8>,
    pub tcp_flags_mask: Option<u8>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub icmpv6_type: Option<u8>,
    pub icmpv6_code: Option<u8>,
    pub arp_opcode: Option<u16>,
    pub arp_spa: Option<String>,
    pub arp_tpa: Option<String>,
    pub ipv6_hop_limit: Option<u8>,
    pub ipv6_flow_label: Option<u32>,
    pub outer_vlan_id: Option<u16>,
    pub outer_vlan_pcp: Option<u8>,
    pub ip_dont_fragment: Option<bool>,
    pub ip_more_fragments: Option<bool>,
    pub ip_frag_offset: Option<u16>,
    pub gre_protocol: Option<u16>,
    pub gre_key: Option<u32>,
    pub oam_level: Option<u8>,
    pub oam_opcode: Option<u8>,
    pub nsh_spi: Option<u32>,
    pub nsh_si: Option<u8>,
    pub nsh_next_protocol: Option<u8>,
    pub conntrack_state: Option<String>,
    pub geneve_vni: Option<u32>,
    pub ip_ttl: Option<u8>,
    pub frame_len: Option<u16>,
    pub ptp_message_type: Option<u8>,
    pub ptp_domain: Option<u8>,
    pub ptp_version: Option<u8>,
}

/// Rewrite actions that would be applied to a passed packet
#[derive(Debug, Clone, Default)]
pub struct SimRewrite {
    pub set_dst_mac: Option<String>,
    pub set_src_mac: Option<String>,
    pub set_vlan_id: Option<u16>,
    pub set_ttl: Option<u8>,
    pub dec_ttl: bool,
    pub set_src_ip: Option<String>,
    pub set_dst_ip: Option<String>,
    pub set_dscp: Option<u8>,
    pub set_src_port: Option<u16>,
    pub set_dst_port: Option<u16>,
    pub dec_hop_limit: bool,
    pub set_hop_limit: Option<u8>,
    pub set_ecn: Option<u8>,
    pub set_vlan_pcp: Option<u8>,
    pub set_outer_vlan_id: Option<u16>,
}

impl SimRewrite {
    pub fn is_empty(&self) -> bool {
        self.set_dst_mac.is_none()
            && self.set_src_mac.is_none()
            && self.set_vlan_id.is_none()
            && self.set_ttl.is_none()
            && !self.dec_ttl
            && self.set_src_ip.is_none()
            && self.set_dst_ip.is_none()
            && self.set_dscp.is_none()
            && self.set_src_port.is_none()
            && self.set_dst_port.is_none()
            && !self.dec_hop_limit
            && self.set_hop_limit.is_none()
            && self.set_ecn.is_none()
            && self.set_vlan_pcp.is_none()
            && self.set_outer_vlan_id.is_none()
    }
}

/// Result of simulating a packet against the rule set
#[derive(Debug, Clone)]
pub struct SimResult {
    pub rule_name: Option<String>,
    pub action: Action,
    pub is_default: bool,
    pub fields: Vec<FieldMatch>,
    pub rewrite: Option<SimRewrite>,
    pub mirror_port: Option<u8>,
    pub redirect_port: Option<u8>,
}

/// Per-field match breakdown
#[derive(Debug, Clone)]
pub struct FieldMatch {
    pub field: String,
    pub rule_value: String,
    pub packet_value: String,
    pub matches: bool,
}

/// Parse a packet specification string like "ethertype=0x0800,src_ip=10.0.0.1,dst_port=80"
pub fn parse_packet_spec(spec: &str) -> Result<SimPacket> {
    let mut pkt = SimPacket::default();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Invalid field spec '{}': expected key=value", part))?;
        let key = key.trim();
        let value = value.trim();

        match key {
            "ethertype" => {
                pkt.ethertype = Some(parse_ethertype(value)?);
            }
            "dst_mac" => {
                MacAddress::parse(value)?; // validate
                pkt.dst_mac = Some(value.to_string());
            }
            "src_mac" => {
                MacAddress::parse(value)?; // validate
                pkt.src_mac = Some(value.to_string());
            }
            "vlan_id" => {
                pkt.vlan_id = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad vlan_id '{}': {}", value, e))?);
            }
            "vlan_pcp" => {
                pkt.vlan_pcp = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad vlan_pcp '{}': {}", value, e))?);
            }
            "src_ip" => {
                pkt.src_ip = Some(value.to_string());
            }
            "dst_ip" => {
                pkt.dst_ip = Some(value.to_string());
            }
            "ip_protocol" => {
                pkt.ip_protocol = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad ip_protocol '{}': {}", value, e))?);
            }
            "src_port" => {
                pkt.src_port = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad src_port '{}': {}", value, e))?);
            }
            "dst_port" => {
                pkt.dst_port = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad dst_port '{}': {}", value, e))?);
            }
            "vxlan_vni" => {
                pkt.vxlan_vni = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad vxlan_vni '{}': {}", value, e))?);
            }
            "src_ipv6" => {
                Ipv6Prefix::parse(value)?; // validate
                pkt.src_ipv6 = Some(value.to_string());
            }
            "dst_ipv6" => {
                Ipv6Prefix::parse(value)?; // validate
                pkt.dst_ipv6 = Some(value.to_string());
            }
            "ipv6_next_header" => {
                pkt.ipv6_next_header = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad ipv6_next_header '{}': {}", value, e))?);
            }
            "raw_bytes" => {
                pkt.raw_bytes = Some(parse_hex_bytes(value)?);
            }
            "gtp_teid" => {
                pkt.gtp_teid = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad gtp_teid '{}': {}", value, e))?);
            }
            "mpls_label" => {
                pkt.mpls_label = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad mpls_label '{}': {}", value, e))?);
            }
            "mpls_tc" => {
                pkt.mpls_tc = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad mpls_tc '{}': {}", value, e))?);
            }
            "mpls_bos" => {
                pkt.mpls_bos = Some(value == "true" || value == "1");
            }
            "igmp_type" => {
                pkt.igmp_type = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad igmp_type '{}': {}", value, e))?);
            }
            "mld_type" => {
                pkt.mld_type = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad mld_type '{}': {}", value, e))?);
            }
            "ip_dscp" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad ip_dscp '{}': {}", value, e))?;
                if v > 63 { bail!("ip_dscp must be 0-63, got {}", v); }
                pkt.ip_dscp = Some(v);
            }
            "ip_ecn" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad ip_ecn '{}': {}", value, e))?;
                if v > 3 { bail!("ip_ecn must be 0-3, got {}", v); }
                pkt.ip_ecn = Some(v);
            }
            "ipv6_dscp" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad ipv6_dscp '{}': {}", value, e))?;
                if v > 63 { bail!("ipv6_dscp must be 0-63, got {}", v); }
                pkt.ipv6_dscp = Some(v);
            }
            "ipv6_ecn" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad ipv6_ecn '{}': {}", value, e))?;
                if v > 3 { bail!("ipv6_ecn must be 0-3, got {}", v); }
                pkt.ipv6_ecn = Some(v);
            }
            "tcp_flags" => {
                let v: u8 = if value.starts_with("0x") || value.starts_with("0X") {
                    u8::from_str_radix(value.trim_start_matches("0x").trim_start_matches("0X"), 16)
                        .map_err(|e| anyhow::anyhow!("Bad tcp_flags '{}': {}", value, e))?
                } else {
                    value.parse().map_err(|e| anyhow::anyhow!("Bad tcp_flags '{}': {}", value, e))?
                };
                pkt.tcp_flags = Some(v);
            }
            "tcp_flags_mask" => {
                let v: u8 = if value.starts_with("0x") || value.starts_with("0X") {
                    u8::from_str_radix(value.trim_start_matches("0x").trim_start_matches("0X"), 16)
                        .map_err(|e| anyhow::anyhow!("Bad tcp_flags_mask '{}': {}", value, e))?
                } else {
                    value.parse().map_err(|e| anyhow::anyhow!("Bad tcp_flags_mask '{}': {}", value, e))?
                };
                pkt.tcp_flags_mask = Some(v);
            }
            "icmp_type" => {
                pkt.icmp_type = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad icmp_type '{}': {}", value, e))?);
            }
            "icmp_code" => {
                pkt.icmp_code = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad icmp_code '{}': {}", value, e))?);
            }
            "icmpv6_type" => {
                pkt.icmpv6_type = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad icmpv6_type '{}': {}", value, e))?);
            }
            "icmpv6_code" => {
                pkt.icmpv6_code = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad icmpv6_code '{}': {}", value, e))?);
            }
            "arp_opcode" => {
                pkt.arp_opcode = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad arp_opcode '{}': {}", value, e))?);
            }
            "arp_spa" => {
                Ipv4Prefix::parse(value)?; // validate
                pkt.arp_spa = Some(value.to_string());
            }
            "arp_tpa" => {
                Ipv4Prefix::parse(value)?; // validate
                pkt.arp_tpa = Some(value.to_string());
            }
            "ipv6_hop_limit" => {
                pkt.ipv6_hop_limit = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad ipv6_hop_limit '{}': {}", value, e))?);
            }
            "ipv6_flow_label" => {
                let v: u32 = value.parse().map_err(|e| anyhow::anyhow!("Bad ipv6_flow_label '{}': {}", value, e))?;
                if v > 0xFFFFF { bail!("ipv6_flow_label must be 0-1048575, got {}", v); }
                pkt.ipv6_flow_label = Some(v);
            }
            "outer_vlan_id" => {
                pkt.outer_vlan_id = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad outer_vlan_id '{}': {}", value, e))?);
            }
            "outer_vlan_pcp" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad outer_vlan_pcp '{}': {}", value, e))?;
                if v > 7 { bail!("outer_vlan_pcp must be 0-7, got {}", v); }
                pkt.outer_vlan_pcp = Some(v);
            }
            "ip_dont_fragment" => {
                pkt.ip_dont_fragment = Some(value == "true" || value == "1");
            }
            "ip_more_fragments" => {
                pkt.ip_more_fragments = Some(value == "true" || value == "1");
            }
            "ip_frag_offset" => {
                let v: u16 = value.parse().map_err(|e| anyhow::anyhow!("Bad ip_frag_offset '{}': {}", value, e))?;
                if v > 8191 { bail!("ip_frag_offset must be 0-8191, got {}", v); }
                pkt.ip_frag_offset = Some(v);
            }
            "gre_protocol" => {
                let v = if value.starts_with("0x") || value.starts_with("0X") {
                    u16::from_str_radix(value.trim_start_matches("0x").trim_start_matches("0X"), 16)
                        .map_err(|e| anyhow::anyhow!("Bad gre_protocol '{}': {}", value, e))?
                } else {
                    value.parse().map_err(|e| anyhow::anyhow!("Bad gre_protocol '{}': {}", value, e))?
                };
                pkt.gre_protocol = Some(v);
            }
            "gre_key" => {
                let v: u32 = value.parse().map_err(|e| anyhow::anyhow!("Bad gre_key '{}': {}", value, e))?;
                pkt.gre_key = Some(v);
            }
            "oam_level" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad oam_level '{}': {}", value, e))?;
                pkt.oam_level = Some(v);
            }
            "oam_opcode" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad oam_opcode '{}': {}", value, e))?;
                pkt.oam_opcode = Some(v);
            }
            "nsh_spi" => {
                let v: u32 = value.parse().map_err(|e| anyhow::anyhow!("Bad nsh_spi '{}': {}", value, e))?;
                pkt.nsh_spi = Some(v);
            }
            "nsh_si" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad nsh_si '{}': {}", value, e))?;
                pkt.nsh_si = Some(v);
            }
            "nsh_next_protocol" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad nsh_next_protocol '{}': {}", value, e))?;
                pkt.nsh_next_protocol = Some(v);
            }
            "conntrack_state" => {
                pkt.conntrack_state = Some(value.to_string());
            }
            "geneve_vni" => {
                pkt.geneve_vni = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad geneve_vni '{}': {}", value, e))?);
            }
            "ip_ttl" => {
                pkt.ip_ttl = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad ip_ttl '{}': {}", value, e))?);
            }
            "frame_len" => {
                pkt.frame_len = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad frame_len '{}': {}", value, e))?);
            }
            "ptp_message_type" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad ptp_message_type '{}': {}", value, e))?;
                if v > 15 { bail!("ptp_message_type must be 0-15, got {}", v); }
                pkt.ptp_message_type = Some(v);
            }
            "ptp_domain" => {
                pkt.ptp_domain = Some(value.parse().map_err(|e| anyhow::anyhow!("Bad ptp_domain '{}': {}", value, e))?);
            }
            "ptp_version" => {
                let v: u8 = value.parse().map_err(|e| anyhow::anyhow!("Bad ptp_version '{}': {}", value, e))?;
                if v > 15 { bail!("ptp_version must be 0-15, got {}", v); }
                pkt.ptp_version = Some(v);
            }
            _ => bail!("Unknown packet field '{}'", key),
        }
    }

    Ok(pkt)
}

/// Build SimRewrite from a rule's RewriteAction
fn build_sim_rewrite(rule: &crate::model::StatelessRule) -> Option<SimRewrite> {
    let rw = rule.rewrite.as_ref()?;
    if rw.is_empty() {
        return None;
    }
    Some(SimRewrite {
        set_dst_mac: rw.set_dst_mac.clone(),
        set_src_mac: rw.set_src_mac.clone(),
        set_vlan_id: rw.set_vlan_id,
        set_ttl: rw.set_ttl,
        dec_ttl: rw.dec_ttl == Some(true),
        set_src_ip: rw.set_src_ip.clone(),
        set_dst_ip: rw.set_dst_ip.clone(),
        set_dscp: rw.set_dscp,
        set_src_port: rw.set_src_port,
        set_dst_port: rw.set_dst_port,
        dec_hop_limit: rw.dec_hop_limit == Some(true),
        set_hop_limit: rw.set_hop_limit,
        set_ecn: rw.set_ecn,
        set_vlan_pcp: rw.set_vlan_pcp,
        set_outer_vlan_id: rw.set_outer_vlan_id,
    })
}

/// Simulate a single stage's rules against a packet
fn simulate_stage(rules: &[crate::model::StatelessRule], default_action: &Action, packet: &SimPacket) -> SimResult {
    let mut sorted = rules.to_vec();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    for rule in &sorted {
        if rule.is_stateful() {
            continue;
        }
        let (matches, fields) = match_criteria_against_packet(&rule.match_criteria, packet);
        if matches {
            let rewrite = if rule.action() == Action::Pass {
                build_sim_rewrite(rule)
            } else {
                None
            };
            return SimResult {
                rule_name: Some(rule.name.clone()),
                action: rule.action(),
                is_default: false,
                fields,
                rewrite,
                mirror_port: rule.mirror_port,
                redirect_port: rule.redirect_port,
            };
        }
    }
    SimResult {
        rule_name: None,
        action: default_action.clone(),
        is_default: true,
        fields: Vec::new(),
        rewrite: None,
        mirror_port: None,
        redirect_port: None,
    }
}

/// Simulate a packet against the filter configuration, returning the match result.
/// For pipeline configs (tables:), evaluates stages sequentially — packet passes
/// only if ALL stages pass (AND semantics, matching RTL pipeline_top.v).
pub fn simulate(config: &FilterConfig, packet: &SimPacket) -> SimResult {
    if config.is_pipeline() {
        return simulate_pipeline(config, packet);
    }

    simulate_stage(&config.pacgate.rules, &config.pacgate.defaults.action, packet)
}

/// Simulate a multi-stage pipeline: each stage evaluated sequentially.
/// If any stage drops, final result is drop. Last stage's match info used for result.
fn simulate_pipeline(config: &FilterConfig, packet: &SimPacket) -> SimResult {
    let tables = config.pacgate.tables.as_ref().unwrap();
    let mut last_result = SimResult {
        rule_name: None,
        action: Action::Pass,
        is_default: true,
        fields: Vec::new(),
        rewrite: None,
        mirror_port: None,
        redirect_port: None,
    };

    for stage in tables {
        let stage_result = simulate_stage(&stage.rules, &stage.default_action, packet);
        if stage_result.action == Action::Drop {
            // Any stage dropping means final drop — return immediately
            return stage_result;
        }
        last_result = stage_result;
    }

    last_result
}

/// Rate-limit state for software simulation (token-bucket per rule)
pub struct SimRateLimitState {
    pub tokens: HashMap<String, f64>,
    pub last_time: HashMap<String, f64>,
}

impl SimRateLimitState {
    /// Initialize rate-limit state from a filter config, setting tokens to burst for each rate-limited rule
    pub fn new(config: &FilterConfig) -> Self {
        let mut tokens = HashMap::new();
        let mut last_time = HashMap::new();
        for rule in config.all_rules() {
            if let Some(ref rl) = rule.rate_limit {
                tokens.insert(rule.name.clone(), rl.burst as f64);
                last_time.insert(rule.name.clone(), 0.0);
            }
        }
        SimRateLimitState { tokens, last_time }
    }

    /// Refill tokens for a rule based on elapsed time
    pub fn refill(&mut self, rule_name: &str, pps: u32, burst: u32, elapsed: f64) {
        if let Some(tok) = self.tokens.get_mut(rule_name) {
            *tok += pps as f64 * elapsed;
            if *tok > burst as f64 {
                *tok = burst as f64;
            }
        }
    }

    /// Try to consume one token; returns true if successful
    pub fn try_consume(&mut self, rule_name: &str) -> bool {
        if let Some(tok) = self.tokens.get_mut(rule_name) {
            if *tok >= 1.0 {
                *tok -= 1.0;
                return true;
            }
        }
        false
    }
}

/// Simulate a packet with rate-limit enforcement
pub fn simulate_with_rate_limit(
    config: &FilterConfig,
    packet: &SimPacket,
    rate_state: &mut SimRateLimitState,
    elapsed_secs: f64,
) -> SimResult {
    let result = simulate(config, packet);

    // If no rule matched (default action), rate-limit doesn't apply
    if result.is_default {
        return result;
    }

    // Check if the matched rule has rate_limit
    if let Some(ref rule_name) = result.rule_name {
        let all_rules = config.all_rules();
        let rule = all_rules.into_iter().find(|r| &r.name == rule_name);
        if let Some(rule) = rule {
            if let Some(ref rl) = rule.rate_limit {
                // Refill tokens based on elapsed time
                rate_state.refill(rule_name, rl.pps, rl.burst, elapsed_secs);

                // Try to consume a token
                if !rate_state.try_consume(rule_name) {
                    // Rate limited — return default action
                    return SimResult {
                        rule_name: Some("rate_limited".to_string()),
                        action: config.pacgate.defaults.action.clone(),
                        is_default: true,
                        fields: result.fields,
                        rewrite: None,
                        mirror_port: None,
                        redirect_port: None,
                    };
                }
            }
        }
    }

    result
}

/// TCP connection state for enhanced stateful tracking
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    New,          // SYN seen (or first packet of non-TCP flow)
    Established,  // Bidirectional traffic seen (SYN-ACK or return traffic)
    FinWait,      // FIN seen
    Closed,       // Both sides FIN'd or RST
}

impl TcpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::New => "new",
            TcpState::Established => "established",
            TcpState::FinWait => "established", // still considered established until fully closed
            TcpState::Closed => "new", // closed flows revert to "new" state
        }
    }

    /// Advance TCP state based on observed TCP flags
    pub fn advance(self, tcp_flags: Option<u8>, is_reverse: bool) -> TcpState {
        let flags = tcp_flags.unwrap_or(0);
        let syn = flags & 0x02 != 0;
        let ack = flags & 0x10 != 0;
        let fin = flags & 0x01 != 0;
        let rst = flags & 0x04 != 0;

        if rst {
            return TcpState::Closed;
        }

        match self {
            TcpState::New => {
                if is_reverse && (syn && ack) {
                    TcpState::Established // SYN-ACK from server
                } else if is_reverse && ack {
                    TcpState::Established // ACK from either direction
                } else {
                    TcpState::New
                }
            }
            TcpState::Established => {
                if fin {
                    TcpState::FinWait
                } else {
                    TcpState::Established
                }
            }
            TcpState::FinWait => {
                if fin || (ack && is_reverse) {
                    TcpState::Closed
                } else {
                    TcpState::FinWait
                }
            }
            TcpState::Closed => TcpState::Closed,
        }
    }
}

/// Per-flow entry with counters and TCP state
#[derive(Debug, Clone)]
pub struct FlowEntry {
    pub rule_name: String,
    pub timestamp: u64,
    pub tcp_state: TcpState,
    pub pkt_count: u64,
    pub byte_count: u64,
}

/// Connection tracking table for software simulation with TCP state tracking
pub struct SimConntrackTable {
    pub flows: HashMap<u64, FlowEntry>,
    pub timeout: u64,
}

impl SimConntrackTable {
    pub fn new(timeout: u64) -> Self {
        SimConntrackTable {
            flows: HashMap::new(),
            timeout,
        }
    }

    /// Hash a 5-tuple (src_ip, dst_ip, protocol, src_port, dst_port) into a u64
    pub fn hash_5tuple(packet: &SimPacket) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        packet.src_ip.hash(&mut hasher);
        packet.dst_ip.hash(&mut hasher);
        packet.ip_protocol.hash(&mut hasher);
        packet.src_port.hash(&mut hasher);
        packet.dst_port.hash(&mut hasher);
        hasher.finish()
    }

    /// Hash the reverse 5-tuple (swap src/dst)
    fn hash_reverse(packet: &SimPacket) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        packet.dst_ip.hash(&mut hasher);
        packet.src_ip.hash(&mut hasher);
        packet.ip_protocol.hash(&mut hasher);
        packet.dst_port.hash(&mut hasher);
        packet.src_port.hash(&mut hasher);
        hasher.finish()
    }

    /// Insert a flow entry with initial TCP state
    pub fn insert_flow(&mut self, packet: &SimPacket, rule_name: &str, timestamp: u64) {
        let hash = Self::hash_5tuple(packet);
        self.flows.insert(hash, FlowEntry {
            rule_name: rule_name.to_string(),
            timestamp,
            tcp_state: TcpState::New,
            pkt_count: 1,
            byte_count: 0,
        });
    }

    /// Check if the reverse flow exists and hasn't timed out
    pub fn check_return(&self, packet: &SimPacket, timestamp: u64) -> Option<String> {
        let rev_hash = Self::hash_reverse(packet);
        if let Some(entry) = self.flows.get(&rev_hash) {
            if timestamp - entry.timestamp <= self.timeout && entry.tcp_state != TcpState::Closed {
                return Some(entry.rule_name.clone());
            }
        }
        None
    }

    /// Determine the conntrack state for a packet (new vs established)
    pub fn get_state(&self, packet: &SimPacket, timestamp: u64) -> &'static str {
        let fwd_hash = Self::hash_5tuple(packet);
        let rev_hash = Self::hash_reverse(packet);

        // Check forward flow
        if let Some(entry) = self.flows.get(&fwd_hash) {
            if timestamp - entry.timestamp <= self.timeout && entry.tcp_state != TcpState::Closed {
                return entry.tcp_state.as_str();
            }
        }

        // Check reverse flow (return traffic → established)
        if let Some(entry) = self.flows.get(&rev_hash) {
            if timestamp - entry.timestamp <= self.timeout && entry.tcp_state != TcpState::Closed {
                return "established";
            }
        }

        "new"
    }

    /// Update TCP state for an existing flow based on observed flags
    pub fn update_tcp_state(&mut self, packet: &SimPacket, timestamp: u64) {
        let fwd_hash = Self::hash_5tuple(packet);
        let rev_hash = Self::hash_reverse(packet);

        // Check if this is a forward flow packet
        if let Some(entry) = self.flows.get_mut(&fwd_hash) {
            entry.timestamp = timestamp;
            entry.tcp_state = entry.tcp_state.advance(packet.tcp_flags, false);
            entry.pkt_count += 1;
            return;
        }

        // Check if this is a reverse flow packet
        if let Some(entry) = self.flows.get_mut(&rev_hash) {
            entry.timestamp = timestamp;
            entry.tcp_state = entry.tcp_state.advance(packet.tcp_flags, true);
            entry.pkt_count += 1;
        }
    }

    /// Increment flow counters for a matched flow (forward direction)
    pub fn increment_counters(&mut self, packet: &SimPacket, byte_len: u64) {
        let fwd_hash = Self::hash_5tuple(packet);
        if let Some(entry) = self.flows.get_mut(&fwd_hash) {
            entry.pkt_count += 1;
            entry.byte_count += byte_len;
            return;
        }
        let rev_hash = Self::hash_reverse(packet);
        if let Some(entry) = self.flows.get_mut(&rev_hash) {
            entry.pkt_count += 1;
            entry.byte_count += byte_len;
        }
    }

    /// Get flow statistics for all active flows
    pub fn flow_stats(&self, timestamp: u64) -> Vec<FlowStats> {
        self.flows.iter()
            .filter(|(_, entry)| {
                timestamp - entry.timestamp <= self.timeout && entry.tcp_state != TcpState::Closed
            })
            .map(|(hash, entry)| FlowStats {
                flow_hash: *hash,
                rule_name: entry.rule_name.clone(),
                tcp_state: entry.tcp_state,
                pkt_count: entry.pkt_count,
                byte_count: entry.byte_count,
            })
            .collect()
    }
}

/// Flow statistics summary for export
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub flow_hash: u64,
    pub rule_name: String,
    pub tcp_state: TcpState,
    pub pkt_count: u64,
    pub byte_count: u64,
}

/// Full stateful simulation combining rate-limit + connection tracking
pub fn simulate_stateful(
    config: &FilterConfig,
    packet: &SimPacket,
    rate_state: &mut SimRateLimitState,
    conntrack: &mut SimConntrackTable,
    elapsed_secs: f64,
    timestamp: u64,
) -> SimResult {
    // Determine conntrack state and inject it into the packet for rule matching
    let ct_state = conntrack.get_state(packet, timestamp);
    let mut pkt_with_state = packet.clone();
    pkt_with_state.conntrack_state = Some(ct_state.to_string());

    // First check if this is a return flow in conntrack
    if let Some(rule_name) = conntrack.check_return(packet, timestamp) {
        // Update TCP state for return traffic
        conntrack.update_tcp_state(packet, timestamp);
        return SimResult {
            rule_name: Some(rule_name),
            action: Action::Pass,
            is_default: false,
            fields: Vec::new(),
            rewrite: None,
            mirror_port: None,
            redirect_port: None,
        };
    }

    // Run normal simulation with rate limiting, using state-annotated packet
    let result = simulate_with_rate_limit(config, &pkt_with_state, rate_state, elapsed_secs);

    // If matched a rule (not default), add to conntrack
    if !result.is_default {
        if let Some(ref rule_name) = result.rule_name {
            if result.action == Action::Pass {
                conntrack.insert_flow(packet, rule_name, timestamp);
            }
        }
    }

    result
}

/// Evaluate match criteria against a packet, returning (overall_match, per-field breakdown)
pub fn match_criteria_against_packet(mc: &MatchCriteria, pkt: &SimPacket) -> (bool, Vec<FieldMatch>) {
    let mut fields = Vec::new();
    let mut all_match = true;

    // Ethertype
    if let Some(ref et_str) = mc.ethertype {
        if let Ok(rule_et) = parse_ethertype(et_str) {
            let pkt_val = pkt.ethertype.map(|v| format!("0x{:04x}", v)).unwrap_or_else(|| "none".to_string());
            let matches = pkt.ethertype.map(|v| v == rule_et).unwrap_or(false);
            fields.push(FieldMatch {
                field: "ethertype".to_string(),
                rule_value: format!("0x{:04x}", rule_et),
                packet_value: pkt_val,
                matches,
            });
            if !matches { all_match = false; }
        }
    }

    // dst_mac
    if let Some(ref rule_mac) = mc.dst_mac {
        let pkt_val = pkt.dst_mac.as_deref().unwrap_or("none");
        let matches = pkt.dst_mac.as_ref().map(|p| mac_matches_pattern(rule_mac, p)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "dst_mac".to_string(),
            rule_value: rule_mac.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // src_mac
    if let Some(ref rule_mac) = mc.src_mac {
        let pkt_val = pkt.src_mac.as_deref().unwrap_or("none");
        let matches = pkt.src_mac.as_ref().map(|p| mac_matches_pattern(rule_mac, p)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "src_mac".to_string(),
            rule_value: rule_mac.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // vlan_id
    if let Some(rule_vid) = mc.vlan_id {
        let pkt_val = pkt.vlan_id.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.vlan_id.map(|v| v == rule_vid).unwrap_or(false);
        fields.push(FieldMatch {
            field: "vlan_id".to_string(),
            rule_value: rule_vid.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // vlan_pcp
    if let Some(rule_pcp) = mc.vlan_pcp {
        let pkt_val = pkt.vlan_pcp.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.vlan_pcp.map(|v| v == rule_pcp).unwrap_or(false);
        fields.push(FieldMatch {
            field: "vlan_pcp".to_string(),
            rule_value: rule_pcp.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // src_ip (CIDR matching)
    if let Some(ref rule_ip) = mc.src_ip {
        let pkt_val = pkt.src_ip.as_deref().unwrap_or("none");
        let matches = pkt.src_ip.as_ref().map(|p| ipv4_matches_cidr(p, rule_ip)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "src_ip".to_string(),
            rule_value: rule_ip.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // dst_ip (CIDR matching)
    if let Some(ref rule_ip) = mc.dst_ip {
        let pkt_val = pkt.dst_ip.as_deref().unwrap_or("none");
        let matches = pkt.dst_ip.as_ref().map(|p| ipv4_matches_cidr(p, rule_ip)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "dst_ip".to_string(),
            rule_value: rule_ip.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // ip_protocol
    if let Some(rule_proto) = mc.ip_protocol {
        let pkt_val = pkt.ip_protocol.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ip_protocol.map(|v| v == rule_proto).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ip_protocol".to_string(),
            rule_value: rule_proto.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // src_port
    if let Some(ref rule_pm) = mc.src_port {
        let pkt_val = pkt.src_port.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.src_port.map(|v| port_matches(v, rule_pm)).unwrap_or(false);
        let rule_str = match rule_pm {
            PortMatch::Exact(p) => p.to_string(),
            PortMatch::Range { range } => format!("{}-{}", range[0], range[1]),
        };
        fields.push(FieldMatch {
            field: "src_port".to_string(),
            rule_value: rule_str,
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // dst_port
    if let Some(ref rule_pm) = mc.dst_port {
        let pkt_val = pkt.dst_port.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.dst_port.map(|v| port_matches(v, rule_pm)).unwrap_or(false);
        let rule_str = match rule_pm {
            PortMatch::Exact(p) => p.to_string(),
            PortMatch::Range { range } => format!("{}-{}", range[0], range[1]),
        };
        fields.push(FieldMatch {
            field: "dst_port".to_string(),
            rule_value: rule_str,
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // vxlan_vni
    if let Some(rule_vni) = mc.vxlan_vni {
        let pkt_val = pkt.vxlan_vni.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.vxlan_vni.map(|v| v == rule_vni).unwrap_or(false);
        fields.push(FieldMatch {
            field: "vxlan_vni".to_string(),
            rule_value: rule_vni.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // src_ipv6 (CIDR matching)
    if let Some(ref rule_ip) = mc.src_ipv6 {
        let pkt_val = pkt.src_ipv6.as_deref().unwrap_or("none");
        let matches = pkt.src_ipv6.as_ref().map(|p| ipv6_matches_cidr(p, rule_ip)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "src_ipv6".to_string(),
            rule_value: rule_ip.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // dst_ipv6 (CIDR matching)
    if let Some(ref rule_ip) = mc.dst_ipv6 {
        let pkt_val = pkt.dst_ipv6.as_deref().unwrap_or("none");
        let matches = pkt.dst_ipv6.as_ref().map(|p| ipv6_matches_cidr(p, rule_ip)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "dst_ipv6".to_string(),
            rule_value: rule_ip.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // ipv6_next_header
    if let Some(rule_nh) = mc.ipv6_next_header {
        let pkt_val = pkt.ipv6_next_header.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ipv6_next_header.map(|v| v == rule_nh).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ipv6_next_header".to_string(),
            rule_value: rule_nh.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // GTP TEID
    if let Some(teid) = mc.gtp_teid {
        let pkt_val = pkt.gtp_teid.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.gtp_teid.map(|v| v == teid).unwrap_or(false);
        fields.push(FieldMatch {
            field: "gtp_teid".to_string(),
            rule_value: teid.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // MPLS label
    if let Some(label) = mc.mpls_label {
        let pkt_val = pkt.mpls_label.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.mpls_label.map(|v| v == label).unwrap_or(false);
        fields.push(FieldMatch {
            field: "mpls_label".to_string(),
            rule_value: label.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // MPLS TC
    if let Some(tc) = mc.mpls_tc {
        let pkt_val = pkt.mpls_tc.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.mpls_tc.map(|v| v == tc).unwrap_or(false);
        fields.push(FieldMatch {
            field: "mpls_tc".to_string(),
            rule_value: tc.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // MPLS BOS
    if let Some(bos) = mc.mpls_bos {
        let pkt_val = pkt.mpls_bos.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.mpls_bos.map(|v| v == bos).unwrap_or(false);
        fields.push(FieldMatch {
            field: "mpls_bos".to_string(),
            rule_value: bos.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // IGMP type
    if let Some(igmp) = mc.igmp_type {
        let pkt_val = pkt.igmp_type.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.igmp_type.map(|v| v == igmp).unwrap_or(false);
        fields.push(FieldMatch {
            field: "igmp_type".to_string(),
            rule_value: igmp.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // MLD type
    if let Some(mld) = mc.mld_type {
        let pkt_val = pkt.mld_type.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.mld_type.map(|v| v == mld).unwrap_or(false);
        fields.push(FieldMatch {
            field: "mld_type".to_string(),
            rule_value: mld.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // DSCP (QoS)
    if let Some(dscp) = mc.ip_dscp {
        let pkt_val = pkt.ip_dscp.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.ip_dscp.map(|v| v == dscp).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ip_dscp".to_string(),
            rule_value: dscp.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ECN (QoS)
    if let Some(ecn) = mc.ip_ecn {
        let pkt_val = pkt.ip_ecn.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.ip_ecn.map(|v| v == ecn).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ip_ecn".to_string(),
            rule_value: ecn.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // IPv6 DSCP
    if let Some(dscp) = mc.ipv6_dscp {
        let pkt_val = pkt.ipv6_dscp.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.ipv6_dscp.map(|v| v == dscp).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ipv6_dscp".to_string(),
            rule_value: dscp.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // IPv6 ECN
    if let Some(ecn) = mc.ipv6_ecn {
        let pkt_val = pkt.ipv6_ecn.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.ipv6_ecn.map(|v| v == ecn).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ipv6_ecn".to_string(),
            rule_value: ecn.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // TCP flags (mask-aware comparison)
    if let Some(rule_flags) = mc.tcp_flags {
        let mask = mc.tcp_flags_mask.unwrap_or(0xFF);
        let pkt_val = pkt.tcp_flags.map(|v| format!("0x{:02x}", v)).unwrap_or("none".to_string());
        let matches = pkt.tcp_flags.map(|v| (v & mask) == (rule_flags & mask)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "tcp_flags".to_string(),
            rule_value: format!("0x{:02x}&0x{:02x}", rule_flags, mask),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ICMP type
    if let Some(rule_type) = mc.icmp_type {
        let pkt_val = pkt.icmp_type.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.icmp_type.map(|v| v == rule_type).unwrap_or(false);
        fields.push(FieldMatch {
            field: "icmp_type".to_string(),
            rule_value: rule_type.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ICMP code
    if let Some(rule_code) = mc.icmp_code {
        let pkt_val = pkt.icmp_code.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.icmp_code.map(|v| v == rule_code).unwrap_or(false);
        fields.push(FieldMatch {
            field: "icmp_code".to_string(),
            rule_value: rule_code.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ICMPv6 type
    if let Some(rule_type) = mc.icmpv6_type {
        let pkt_val = pkt.icmpv6_type.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.icmpv6_type.map(|v| v == rule_type).unwrap_or(false);
        fields.push(FieldMatch {
            field: "icmpv6_type".to_string(),
            rule_value: rule_type.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ICMPv6 code
    if let Some(rule_code) = mc.icmpv6_code {
        let pkt_val = pkt.icmpv6_code.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.icmpv6_code.map(|v| v == rule_code).unwrap_or(false);
        fields.push(FieldMatch {
            field: "icmpv6_code".to_string(),
            rule_value: rule_code.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ARP opcode
    if let Some(rule_op) = mc.arp_opcode {
        let pkt_val = pkt.arp_opcode.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.arp_opcode.map(|v| v == rule_op).unwrap_or(false);
        fields.push(FieldMatch {
            field: "arp_opcode".to_string(),
            rule_value: rule_op.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ARP SPA
    if let Some(ref rule_spa) = mc.arp_spa {
        let pkt_val = pkt.arp_spa.as_deref().unwrap_or("none");
        let matches = pkt.arp_spa.as_ref().map(|p| ipv4_matches_cidr(p, rule_spa)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "arp_spa".to_string(),
            rule_value: rule_spa.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // ARP TPA
    if let Some(ref rule_tpa) = mc.arp_tpa {
        let pkt_val = pkt.arp_tpa.as_deref().unwrap_or("none");
        let matches = pkt.arp_tpa.as_ref().map(|p| ipv4_matches_cidr(p, rule_tpa)).unwrap_or(false);
        fields.push(FieldMatch {
            field: "arp_tpa".to_string(),
            rule_value: rule_tpa.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // IPv6 hop limit
    if let Some(rule_hl) = mc.ipv6_hop_limit {
        let pkt_val = pkt.ipv6_hop_limit.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.ipv6_hop_limit.map(|v| v == rule_hl).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ipv6_hop_limit".to_string(),
            rule_value: rule_hl.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // IPv6 flow label
    if let Some(rule_fl) = mc.ipv6_flow_label {
        let pkt_val = pkt.ipv6_flow_label.map(|v| v.to_string()).unwrap_or("none".to_string());
        let matches = pkt.ipv6_flow_label.map(|v| v == rule_fl).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ipv6_flow_label".to_string(),
            rule_value: rule_fl.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // outer_vlan_id (QinQ)
    if let Some(rule_vid) = mc.outer_vlan_id {
        let pkt_val = pkt.outer_vlan_id.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.outer_vlan_id.map(|v| v == rule_vid).unwrap_or(false);
        fields.push(FieldMatch {
            field: "outer_vlan_id".to_string(),
            rule_value: rule_vid.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // outer_vlan_pcp (QinQ)
    if let Some(rule_pcp) = mc.outer_vlan_pcp {
        let pkt_val = pkt.outer_vlan_pcp.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.outer_vlan_pcp.map(|v| v == rule_pcp).unwrap_or(false);
        fields.push(FieldMatch {
            field: "outer_vlan_pcp".to_string(),
            rule_value: rule_pcp.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ip_dont_fragment
    if let Some(rule_df) = mc.ip_dont_fragment {
        let pkt_val = pkt.ip_dont_fragment.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ip_dont_fragment.map(|v| v == rule_df).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ip_dont_fragment".to_string(),
            rule_value: rule_df.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ip_more_fragments
    if let Some(rule_mf) = mc.ip_more_fragments {
        let pkt_val = pkt.ip_more_fragments.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ip_more_fragments.map(|v| v == rule_mf).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ip_more_fragments".to_string(),
            rule_value: rule_mf.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ip_frag_offset
    if let Some(rule_fo) = mc.ip_frag_offset {
        let pkt_val = pkt.ip_frag_offset.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ip_frag_offset.map(|v| v == rule_fo).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ip_frag_offset".to_string(),
            rule_value: rule_fo.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // gre_protocol
    if let Some(rule_proto) = mc.gre_protocol {
        let pkt_val = pkt.gre_protocol.map(|v| format!("0x{:04x}", v)).unwrap_or_else(|| "none".to_string());
        let matches = pkt.gre_protocol.map(|v| v == rule_proto).unwrap_or(false);
        fields.push(FieldMatch {
            field: "gre_protocol".to_string(),
            rule_value: format!("0x{:04x}", rule_proto),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // gre_key
    if let Some(rule_key) = mc.gre_key {
        let pkt_val = pkt.gre_key.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.gre_key.map(|v| v == rule_key).unwrap_or(false);
        fields.push(FieldMatch {
            field: "gre_key".to_string(),
            rule_value: rule_key.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // oam_level
    if let Some(rule_level) = mc.oam_level {
        let pkt_val = pkt.oam_level.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.oam_level.map(|v| v == rule_level).unwrap_or(false);
        fields.push(FieldMatch {
            field: "oam_level".to_string(),
            rule_value: rule_level.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // oam_opcode
    if let Some(rule_opcode) = mc.oam_opcode {
        let pkt_val = pkt.oam_opcode.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.oam_opcode.map(|v| v == rule_opcode).unwrap_or(false);
        fields.push(FieldMatch {
            field: "oam_opcode".to_string(),
            rule_value: rule_opcode.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // nsh_spi
    if let Some(rule_spi) = mc.nsh_spi {
        let pkt_val = pkt.nsh_spi.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.nsh_spi.map(|v| v == rule_spi).unwrap_or(false);
        fields.push(FieldMatch {
            field: "nsh_spi".to_string(),
            rule_value: rule_spi.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // nsh_si
    if let Some(rule_si) = mc.nsh_si {
        let pkt_val = pkt.nsh_si.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.nsh_si.map(|v| v == rule_si).unwrap_or(false);
        fields.push(FieldMatch {
            field: "nsh_si".to_string(),
            rule_value: rule_si.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // nsh_next_protocol
    if let Some(rule_np) = mc.nsh_next_protocol {
        let pkt_val = pkt.nsh_next_protocol.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.nsh_next_protocol.map(|v| v == rule_np).unwrap_or(false);
        fields.push(FieldMatch {
            field: "nsh_next_protocol".to_string(),
            rule_value: rule_np.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // conntrack_state
    if let Some(ref rule_state) = mc.conntrack_state {
        let pkt_val = pkt.conntrack_state.as_deref().unwrap_or("none");
        let matches = pkt.conntrack_state.as_ref().map(|s| s == rule_state).unwrap_or(false);
        fields.push(FieldMatch {
            field: "conntrack_state".to_string(),
            rule_value: rule_state.clone(),
            packet_value: pkt_val.to_string(),
            matches,
        });
        if !matches { all_match = false; }
    }

    // geneve_vni
    if let Some(rule_vni) = mc.geneve_vni {
        let pkt_val = pkt.geneve_vni.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.geneve_vni.map(|v| v == rule_vni).unwrap_or(false);
        fields.push(FieldMatch {
            field: "geneve_vni".to_string(),
            rule_value: rule_vni.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ip_ttl
    if let Some(rule_ttl) = mc.ip_ttl {
        let pkt_val = pkt.ip_ttl.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ip_ttl.map(|v| v == rule_ttl).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ip_ttl".to_string(),
            rule_value: rule_ttl.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // frame_len_min
    if let Some(min) = mc.frame_len_min {
        let pkt_val = pkt.frame_len.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.frame_len.map(|l| l >= min).unwrap_or(false);
        fields.push(FieldMatch {
            field: "frame_len_min".to_string(),
            rule_value: min.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // frame_len_max
    if let Some(max) = mc.frame_len_max {
        let pkt_val = pkt.frame_len.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.frame_len.map(|l| l <= max).unwrap_or(false);
        fields.push(FieldMatch {
            field: "frame_len_max".to_string(),
            rule_value: max.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ptp_message_type
    if let Some(rule_val) = mc.ptp_message_type {
        let pkt_val = pkt.ptp_message_type.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ptp_message_type.map(|v| v == rule_val).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ptp_message_type".to_string(),
            rule_value: rule_val.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ptp_domain
    if let Some(rule_val) = mc.ptp_domain {
        let pkt_val = pkt.ptp_domain.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ptp_domain.map(|v| v == rule_val).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ptp_domain".to_string(),
            rule_value: rule_val.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // ptp_version
    if let Some(rule_val) = mc.ptp_version {
        let pkt_val = pkt.ptp_version.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string());
        let matches = pkt.ptp_version.map(|v| v == rule_val).unwrap_or(false);
        fields.push(FieldMatch {
            field: "ptp_version".to_string(),
            rule_value: rule_val.to_string(),
            packet_value: pkt_val,
            matches,
        });
        if !matches { all_match = false; }
    }

    // byte_match
    if let Some(ref byte_matches) = mc.byte_match {
        for bm in byte_matches {
            let (bm_matches, bm_field) = byte_match_against_packet(bm, pkt);
            fields.push(bm_field);
            if !bm_matches { all_match = false; }
        }
    }

    (all_match, fields)
}

/// Evaluate a single byte_match rule against the packet's raw_bytes
fn byte_match_against_packet(bm: &ByteMatch, pkt: &SimPacket) -> (bool, FieldMatch) {
    let offset = bm.offset as usize;
    let value_bytes = ByteMatch::parse_hex_value(&bm.value).unwrap_or_default();
    let mask_bytes = bm.mask.as_ref()
        .and_then(|m| ByteMatch::parse_hex_value(m).ok())
        .unwrap_or_else(|| vec![0xFF; value_bytes.len()]);

    let rule_str = format!("offset={} value={} mask={}", bm.offset, bm.value,
        bm.mask.as_deref().unwrap_or("0xff.."));

    match &pkt.raw_bytes {
        Some(raw) => {
            let mut all_ok = true;
            let mut pkt_hex = String::new();
            for (i, vb) in value_bytes.iter().enumerate() {
                let idx = offset + i;
                if idx >= raw.len() {
                    all_ok = false;
                    pkt_hex.push_str("??");
                } else {
                    let mb = if i < mask_bytes.len() { mask_bytes[i] } else { 0xFF };
                    if (raw[idx] & mb) != (vb & mb) {
                        all_ok = false;
                    }
                    pkt_hex.push_str(&format!("{:02x}", raw[idx]));
                }
            }
            (all_ok, FieldMatch {
                field: format!("byte_match[{}]", bm.offset),
                rule_value: rule_str,
                packet_value: format!("0x{}", pkt_hex),
                matches: all_ok,
            })
        }
        None => {
            (false, FieldMatch {
                field: format!("byte_match[{}]", bm.offset),
                rule_value: rule_str,
                packet_value: "no raw_bytes".to_string(),
                matches: false,
            })
        }
    }
}

/// Parse a hex string like "0x4500deadbeef" into bytes
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    if s.len() % 2 != 0 {
        bail!("Hex string must have even number of digits: '{}'", s);
    }
    let mut bytes = Vec::new();
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i+2], 16)
            .map_err(|e| anyhow::anyhow!("Bad hex byte '{}': {}", &s[i..i+2], e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Check if an IPv4 address matches a CIDR prefix
fn ipv4_matches_cidr(addr_str: &str, cidr_str: &str) -> bool {
    let addr = match Ipv4Prefix::parse(addr_str) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let cidr = match Ipv4Prefix::parse(cidr_str) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Apply CIDR mask to both addresses and compare
    for i in 0..4 {
        if (addr.addr[i] & cidr.mask[i]) != (cidr.addr[i] & cidr.mask[i]) {
            return false;
        }
    }
    true
}

/// Check if an IPv6 address matches a CIDR prefix
fn ipv6_matches_cidr(addr_str: &str, cidr_str: &str) -> bool {
    let addr = match Ipv6Prefix::parse(addr_str) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let cidr = match Ipv6Prefix::parse(cidr_str) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Apply CIDR mask to both addresses and compare
    for i in 0..16 {
        if (addr.addr[i] & cidr.mask[i]) != (cidr.addr[i] & cidr.mask[i]) {
            return false;
        }
    }
    true
}

/// Check if a MAC address matches a pattern (with wildcards)
fn mac_matches_pattern(pattern: &str, addr: &str) -> bool {
    let p_parts: Vec<&str> = pattern.split(':').collect();
    let a_parts: Vec<&str> = addr.split(':').collect();
    if p_parts.len() != 6 || a_parts.len() != 6 {
        return false;
    }
    for (pp, ap) in p_parts.iter().zip(a_parts.iter()) {
        if *pp == "*" {
            continue;
        }
        if pp.to_lowercase() != ap.to_lowercase() {
            return false;
        }
    }
    true
}

/// Check if a port value matches a PortMatch (exact or range)
fn port_matches(port: u16, pm: &PortMatch) -> bool {
    match pm {
        PortMatch::Exact(p) => port == *p,
        PortMatch::Range { range } => port >= range[0] && port <= range[1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn make_config(rules: Vec<StatelessRule>, default: Action) -> FilterConfig {
        FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: default },
                rules,
                conntrack: None,
                tables: None,
            },
        }
    }

    #[test]
    fn parse_packet_spec_basic() {
        let pkt = parse_packet_spec("ethertype=0x0800,dst_port=80").unwrap();
        assert_eq!(pkt.ethertype, Some(0x0800));
        assert_eq!(pkt.dst_port, Some(80));
        assert!(pkt.src_ip.is_none());
    }

    #[test]
    fn parse_packet_spec_all_fields() {
        let pkt = parse_packet_spec(
            "ethertype=0x0800,dst_mac=ff:ff:ff:ff:ff:ff,src_mac=00:11:22:33:44:55,\
             vlan_id=100,vlan_pcp=5,src_ip=10.0.0.1,dst_ip=192.168.1.1,\
             ip_protocol=6,src_port=12345,dst_port=80,vxlan_vni=1000"
        ).unwrap();
        assert_eq!(pkt.ethertype, Some(0x0800));
        assert_eq!(pkt.dst_mac.as_deref(), Some("ff:ff:ff:ff:ff:ff"));
        assert_eq!(pkt.vlan_id, Some(100));
        assert_eq!(pkt.ip_protocol, Some(6));
        assert_eq!(pkt.vxlan_vni, Some(1000));
    }

    #[test]
    fn parse_packet_spec_unknown_field() {
        assert!(parse_packet_spec("unknown=123").is_err());
    }

    #[test]
    fn parse_packet_spec_bad_format() {
        assert!(parse_packet_spec("no_equals_sign").is_err());
    }

    #[test]
    fn simulate_matches_first_rule() {
        let rules = vec![
            StatelessRule {
                name: "allow_arp".to_string(),
                priority: 200,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0806".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
            StatelessRule {
                name: "allow_ipv4".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0806").unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.rule_name.as_deref(), Some("allow_arp"));
        assert_eq!(result.action, Action::Pass);
        assert!(!result.is_default);
    }

    #[test]
    fn simulate_default_action() {
        let rules = vec![
            StatelessRule {
                name: "allow_arp".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0806".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = simulate(&config, &pkt);
        assert!(result.rule_name.is_none());
        assert_eq!(result.action, Action::Drop);
        assert!(result.is_default);
    }

    #[test]
    fn simulate_priority_order() {
        let rules = vec![
            StatelessRule {
                name: "low_pri".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
            StatelessRule {
                name: "high_pri".to_string(),
                priority: 200,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800").unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.rule_name.as_deref(), Some("high_pri"));
        assert_eq!(result.action, Action::Pass);
    }

    #[test]
    fn simulate_ip_cidr_match() {
        let rules = vec![
            StatelessRule {
                name: "subnet".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    src_ip: Some("10.0.0.0/8".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("src_ip=10.1.2.3").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("src_ip=192.168.1.1").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_port_range() {
        let rules = vec![
            StatelessRule {
                name: "high_ports".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    dst_port: Some(PortMatch::Range { range: [1024, 65535] }),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("dst_port=8080").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_mac_wildcard() {
        let rules = vec![
            StatelessRule {
                name: "vendor".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    src_mac: Some("00:1a:2b:*:*:*".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("src_mac=00:1a:2b:cc:dd:ee").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("src_mac=00:1a:3c:cc:dd:ee").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_multi_field() {
        let rules = vec![
            StatelessRule {
                name: "web_server".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    ip_protocol: Some(6),
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        // All fields match
        let pkt1 = parse_packet_spec("ethertype=0x0800,ip_protocol=6,dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        // Wrong port
        let pkt2 = parse_packet_spec("ethertype=0x0800,ip_protocol=6,dst_port=443").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);

        // Missing protocol
        let pkt3 = parse_packet_spec("ethertype=0x0800,dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt3).action, Action::Drop);
    }

    #[test]
    fn simulate_field_breakdown() {
        let rules = vec![
            StatelessRule {
                name: "test".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let pkt = parse_packet_spec("ethertype=0x0800,dst_port=80").unwrap();
        let result = simulate(&config, &pkt);
        assert!(!result.is_default);
        assert!(result.fields.iter().all(|f| f.matches));
        assert_eq!(result.fields.len(), 2);
    }

    #[test]
    fn ipv4_cidr_matching() {
        assert!(ipv4_matches_cidr("10.1.2.3", "10.0.0.0/8"));
        assert!(ipv4_matches_cidr("10.0.0.1", "10.0.0.0/24"));
        assert!(!ipv4_matches_cidr("192.168.1.1", "10.0.0.0/8"));
        assert!(ipv4_matches_cidr("192.168.1.1", "192.168.1.1"));
        assert!(ipv4_matches_cidr("0.0.0.0", "0.0.0.0/0"));
        assert!(ipv4_matches_cidr("255.255.255.255", "0.0.0.0/0"));
    }

    #[test]
    fn mac_pattern_matching() {
        assert!(mac_matches_pattern("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"));
        assert!(mac_matches_pattern("00:1a:2b:*:*:*", "00:1a:2b:cc:dd:ee"));
        assert!(!mac_matches_pattern("00:1a:2b:*:*:*", "00:1a:3c:cc:dd:ee"));
        assert!(mac_matches_pattern("*:*:*:*:*:*", "aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn port_matching() {
        assert!(port_matches(80, &PortMatch::Exact(80)));
        assert!(!port_matches(443, &PortMatch::Exact(80)));
        assert!(port_matches(8080, &PortMatch::Range { range: [1024, 65535] }));
        assert!(!port_matches(80, &PortMatch::Range { range: [1024, 65535] }));
        assert!(port_matches(1024, &PortMatch::Range { range: [1024, 65535] }));
    }

    #[test]
    fn simulate_empty_criteria_matches_all() {
        let rules = vec![
            StatelessRule {
                name: "catch_all".to_string(),
                priority: 100,
                match_criteria: MatchCriteria::default(),
                action: Some(Action::Drop),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Pass);
        let pkt = parse_packet_spec("ethertype=0x9999").unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.rule_name.as_deref(), Some("catch_all"));
        assert_eq!(result.action, Action::Drop);
    }

    #[test]
    fn simulate_vxlan_vni() {
        let rules = vec![
            StatelessRule {
                name: "tenant_100".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    vxlan_vni: Some(100),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("vxlan_vni=100").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("vxlan_vni=200").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_ipv6_cidr_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_ipv6_subnet".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    src_ipv6: Some("2001:db8::/32".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("src_ipv6=2001:db8::1").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("src_ipv6=2001:db9::1").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_ipv6_next_header() {
        let rules = vec![
            StatelessRule {
                name: "allow_icmpv6".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ipv6_next_header: Some(58),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let pkt1 = parse_packet_spec("ipv6_next_header=58").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        let pkt2 = parse_packet_spec("ipv6_next_header=6").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn ipv6_cidr_matching() {
        assert!(ipv6_matches_cidr("2001:db8::1", "2001:db8::/32"));
        assert!(ipv6_matches_cidr("2001:db8:abcd::1", "2001:db8::/32"));
        assert!(!ipv6_matches_cidr("2001:db9::1", "2001:db8::/32"));
        assert!(ipv6_matches_cidr("fe80::1", "fe80::/10"));
        assert!(ipv6_matches_cidr("::1", "::1/128"));
        assert!(ipv6_matches_cidr("::1", "::1"));
    }

    #[test]
    fn simulate_ipv6_all_fields() {
        let rules = vec![
            StatelessRule {
                name: "ipv6_web".to_string(),
                priority: 200,
                match_criteria: MatchCriteria {
                    src_ipv6: Some("2001:db8::/32".to_string()),
                    ipv6_next_header: Some(6), // TCP
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        // All match
        let pkt1 = parse_packet_spec("src_ipv6=2001:db8::1,ipv6_next_header=6,dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt1).action, Action::Pass);

        // Wrong subnet
        let pkt2 = parse_packet_spec("src_ipv6=2001:db9::1,ipv6_next_header=6,dst_port=80").unwrap();
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);

        // Wrong port
        let pkt3 = parse_packet_spec("src_ipv6=2001:db8::1,ipv6_next_header=6,dst_port=443").unwrap();
        assert_eq!(simulate(&config, &pkt3).action, Action::Drop);
    }

    #[test]
    fn parse_hex_bytes_basic() {
        let bytes = parse_hex_bytes("0x4500").unwrap();
        assert_eq!(bytes, vec![0x45, 0x00]);
    }

    #[test]
    fn parse_hex_bytes_no_prefix() {
        let bytes = parse_hex_bytes("deadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_hex_bytes_odd_digits_rejected() {
        assert!(parse_hex_bytes("0x456").is_err());
    }

    #[test]
    fn simulate_byte_match_matches() {
        let rules = vec![
            StatelessRule {
                name: "ip_version".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    byte_match: Some(vec![
                        ByteMatch { offset: 0, value: "0x45".to_string(), mask: None },
                    ]),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        let mut pkt = SimPacket::default();
        pkt.raw_bytes = Some(vec![0x45, 0x00, 0x00, 0x28]);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);
    }

    #[test]
    fn simulate_byte_match_with_mask() {
        let rules = vec![
            StatelessRule {
                name: "ip_version_masked".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    byte_match: Some(vec![
                        ByteMatch { offset: 0, value: "0x40".to_string(), mask: Some("0xf0".to_string()) },
                    ]),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        // 0x45 & 0xf0 = 0x40 == 0x40 & 0xf0 → match
        let mut pkt = SimPacket::default();
        pkt.raw_bytes = Some(vec![0x45, 0x00]);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);

        // 0x60 & 0xf0 = 0x60 != 0x40 → no match
        let mut pkt2 = SimPacket::default();
        pkt2.raw_bytes = Some(vec![0x60, 0x00]);
        assert_eq!(simulate(&config, &pkt2).action, Action::Drop);
    }

    #[test]
    fn simulate_byte_match_no_raw_bytes() {
        let rules = vec![
            StatelessRule {
                name: "byte_rule".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    byte_match: Some(vec![
                        ByteMatch { offset: 0, value: "0x45".to_string(), mask: None },
                    ]),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);

        // No raw_bytes → no match → default action
        let pkt = SimPacket::default();
        assert_eq!(simulate(&config, &pkt).action, Action::Drop);
    }

    #[test]
    fn parse_raw_bytes_in_packet_spec() {
        let pkt = parse_packet_spec("raw_bytes=0x4500deadbeef").unwrap();
        assert_eq!(pkt.raw_bytes, Some(vec![0x45, 0x00, 0xde, 0xad, 0xbe, 0xef]));
    }

    // --- GTP/MPLS/multicast simulation ---

    #[test]
    fn parse_gtp_teid() {
        let pkt = parse_packet_spec("gtp_teid=1000").unwrap();
        assert_eq!(pkt.gtp_teid, Some(1000));
    }

    #[test]
    fn parse_mpls_fields() {
        let pkt = parse_packet_spec("mpls_label=200,mpls_tc=7,mpls_bos=true").unwrap();
        assert_eq!(pkt.mpls_label, Some(200));
        assert_eq!(pkt.mpls_tc, Some(7));
        assert_eq!(pkt.mpls_bos, Some(true));
    }

    #[test]
    fn parse_igmp_type() {
        let pkt = parse_packet_spec("igmp_type=17").unwrap();
        assert_eq!(pkt.igmp_type, Some(17));
    }

    #[test]
    fn parse_mld_type() {
        let pkt = parse_packet_spec("mld_type=130").unwrap();
        assert_eq!(pkt.mld_type, Some(130));
    }

    #[test]
    fn simulate_gtp_teid_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_tunnel".into(),
                priority: 100,
                match_criteria: MatchCriteria {
                    gtp_teid: Some(1000),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let mut pkt = SimPacket::default();
        pkt.gtp_teid = Some(1000);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);

        // Wrong TEID → default drop
        pkt.gtp_teid = Some(9999);
        assert_eq!(simulate(&config, &pkt).action, Action::Drop);
    }

    #[test]
    fn simulate_mpls_label_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_vpn".into(),
                priority: 100,
                match_criteria: MatchCriteria {
                    mpls_label: Some(200),
                    mpls_bos: Some(true),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let mut pkt = SimPacket::default();
        pkt.mpls_label = Some(200);
        pkt.mpls_bos = Some(true);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);

        // Wrong label → drop
        pkt.mpls_label = Some(300);
        assert_eq!(simulate(&config, &pkt).action, Action::Drop);
    }

    #[test]
    fn simulate_igmp_type_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_igmp".into(),
                priority: 100,
                match_criteria: MatchCriteria {
                    igmp_type: Some(17),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let mut pkt = SimPacket::default();
        pkt.igmp_type = Some(17);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);

        // Wrong type → drop
        pkt.igmp_type = Some(22);
        assert_eq!(simulate(&config, &pkt).action, Action::Drop);
    }

    #[test]
    fn simulate_mld_type_match() {
        let rules = vec![
            StatelessRule {
                name: "allow_mld".into(),
                priority: 100,
                match_criteria: MatchCriteria {
                    mld_type: Some(130),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        let config = make_config(rules, Action::Drop);
        let mut pkt = SimPacket::default();
        pkt.mld_type = Some(130);
        assert_eq!(simulate(&config, &pkt).action, Action::Pass);
    }

    // --- Rate limit simulation tests ---

    fn make_rate_limited_config() -> FilterConfig {
        use crate::model::RateLimit;
        let rules = vec![
            StatelessRule {
                name: "http_limited".to_string(),
                priority: 200,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0800".to_string()),
                    dst_port: Some(PortMatch::Exact(80)),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: Some(RateLimit { pps: 100, burst: 10 }),
                rewrite: None, mirror_port: None, redirect_port: None,
            },
            StatelessRule {
                name: "allow_arp".to_string(),
                priority: 100,
                match_criteria: MatchCriteria {
                    ethertype: Some("0x0806".to_string()),
                    ..Default::default()
                },
                action: Some(Action::Pass),
                rule_type: None,
                fsm: None,
                ports: None,
                rate_limit: None,
                rewrite: None, mirror_port: None, redirect_port: None,
            },
        ];
        make_config(rules, Action::Drop)
    }

    #[test]
    fn rate_limit_state_new_initializes_tokens() {
        let config = make_rate_limited_config();
        let state = SimRateLimitState::new(&config);
        assert_eq!(*state.tokens.get("http_limited").unwrap(), 10.0);
        assert!(!state.tokens.contains_key("allow_arp"));
    }

    #[test]
    fn rate_limit_state_refill_adds_tokens() {
        let config = make_rate_limited_config();
        let mut state = SimRateLimitState::new(&config);
        // Consume all tokens first
        state.tokens.insert("http_limited".to_string(), 0.0);
        state.refill("http_limited", 100, 10, 0.05); // 100 pps * 0.05s = 5 tokens
        let tokens = *state.tokens.get("http_limited").unwrap();
        assert!((tokens - 5.0).abs() < 0.001);
    }

    #[test]
    fn rate_limit_state_refill_caps_at_burst() {
        let config = make_rate_limited_config();
        let mut state = SimRateLimitState::new(&config);
        state.refill("http_limited", 100, 10, 1.0); // 100 pps * 1s = 100, but burst=10
        let tokens = *state.tokens.get("http_limited").unwrap();
        assert!((tokens - 10.0).abs() < 0.001);
    }

    #[test]
    fn rate_limit_try_consume_decrements() {
        let config = make_rate_limited_config();
        let mut state = SimRateLimitState::new(&config);
        assert!(state.try_consume("http_limited"));
        let tokens = *state.tokens.get("http_limited").unwrap();
        assert!((tokens - 9.0).abs() < 0.001);
    }

    #[test]
    fn rate_limit_try_consume_empty_returns_false() {
        let config = make_rate_limited_config();
        let mut state = SimRateLimitState::new(&config);
        state.tokens.insert("http_limited".to_string(), 0.0);
        assert!(!state.try_consume("http_limited"));
    }

    #[test]
    fn simulate_with_rate_limit_passes_when_tokens_available() {
        let config = make_rate_limited_config();
        let mut state = SimRateLimitState::new(&config);
        let pkt = parse_packet_spec("ethertype=0x0800,dst_port=80").unwrap();
        let result = simulate_with_rate_limit(&config, &pkt, &mut state, 0.0);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("http_limited"));
        assert!(!result.is_default);
    }

    #[test]
    fn simulate_with_rate_limit_drops_when_exhausted() {
        let config = make_rate_limited_config();
        let mut state = SimRateLimitState::new(&config);
        state.tokens.insert("http_limited".to_string(), 0.0);
        let pkt = parse_packet_spec("ethertype=0x0800,dst_port=80").unwrap();
        let result = simulate_with_rate_limit(&config, &pkt, &mut state, 0.0);
        assert_eq!(result.action, Action::Drop); // default action
        assert!(result.is_default);
        assert_eq!(result.rule_name.as_deref(), Some("rate_limited"));
    }

    #[test]
    fn simulate_with_rate_limit_no_rate_limit_rule_passes() {
        let config = make_rate_limited_config();
        let mut state = SimRateLimitState::new(&config);
        let pkt = parse_packet_spec("ethertype=0x0806").unwrap();
        let result = simulate_with_rate_limit(&config, &pkt, &mut state, 0.0);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_arp"));
        assert!(!result.is_default);
    }

    // --- Conntrack simulation tests ---

    #[test]
    fn conntrack_hash_5tuple_deterministic() {
        let pkt = parse_packet_spec("src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,src_port=12345,dst_port=80").unwrap();
        let h1 = SimConntrackTable::hash_5tuple(&pkt);
        let h2 = SimConntrackTable::hash_5tuple(&pkt);
        assert_eq!(h1, h2);
    }

    #[test]
    fn conntrack_insert_and_check_return() {
        let mut ct = SimConntrackTable::new(100);
        let pkt = parse_packet_spec("src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,src_port=12345,dst_port=80").unwrap();
        ct.insert_flow(&pkt, "allow_web", 0);

        // Reverse packet should match
        let rev = parse_packet_spec("src_ip=10.0.0.2,dst_ip=10.0.0.1,ip_protocol=6,src_port=80,dst_port=12345").unwrap();
        assert!(ct.check_return(&rev, 50).is_some());
    }

    #[test]
    fn conntrack_timeout_expires() {
        let mut ct = SimConntrackTable::new(100);
        let pkt = parse_packet_spec("src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,src_port=12345,dst_port=80").unwrap();
        ct.insert_flow(&pkt, "allow_web", 0);

        let rev = parse_packet_spec("src_ip=10.0.0.2,dst_ip=10.0.0.1,ip_protocol=6,src_port=80,dst_port=12345").unwrap();
        assert!(ct.check_return(&rev, 200).is_none()); // expired
    }

    #[test]
    fn test_dscp_match() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_dscp=46").unwrap();
        assert_eq!(pkt.ip_dscp, Some(46));
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ef_rule
      priority: 100
      match:
        ethertype: "0x0800"
        ip_dscp: 46
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("ef_rule"));
    }

    #[test]
    fn test_ecn_match() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_ecn=2").unwrap();
        assert_eq!(pkt.ip_ecn, Some(2));
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ecn_rule
      priority: 100
      match:
        ethertype: "0x0800"
        ip_ecn: 2
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("ecn_rule"));
    }

    #[test]
    fn test_ipv6_dscp_match() {
        let pkt = parse_packet_spec("ethertype=0x86DD,ipv6_dscp=46").unwrap();
        assert_eq!(pkt.ipv6_dscp, Some(46));
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ipv6_ef
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_dscp: 46
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("ipv6_ef"));
    }

    #[test]
    fn test_tcp_flags_match() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=6,tcp_flags=0x02").unwrap();
        assert_eq!(pkt.tcp_flags, Some(0x02));
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_syn
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        tcp_flags: 2
        tcp_flags_mask: 18
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_syn"));
    }

    #[test]
    fn test_tcp_flags_mask_match() {
        // SYN+ACK (0x12) should NOT match SYN-only rule (flags=0x02, mask=0x12)
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=6,tcp_flags=0x12").unwrap();
        assert_eq!(pkt.tcp_flags, Some(0x12));
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: syn_only
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        tcp_flags: 2
        tcp_flags_mask: 18
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        // SYN+ACK (0x12 & 0x12 = 0x12) != (0x02 & 0x12 = 0x02), so no match
        assert_eq!(result.action, Action::Drop);
        assert!(result.is_default);
    }

    #[test]
    fn test_icmp_type_match() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=1,icmp_type=8").unwrap();
        assert_eq!(pkt.icmp_type, Some(8));
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ping
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 1
        icmp_type: 8
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_ping"));
    }

    #[test]
    fn test_icmp_code_match() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=1,icmp_type=3,icmp_code=1").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: host_unreachable
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 1
        icmp_type: 3
        icmp_code: 1
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("host_unreachable"));
    }

    #[test]
    fn test_icmpv6_type_match() {
        let pkt = parse_packet_spec("ethertype=0x86DD,ipv6_next_header=58,icmpv6_type=128").unwrap();
        assert_eq!(pkt.icmpv6_type, Some(128));
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_icmpv6_echo
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_next_header: 58
        icmpv6_type: 128
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_icmpv6_echo"));
    }

    #[test]
    fn test_arp_opcode_match() {
        let pkt = parse_packet_spec("ethertype=0x0806,arp_opcode=1").unwrap();
        assert_eq!(pkt.arp_opcode, Some(1));
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_arp_request
      priority: 100
      match:
        ethertype: "0x0806"
        arp_opcode: 1
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_arp_request"));
    }

    #[test]
    fn test_arp_spa_match() {
        let pkt = parse_packet_spec("ethertype=0x0806,arp_opcode=2,arp_spa=10.0.0.1").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_gateway_reply
      priority: 100
      match:
        ethertype: "0x0806"
        arp_opcode: 2
        arp_spa: "10.0.0.1"
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_gateway_reply"));
    }

    #[test]
    fn test_ipv6_hop_limit_match() {
        let pkt = parse_packet_spec("ethertype=0x86DD,ipv6_hop_limit=64").unwrap();
        assert_eq!(pkt.ipv6_hop_limit, Some(64));
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ttl64
      priority: 100
      match:
        ethertype: "0x86DD"
        ipv6_hop_limit: 64
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_ttl64"));
    }

    #[test]
    fn tcp_state_advance_syn_ack() {
        let state = TcpState::New;
        // SYN-ACK from reverse direction → established
        let next = state.advance(Some(0x12), true); // SYN+ACK
        assert_eq!(next, TcpState::Established);
    }

    #[test]
    fn tcp_state_advance_rst() {
        let state = TcpState::Established;
        let next = state.advance(Some(0x04), false); // RST
        assert_eq!(next, TcpState::Closed);
    }

    #[test]
    fn tcp_state_advance_fin() {
        let state = TcpState::Established;
        let next = state.advance(Some(0x01), false); // FIN
        assert_eq!(next, TcpState::FinWait);
    }

    #[test]
    fn conntrack_state_new_flow() {
        let ct = SimConntrackTable::new(1000);
        let pkt = SimPacket {
            src_ip: Some("10.0.0.1".to_string()),
            dst_ip: Some("10.0.0.2".to_string()),
            ip_protocol: Some(6),
            src_port: Some(1234),
            dst_port: Some(80),
            ..Default::default()
        };
        assert_eq!(ct.get_state(&pkt, 0), "new");
    }

    #[test]
    fn conntrack_state_after_insert() {
        let mut ct = SimConntrackTable::new(1000);
        let pkt = SimPacket {
            src_ip: Some("10.0.0.1".to_string()),
            dst_ip: Some("10.0.0.2".to_string()),
            ip_protocol: Some(6),
            src_port: Some(1234),
            dst_port: Some(80),
            ..Default::default()
        };
        ct.insert_flow(&pkt, "test_rule", 0);
        // Forward flow should be "new" (initial state after SYN)
        assert_eq!(ct.get_state(&pkt, 0), "new");
    }

    #[test]
    fn conntrack_state_reverse_established() {
        let mut ct = SimConntrackTable::new(1000);
        let fwd = SimPacket {
            src_ip: Some("10.0.0.1".to_string()),
            dst_ip: Some("10.0.0.2".to_string()),
            ip_protocol: Some(6),
            src_port: Some(1234),
            dst_port: Some(80),
            ..Default::default()
        };
        ct.insert_flow(&fwd, "test_rule", 0);
        // Reverse packet should see "established"
        let rev = SimPacket {
            src_ip: Some("10.0.0.2".to_string()),
            dst_ip: Some("10.0.0.1".to_string()),
            ip_protocol: Some(6),
            src_port: Some(80),
            dst_port: Some(1234),
            ..Default::default()
        };
        assert_eq!(ct.get_state(&rev, 0), "established");
    }

    #[test]
    fn conntrack_update_tcp_state() {
        let mut ct = SimConntrackTable::new(1000);
        let fwd = SimPacket {
            src_ip: Some("10.0.0.1".to_string()),
            dst_ip: Some("10.0.0.2".to_string()),
            ip_protocol: Some(6),
            src_port: Some(1234),
            dst_port: Some(80),
            tcp_flags: Some(0x02), // SYN
            ..Default::default()
        };
        ct.insert_flow(&fwd, "test_rule", 0);
        // SYN-ACK from reverse
        let rev = SimPacket {
            src_ip: Some("10.0.0.2".to_string()),
            dst_ip: Some("10.0.0.1".to_string()),
            ip_protocol: Some(6),
            src_port: Some(80),
            dst_port: Some(1234),
            tcp_flags: Some(0x12), // SYN+ACK
            ..Default::default()
        };
        ct.update_tcp_state(&rev, 1);
        // Forward flow should now be established
        assert_eq!(ct.get_state(&fwd, 1), "established");
    }

    #[test]
    fn simulate_conntrack_state_match() {
        let pkt = SimPacket {
            ethertype: Some(0x0800),
            conntrack_state: Some("established".to_string()),
            ..Default::default()
        };
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_established
      priority: 100
      match:
        ethertype: "0x0800"
        conntrack_state: "established"
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_established"));
    }

    #[test]
    fn simulate_conntrack_state_no_match() {
        let pkt = SimPacket {
            ethertype: Some(0x0800),
            conntrack_state: Some("new".to_string()),
            ..Default::default()
        };
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_established
      priority: 100
      match:
        ethertype: "0x0800"
        conntrack_state: "established"
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Drop);
    }

    // --- Mirror/Redirect simulation ---

    #[test]
    fn simulate_mirror_port_returned() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: mirror_http
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 6
        dst_port: 80
      action: pass
      mirror_port: 1
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let pkt = SimPacket {
            ethertype: Some(0x0800),
            ip_protocol: Some(6),
            dst_port: Some(80),
            ..Default::default()
        };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.mirror_port, Some(1));
        assert_eq!(result.redirect_port, None);
    }

    #[test]
    fn simulate_redirect_port_returned() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: redirect_dns
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 17
        dst_port: 53
      action: pass
      redirect_port: 2
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let pkt = SimPacket {
            ethertype: Some(0x0800),
            ip_protocol: Some(17),
            dst_port: Some(53),
            ..Default::default()
        };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.mirror_port, None);
        assert_eq!(result.redirect_port, Some(2));
    }

    #[test]
    fn simulate_mirror_and_redirect_together() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: both
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      mirror_port: 3
      redirect_port: 4
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let pkt = SimPacket {
            ethertype: Some(0x0800),
            ..Default::default()
        };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.mirror_port, Some(3));
        assert_eq!(result.redirect_port, Some(4));
    }

    // --- OAM/CFM tests ---

    #[test]
    fn parse_oam_fields() {
        let pkt = parse_packet_spec("ethertype=0x8902,oam_level=3,oam_opcode=1").unwrap();
        assert_eq!(pkt.ethertype, Some(0x8902));
        assert_eq!(pkt.oam_level, Some(3));
        assert_eq!(pkt.oam_opcode, Some(1));
    }

    #[test]
    fn simulate_oam_ccm_match() {
        let pkt = parse_packet_spec("ethertype=0x8902,oam_level=3,oam_opcode=1").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ccm
      priority: 100
      match:
        ethertype: "0x8902"
        oam_level: 3
        oam_opcode: 1
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_ccm"));
    }

    #[test]
    fn simulate_oam_level_mismatch() {
        let pkt = parse_packet_spec("ethertype=0x8902,oam_level=5,oam_opcode=1").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_ccm_level3
      priority: 100
      match:
        ethertype: "0x8902"
        oam_level: 3
        oam_opcode: 1
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Drop);
    }

    #[test]
    fn simulate_oam_dmm_match() {
        let pkt = parse_packet_spec("ethertype=0x8902,oam_level=5,oam_opcode=47").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_dmm
      priority: 100
      match:
        ethertype: "0x8902"
        oam_opcode: 47
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_dmm"));
    }

    // --- NSH/SFC tests ---

    #[test]
    fn parse_nsh_fields() {
        let pkt = parse_packet_spec("ethertype=0x894F,nsh_spi=100,nsh_si=254,nsh_next_protocol=1").unwrap();
        assert_eq!(pkt.nsh_spi, Some(100));
        assert_eq!(pkt.nsh_si, Some(254));
        assert_eq!(pkt.nsh_next_protocol, Some(1));
    }

    #[test]
    fn simulate_nsh_spi_match() {
        let pkt = parse_packet_spec("ethertype=0x894F,nsh_spi=100,nsh_si=254").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: sfc_proxy
      priority: 100
      match:
        ethertype: "0x894F"
        nsh_spi: 100
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("sfc_proxy"));
    }

    #[test]
    fn simulate_nsh_spi_mismatch() {
        let pkt = parse_packet_spec("ethertype=0x894F,nsh_spi=200,nsh_si=254").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: sfc_proxy
      priority: 100
      match:
        ethertype: "0x894F"
        nsh_spi: 100
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Drop);
    }

    #[test]
    fn simulate_nsh_next_protocol_match() {
        let pkt = parse_packet_spec("ethertype=0x894F,nsh_spi=101,nsh_next_protocol=1").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: sfc_ipv4
      priority: 100
      match:
        ethertype: "0x894F"
        nsh_next_protocol: 1
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
    }

    // --- Geneve VNI tests ---

    #[test]
    fn parse_geneve_vni() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=17,dst_port=6081,geneve_vni=1000").unwrap();
        assert_eq!(pkt.ethertype, Some(0x0800));
        assert_eq!(pkt.ip_protocol, Some(17));
        assert_eq!(pkt.dst_port, Some(6081));
        assert_eq!(pkt.geneve_vni, Some(1000));
    }

    #[test]
    fn simulate_geneve_vni_match() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=17,dst_port=6081,geneve_vni=1000").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_geneve_vni
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 17
        dst_port: 6081
        geneve_vni: 1000
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("allow_geneve_vni"));
    }

    #[test]
    fn simulate_geneve_vni_mismatch() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_protocol=17,dst_port=6081,geneve_vni=2000").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: allow_geneve_vni
      priority: 100
      match:
        ethertype: "0x0800"
        ip_protocol: 17
        dst_port: 6081
        geneve_vni: 1000
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Drop);
    }

    // --- ip_ttl and frame_len tests ---

    #[test]
    fn parse_ip_ttl() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_ttl=1").unwrap();
        assert_eq!(pkt.ethertype, Some(0x0800));
        assert_eq!(pkt.ip_ttl, Some(1));
    }

    #[test]
    fn simulate_ip_ttl_match() {
        let pkt = parse_packet_spec("ethertype=0x0800,ip_ttl=1").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: drop_ttl1
      priority: 100
      match:
        ethertype: "0x0800"
        ip_ttl: 1
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("drop_ttl1"));
    }

    #[test]
    fn parse_frame_len() {
        let pkt = parse_packet_spec("ethertype=0x0800,frame_len=128").unwrap();
        assert_eq!(pkt.ethertype, Some(0x0800));
        assert_eq!(pkt.frame_len, Some(128));
    }

    #[test]
    fn simulate_frame_len_match() {
        // frame_len=256 should match frame_len_min=64, frame_len_max=1500
        let pkt = parse_packet_spec("ethertype=0x0800,frame_len=256").unwrap();
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: normal_size
      priority: 100
      match:
        ethertype: "0x0800"
        frame_len_min: 64
        frame_len_max: 1500
      action: pass
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("normal_size"));

        // frame_len=40 is below min=64 → drop
        let pkt2 = parse_packet_spec("ethertype=0x0800,frame_len=40").unwrap();
        let result2 = simulate(&config, &pkt2);
        assert_eq!(result2.action, Action::Drop);

        // frame_len=9000 is above max=1500 → drop
        let pkt3 = parse_packet_spec("ethertype=0x0800,frame_len=9000").unwrap();
        let result3 = simulate(&config, &pkt3);
        assert_eq!(result3.action, Action::Drop);
    }

    // --- Rewrite new fields tests ---

    #[test]
    fn simulate_rewrite_dec_hop_limit() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: ipv6_router
      priority: 100
      match:
        ethertype: "0x86DD"
      action: pass
      rewrite:
        dec_hop_limit: true
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let pkt = SimPacket {
            ethertype: Some(0x86DD),
            ..Default::default()
        };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        let rw = result.rewrite.unwrap();
        assert!(rw.dec_hop_limit);
        assert!(rw.set_hop_limit.is_none());
    }

    #[test]
    fn simulate_rewrite_set_vlan_pcp() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: qos_remark
      priority: 100
      match:
        ethertype: "0x0800"
      action: pass
      rewrite:
        set_vlan_pcp: 5
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let pkt = SimPacket {
            ethertype: Some(0x0800),
            ..Default::default()
        };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        let rw = result.rewrite.unwrap();
        assert_eq!(rw.set_vlan_pcp, Some(5));
        assert!(rw.set_outer_vlan_id.is_none());
    }

    // --- Flow counter tests ---

    #[test]
    fn flow_entry_initial_counts() {
        let mut ct = SimConntrackTable::new(1000);
        let pkt = parse_packet_spec("src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,src_port=1234,dst_port=80").unwrap();
        ct.insert_flow(&pkt, "allow_web", 0);
        let hash = SimConntrackTable::hash_5tuple(&pkt);
        let entry = ct.flows.get(&hash).unwrap();
        assert_eq!(entry.pkt_count, 1);
        assert_eq!(entry.byte_count, 0);
    }

    #[test]
    fn flow_counter_increment() {
        let mut ct = SimConntrackTable::new(1000);
        let pkt = parse_packet_spec("src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,src_port=1234,dst_port=80").unwrap();
        ct.insert_flow(&pkt, "allow_web", 0);
        ct.increment_counters(&pkt, 64);
        ct.increment_counters(&pkt, 128);
        let hash = SimConntrackTable::hash_5tuple(&pkt);
        let entry = ct.flows.get(&hash).unwrap();
        assert_eq!(entry.pkt_count, 3); // 1 from insert + 2 from increment
        assert_eq!(entry.byte_count, 192);
    }

    #[test]
    fn flow_counter_reverse_direction() {
        let mut ct = SimConntrackTable::new(1000);
        let fwd = parse_packet_spec("src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,src_port=1234,dst_port=80").unwrap();
        ct.insert_flow(&fwd, "allow_web", 0);
        // Increment via reverse packet
        let rev = parse_packet_spec("src_ip=10.0.0.2,dst_ip=10.0.0.1,ip_protocol=6,src_port=80,dst_port=1234").unwrap();
        ct.increment_counters(&rev, 100);
        let hash = SimConntrackTable::hash_5tuple(&fwd);
        let entry = ct.flows.get(&hash).unwrap();
        assert_eq!(entry.pkt_count, 2); // 1 from insert + 1 from reverse increment
        assert_eq!(entry.byte_count, 100);
    }

    #[test]
    fn flow_stats_active_only() {
        let mut ct = SimConntrackTable::new(100);
        let pkt1 = parse_packet_spec("src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,src_port=1234,dst_port=80").unwrap();
        let pkt2 = parse_packet_spec("src_ip=10.0.0.3,dst_ip=10.0.0.4,ip_protocol=17,src_port=5000,dst_port=53").unwrap();
        ct.insert_flow(&pkt1, "flow1", 0);
        ct.insert_flow(&pkt2, "flow2", 50);
        // At timestamp 200, flow1 should be expired (200-0=200 > 100), flow2 still active (200-50=150 > 100)
        // Actually 200-50=150 > 100, so both expired
        let stats = ct.flow_stats(200);
        assert_eq!(stats.len(), 0);
        // At timestamp 90, both active
        let stats = ct.flow_stats(90);
        assert_eq!(stats.len(), 2);
    }

    #[test]
    fn flow_stats_counter_values() {
        let mut ct = SimConntrackTable::new(1000);
        let pkt = parse_packet_spec("src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,src_port=1234,dst_port=80").unwrap();
        ct.insert_flow(&pkt, "allow_web", 0);
        ct.increment_counters(&pkt, 64);
        ct.increment_counters(&pkt, 128);
        let stats = ct.flow_stats(10);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].rule_name, "allow_web");
        assert_eq!(stats[0].pkt_count, 3);
        assert_eq!(stats[0].byte_count, 192);
    }

    #[test]
    fn update_tcp_state_increments_pkt_count() {
        let mut ct = SimConntrackTable::new(1000);
        let fwd = parse_packet_spec("src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,src_port=1234,dst_port=80").unwrap();
        ct.insert_flow(&fwd, "test", 0);
        let mut syn_ack = parse_packet_spec("src_ip=10.0.0.2,dst_ip=10.0.0.1,ip_protocol=6,src_port=80,dst_port=1234").unwrap();
        syn_ack.tcp_flags = Some(0x12);
        ct.update_tcp_state(&syn_ack, 1);
        let hash = SimConntrackTable::hash_5tuple(&fwd);
        let entry = ct.flows.get(&hash).unwrap();
        assert_eq!(entry.pkt_count, 2); // 1 from insert + 1 from update_tcp_state
    }

    #[test]
    fn simulate_no_match_no_egress_actions() {
        let yaml = r#"
pacgate:
  version: "1.0"
  defaults:
    action: drop
  rules:
    - name: mirror_http
      priority: 100
      match:
        ethertype: "0x0800"
        dst_port: 80
      action: pass
      mirror_port: 1
"#;
        let config: crate::model::FilterConfig = serde_yaml::from_str(yaml).unwrap();
        let pkt = SimPacket {
            ethertype: Some(0x0806),
            ..Default::default()
        };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Drop);
        assert!(result.is_default);
        assert_eq!(result.mirror_port, None);
        assert_eq!(result.redirect_port, None);
    }

    // --- Pipeline simulation tests ---

    fn make_pipeline_config(stages: Vec<PipelineStage>, default: Action) -> FilterConfig {
        FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: default },
                rules: Vec::new(),
                conntrack: None,
                tables: Some(stages),
            },
        }
    }

    fn make_stage(name: &str, rules: Vec<StatelessRule>, default: Action, next: Option<&str>) -> PipelineStage {
        PipelineStage {
            name: name.to_string(),
            rules,
            default_action: default,
            next_table: next.map(|s| s.to_string()),
        }
    }

    fn simple_rule(name: &str, priority: u32, mc: MatchCriteria, action: Action) -> StatelessRule {
        StatelessRule {
            name: name.to_string(), priority,
            match_criteria: mc,
            action: Some(action),
            rule_type: None, fsm: None, ports: None,
            rate_limit: None, rewrite: None,
            mirror_port: None, redirect_port: None,
        }
    }

    #[test]
    fn pipeline_simulate_both_pass() {
        let config = make_pipeline_config(vec![
            make_stage("classify", vec![
                simple_rule("web", 100, MatchCriteria { dst_port: Some(PortMatch::Exact(80)), ..Default::default() }, Action::Pass),
            ], Action::Drop, Some("enforce")),
            make_stage("enforce", vec![
                simple_rule("allow_all", 100, MatchCriteria::default(), Action::Pass),
            ], Action::Drop, None),
        ], Action::Drop);
        let pkt = SimPacket { dst_port: Some(80), ..Default::default() };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert!(!result.is_default);
    }

    #[test]
    fn pipeline_simulate_first_stage_drops() {
        let config = make_pipeline_config(vec![
            make_stage("classify", vec![
                simple_rule("block_ssh", 100, MatchCriteria { dst_port: Some(PortMatch::Exact(22)), ..Default::default() }, Action::Drop),
            ], Action::Pass, Some("enforce")),
            make_stage("enforce", vec![
                simple_rule("allow_all", 100, MatchCriteria::default(), Action::Pass),
            ], Action::Drop, None),
        ], Action::Drop);
        let pkt = SimPacket { dst_port: Some(22), ..Default::default() };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Drop);
        assert_eq!(result.rule_name.as_deref(), Some("block_ssh"));
    }

    #[test]
    fn pipeline_simulate_second_stage_drops() {
        let config = make_pipeline_config(vec![
            make_stage("classify", vec![
                simple_rule("web", 100, MatchCriteria { dst_port: Some(PortMatch::Exact(80)), ..Default::default() }, Action::Pass),
            ], Action::Drop, Some("enforce")),
            make_stage("enforce", vec![], Action::Drop, None),
        ], Action::Drop);
        let pkt = SimPacket { dst_port: Some(80), ..Default::default() };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Drop);
        assert!(result.is_default);
    }

    #[test]
    fn pipeline_simulate_default_actions() {
        let config = make_pipeline_config(vec![
            make_stage("classify", vec![], Action::Pass, Some("enforce")),
            make_stage("enforce", vec![], Action::Pass, None),
        ], Action::Drop);
        let pkt = SimPacket { dst_port: Some(80), ..Default::default() };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert!(result.is_default);
    }

    #[test]
    fn pipeline_simulate_three_stages() {
        let config = make_pipeline_config(vec![
            make_stage("s1", vec![
                simple_rule("r1", 100, MatchCriteria { dst_port: Some(PortMatch::Exact(80)), ..Default::default() }, Action::Pass),
            ], Action::Drop, Some("s2")),
            make_stage("s2", vec![
                simple_rule("r2", 100, MatchCriteria { ethertype: Some("0x0800".into()), ..Default::default() }, Action::Pass),
            ], Action::Drop, Some("s3")),
            make_stage("s3", vec![
                simple_rule("r3", 100, MatchCriteria::default(), Action::Pass),
            ], Action::Drop, None),
        ], Action::Drop);
        let pkt = SimPacket { ethertype: Some(0x0800), dst_port: Some(80), ..Default::default() };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("r3"));
    }

    #[test]
    fn pipeline_simulate_middle_stage_drops() {
        let config = make_pipeline_config(vec![
            make_stage("s1", vec![
                simple_rule("r1", 100, MatchCriteria::default(), Action::Pass),
            ], Action::Drop, Some("s2")),
            make_stage("s2", vec![], Action::Drop, Some("s3")),
            make_stage("s3", vec![
                simple_rule("r3", 100, MatchCriteria::default(), Action::Pass),
            ], Action::Drop, None),
        ], Action::Drop);
        let pkt = SimPacket::default();
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Drop);
        assert!(result.is_default);
    }

    #[test]
    fn pipeline_backward_compat_no_tables() {
        let config = make_config(vec![
            simple_rule("web", 100, MatchCriteria { dst_port: Some(PortMatch::Exact(80)), ..Default::default() }, Action::Pass),
        ], Action::Drop);
        let pkt = SimPacket { dst_port: Some(80), ..Default::default() };
        let result = simulate(&config, &pkt);
        assert_eq!(result.action, Action::Pass);
        assert_eq!(result.rule_name.as_deref(), Some("web"));
    }
}
