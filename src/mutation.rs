//! Rule Mutation Engine for Mutation Testing
//!
//! Generates mutated rule sets to verify test quality — if a mutation
//! is not caught by existing tests, the test suite has a gap.

use crate::model::{Action, FilterConfig, PortMatch};

/// A single mutation applied to a rule set
#[derive(Debug, Clone, serde::Serialize)]
pub struct Mutation {
    pub name: String,
    pub description: String,
    pub mutant_index: usize,
}

/// Generate mutated variants of a rule set
pub fn generate_mutations(config: &FilterConfig) -> Vec<(Mutation, FilterConfig)> {
    let mut mutations = Vec::new();
    let mut index = 0;

    // Mutation 1: Flip action on each rule
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() {
            let mut mutated = config.clone();
            let flipped = match rule.action() {
                Action::Pass => Action::Drop,
                Action::Drop => Action::Pass,
            };
            mutated.pacgate.rules[i].action = Some(flipped);
            mutations.push((Mutation {
                name: format!("flip_action_{}", rule.name),
                description: format!("Flip action of rule '{}' from {:?} to opposite", rule.name, rule.action()),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 2: Remove each rule
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        let mut mutated = config.clone();
        mutated.pacgate.rules.remove(i);
        mutations.push((Mutation {
            name: format!("remove_{}", rule.name),
            description: format!("Remove rule '{}'", rule.name),
            mutant_index: index,
        }, mutated));
        index += 1;
    }

    // Mutation 3: Swap priorities of adjacent rules
    if config.pacgate.rules.len() >= 2 {
        for i in 0..config.pacgate.rules.len() - 1 {
            let mut mutated = config.clone();
            let pri_a = mutated.pacgate.rules[i].priority;
            let pri_b = mutated.pacgate.rules[i + 1].priority;
            if pri_a != pri_b {
                mutated.pacgate.rules[i].priority = pri_b;
                mutated.pacgate.rules[i + 1].priority = pri_a;
                mutations.push((Mutation {
                    name: format!("swap_priority_{}_{}", mutated.pacgate.rules[i].name, mutated.pacgate.rules[i + 1].name),
                    description: format!("Swap priorities of '{}' ({}) and '{}' ({})",
                        mutated.pacgate.rules[i].name, pri_a,
                        mutated.pacgate.rules[i + 1].name, pri_b),
                    mutant_index: index,
                }, mutated));
                index += 1;
            }
        }
    }

    // Mutation 4: Flip default action
    {
        let mut mutated = config.clone();
        mutated.pacgate.defaults.action = match config.pacgate.defaults.action {
            Action::Pass => Action::Drop,
            Action::Drop => Action::Pass,
        };
        mutations.push((Mutation {
            name: "flip_default_action".to_string(),
            description: format!("Flip default action from {:?} to opposite", config.pacgate.defaults.action),
            mutant_index: index,
        }, mutated));
    }

    // Mutation 5: Remove a match field from each rule
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.ethertype.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.ethertype = None;
            mutations.push((Mutation {
                name: format!("remove_ethertype_{}", rule.name),
                description: format!("Remove ethertype match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 6: Widen src_ip CIDR prefix
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() {
            if let Some(ref ip) = rule.match_criteria.src_ip {
                if let Some(slash_pos) = ip.find('/') {
                    if let Ok(prefix_len) = ip[slash_pos + 1..].parse::<u8>() {
                        if prefix_len > 8 {
                            let mut mutated = config.clone();
                            let addr_part = &ip[..slash_pos];
                            mutated.pacgate.rules[i].match_criteria.src_ip =
                                Some(format!("{}/{}", addr_part, prefix_len - 8));
                            mutations.push((Mutation {
                                name: format!("widen_src_ip_{}", rule.name),
                                description: format!("Widen src_ip CIDR from /{} to /{} in rule '{}'",
                                    prefix_len, prefix_len - 8, rule.name),
                                mutant_index: index,
                            }, mutated));
                            index += 1;
                        }
                    }
                }
            }
        }
    }

    // Mutation 7: Shift dst_port by +1
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() {
            if let Some(PortMatch::Exact(p)) = rule.match_criteria.dst_port {
                if p < 65535 {
                    let mut mutated = config.clone();
                    mutated.pacgate.rules[i].match_criteria.dst_port = Some(PortMatch::Exact(p + 1));
                    mutations.push((Mutation {
                        name: format!("shift_dst_port_{}", rule.name),
                        description: format!("Shift dst_port from {} to {} in rule '{}'",
                            p, p + 1, rule.name),
                        mutant_index: index,
                    }, mutated));
                    index += 1;
                }
            }
        }
    }

    // Mutation 8: Remove gtp_teid
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.gtp_teid.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.gtp_teid = None;
            mutations.push((Mutation {
                name: format!("remove_gtp_teid_{}", rule.name),
                description: format!("Remove gtp_teid match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 9: Remove mpls_label
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.mpls_label.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.mpls_label = None;
            mutations.push((Mutation {
                name: format!("remove_mpls_label_{}", rule.name),
                description: format!("Remove mpls_label match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 10: Remove igmp_type
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.igmp_type.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.igmp_type = None;
            mutations.push((Mutation {
                name: format!("remove_igmp_type_{}", rule.name),
                description: format!("Remove igmp_type match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 11: Remove vxlan_vni
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.vxlan_vni.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.vxlan_vni = None;
            mutations.push((Mutation {
                name: format!("remove_vxlan_vni_{}", rule.name),
                description: format!("Remove vxlan_vni match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 12: Remove ip_dscp
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.ip_dscp.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.ip_dscp = None;
            mutations.push((Mutation {
                name: format!("remove_ip_dscp_{}", rule.name),
                description: format!("Remove ip_dscp match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 13: Remove ip_ecn
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.ip_ecn.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.ip_ecn = None;
            mutations.push((Mutation {
                name: format!("remove_ip_ecn_{}", rule.name),
                description: format!("Remove ip_ecn match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 14: Remove tcp_flags
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.tcp_flags.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.tcp_flags = None;
            mutated.pacgate.rules[i].match_criteria.tcp_flags_mask = None;
            mutations.push((Mutation {
                name: format!("remove_tcp_flags_{}", rule.name),
                description: format!("Remove tcp_flags match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 15: Remove icmp_type
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.icmp_type.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.icmp_type = None;
            mutated.pacgate.rules[i].match_criteria.icmp_code = None;
            mutations.push((Mutation {
                name: format!("remove_icmp_type_{}", rule.name),
                description: format!("Remove icmp_type match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 16: Remove ipv6_dscp
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.ipv6_dscp.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.ipv6_dscp = None;
            mutations.push((Mutation {
                name: format!("remove_ipv6_dscp_{}", rule.name),
                description: format!("Remove ipv6_dscp match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 17: Remove icmpv6_type (also removes icmpv6_code)
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.icmpv6_type.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.icmpv6_type = None;
            mutated.pacgate.rules[i].match_criteria.icmpv6_code = None;
            mutations.push((Mutation {
                name: format!("remove_icmpv6_type_{}", rule.name),
                description: format!("Remove icmpv6_type match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 18: Remove arp_opcode (also removes arp_spa, arp_tpa)
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.arp_opcode.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.arp_opcode = None;
            mutated.pacgate.rules[i].match_criteria.arp_spa = None;
            mutated.pacgate.rules[i].match_criteria.arp_tpa = None;
            mutations.push((Mutation {
                name: format!("remove_arp_opcode_{}", rule.name),
                description: format!("Remove arp_opcode match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 19: Remove ipv6_hop_limit (also removes ipv6_flow_label)
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.ipv6_hop_limit.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.ipv6_hop_limit = None;
            mutated.pacgate.rules[i].match_criteria.ipv6_flow_label = None;
            mutations.push((Mutation {
                name: format!("remove_ipv6_hop_limit_{}", rule.name),
                description: format!("Remove ipv6_hop_limit match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 20: Remove outer_vlan_id (also removes outer_vlan_pcp)
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.outer_vlan_id.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.outer_vlan_id = None;
            mutated.pacgate.rules[i].match_criteria.outer_vlan_pcp = None;
            mutations.push((Mutation {
                name: format!("remove_outer_vlan_id_{}", rule.name),
                description: format!("Remove outer_vlan_id match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 21: Remove ip_frag_offset (also removes ip_dont_fragment, ip_more_fragments)
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.ip_frag_offset.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.ip_frag_offset = None;
            mutated.pacgate.rules[i].match_criteria.ip_dont_fragment = None;
            mutated.pacgate.rules[i].match_criteria.ip_more_fragments = None;
            mutations.push((Mutation {
                name: format!("remove_ip_frag_offset_{}", rule.name),
                description: format!("Remove ip_frag_offset match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 23: Remove gre_protocol (also removes gre_key)
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.gre_protocol.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.gre_protocol = None;
            mutated.pacgate.rules[i].match_criteria.gre_key = None;
            mutations.push((Mutation {
                name: format!("remove_gre_protocol_{}", rule.name),
                description: format!("Remove gre_protocol match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 24: Remove conntrack_state
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.conntrack_state.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.conntrack_state = None;
            mutations.push((Mutation {
                name: format!("remove_conntrack_state_{}", rule.name),
                description: format!("Remove conntrack_state match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 25: Remove mirror_port
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.mirror_port.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].mirror_port = None;
            mutations.push((Mutation {
                name: format!("remove_mirror_port_{}", rule.name),
                description: format!("Remove mirror_port from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 26: Remove redirect_port
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.redirect_port.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].redirect_port = None;
            mutations.push((Mutation {
                name: format!("remove_redirect_port_{}", rule.name),
                description: format!("Remove redirect_port from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 27: Remove flow counters from conntrack config
    if let Some(ref ct) = config.pacgate.conntrack {
        if ct.enable_flow_counters == Some(true) {
            let mut mutated = config.clone();
            if let Some(ref mut mct) = mutated.pacgate.conntrack {
                mct.enable_flow_counters = None;
            }
            mutations.push((Mutation {
                name: "remove_flow_counters".to_string(),
                description: "Remove enable_flow_counters from conntrack config".to_string(),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 28: Remove oam_level (clears both oam_level and oam_opcode)
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.oam_level.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.oam_level = None;
            mutated.pacgate.rules[i].match_criteria.oam_opcode = None;
            mutations.push((Mutation {
                name: format!("remove_oam_level_{}", rule.name),
                description: format!("Remove oam_level match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 29: Remove nsh_spi (clears nsh_spi, nsh_si, and nsh_next_protocol)
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.nsh_spi.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.nsh_spi = None;
            mutated.pacgate.rules[i].match_criteria.nsh_si = None;
            mutated.pacgate.rules[i].match_criteria.nsh_next_protocol = None;
            mutations.push((Mutation {
                name: format!("remove_nsh_spi_{}", rule.name),
                description: format!("Remove nsh_spi match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 22: Remove set_src_port from rewrite actions
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() {
            if let Some(ref rewrite) = rule.rewrite {
                if rewrite.set_src_port.is_some() {
                    let mut mutated = config.clone();
                    if let Some(ref mut rw) = mutated.pacgate.rules[i].rewrite {
                        rw.set_src_port = None;
                    }
                    mutations.push((Mutation {
                        name: format!("remove_set_src_port_{}", rule.name),
                        description: format!("Remove set_src_port rewrite from rule '{}'", rule.name),
                        mutant_index: index,
                    }, mutated));
                    index += 1;
                }
            }
        }
    }

    // Mutation 30: Remove geneve_vni
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.geneve_vni.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.geneve_vni = None;
            mutations.push((Mutation {
                name: format!("remove_geneve_vni_{}", rule.name),
                description: format!("Remove geneve_vni match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 31: Remove ip_ttl
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.ip_ttl.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.ip_ttl = None;
            mutations.push((Mutation {
                name: format!("remove_ip_ttl_{}", rule.name),
                description: format!("Remove ip_ttl match from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 32: Remove dec_hop_limit (clears dec_hop_limit and set_hop_limit)
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() {
            if let Some(ref rw) = rule.rewrite {
                if rw.dec_hop_limit == Some(true) || rw.set_hop_limit.is_some() {
                    let mut mutated = config.clone();
                    if let Some(ref mut mrw) = mutated.pacgate.rules[i].rewrite {
                        mrw.dec_hop_limit = None;
                        mrw.set_hop_limit = None;
                    }
                    mutations.push((Mutation {
                        name: format!("remove_dec_hop_limit_{}", rule.name),
                        description: format!("Remove hop limit rewrite from rule '{}'", rule.name),
                        mutant_index: index,
                    }, mutated));
                    index += 1;
                }
            }
        }
    }

    // Mutation 33: Remove set_vlan_pcp from rewrite actions
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() {
            if let Some(ref rw) = rule.rewrite {
                if rw.set_vlan_pcp.is_some() {
                    let mut mutated = config.clone();
                    if let Some(ref mut mrw) = mutated.pacgate.rules[i].rewrite {
                        mrw.set_vlan_pcp = None;
                    }
                    mutations.push((Mutation {
                        name: format!("remove_set_vlan_pcp_{}", rule.name),
                        description: format!("Remove set_vlan_pcp rewrite from rule '{}'", rule.name),
                        mutant_index: index,
                    }, mutated));
                    index += 1;
                }
            }
        }
    }

    // Mutation 34: Swap pipeline stage order (adjacent stages)
    if let Some(ref tables) = config.pacgate.tables {
        if tables.len() >= 2 {
            for i in 0..tables.len() - 1 {
                let mut mutated = config.clone();
                let tables_mut = mutated.pacgate.tables.as_mut().unwrap();
                tables_mut.swap(i, i + 1);
                mutations.push((Mutation {
                    name: format!("swap_stage_{}_{}", tables[i].name, tables[i + 1].name),
                    description: format!("Swap pipeline stages '{}' and '{}'", tables[i].name, tables[i + 1].name),
                    mutant_index: index,
                }, mutated));
                index += 1;
            }
        }
    }

    // Mutation 35: Remove a pipeline stage
    if let Some(ref tables) = config.pacgate.tables {
        for (i, stage) in tables.iter().enumerate() {
            if tables.len() > 1 {
                let mut mutated = config.clone();
                mutated.pacgate.tables.as_mut().unwrap().remove(i);
                mutations.push((Mutation {
                    name: format!("remove_stage_{}", stage.name),
                    description: format!("Remove pipeline stage '{}'", stage.name),
                    mutant_index: index,
                }, mutated));
                index += 1;
            }
        }
    }

    // Mutation 36: Remove ptp_message_type from a PTP rule
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() && rule.match_criteria.ptp_message_type.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].match_criteria.ptp_message_type = None;
            mutations.push((Mutation {
                name: format!("remove_ptp_message_type_{}", rule.name),
                description: format!("Remove ptp_message_type from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 37: Shift ptp_domain value
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if !rule.is_stateful() {
            if let Some(dom) = rule.match_criteria.ptp_domain {
                let new_dom = if dom < 255 { dom + 1 } else { 0 };
                let mut mutated = config.clone();
                mutated.pacgate.rules[i].match_criteria.ptp_domain = Some(new_dom);
                mutations.push((Mutation {
                    name: format!("shift_ptp_domain_{}", rule.name),
                    description: format!("Shift ptp_domain from {} to {} in rule '{}'", dom, new_dom, rule.name),
                    mutant_index: index,
                }, mutated));
                index += 1;
            }
        }
    }

    // Mutation 38: Remove rss_queue from a rule
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if rule.rss_queue.is_some() {
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].rss_queue = None;
            mutations.push((Mutation {
                name: format!("remove_rss_queue_{}", rule.name),
                description: format!("Remove rss_queue from rule '{}'", rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    // Mutation 39: Shift rss_queue value
    for (i, rule) in config.pacgate.rules.iter().enumerate() {
        if let Some(q) = rule.rss_queue {
            let new_q = if q < 15 { q + 1 } else { 0 };
            let mut mutated = config.clone();
            mutated.pacgate.rules[i].rss_queue = Some(new_q);
            mutations.push((Mutation {
                name: format!("shift_rss_queue_{}", rule.name),
                description: format!("Shift rss_queue from {} to {} in rule '{}'", q, new_q, rule.name),
                mutant_index: index,
            }, mutated));
            index += 1;
        }
    }

    mutations
}

/// Generate a JSON mutation report
pub fn generate_mutation_report(config: &FilterConfig) -> serde_json::Value {
    let mutations = generate_mutations(config);
    let mutation_info: Vec<serde_json::Value> = mutations.iter().map(|(m, _)| {
        serde_json::json!({
            "name": m.name,
            "description": m.description,
            "index": m.mutant_index,
        })
    }).collect();

    serde_json::json!({
        "status": "ok",
        "total_mutations": mutations.len(),
        "mutations": mutation_info,
        "instructions": "Each mutant should fail at least one test. Surviving mutants indicate test gaps.",
    })
}

/// Result of running a single mutant's tests
#[derive(Debug, Clone, serde::Serialize)]
pub struct MutantResult {
    pub name: String,
    pub status: String, // "killed", "survived", "error"
    pub description: String,
}

/// Aggregated mutation testing report
#[derive(Debug, Clone, serde::Serialize)]
pub struct MutationTestReport {
    pub total: usize,
    pub killed: usize,
    pub survived: usize,
    pub errors: usize,
    pub kill_rate: f64,
    pub details: Vec<MutantResult>,
}

/// Run mutation tests: compile and lint each mutant, report kill rate
///
/// For each mutant directory in output_dir/mutants/mut_N/:
/// - Check if iverilog is available
/// - Run iverilog lint on generated Verilog
/// - Track whether the mutant would be killed (lint failure = killed for now)
/// - Return aggregated report
pub fn run_mutation_tests(
    config: &FilterConfig,
    templates_dir: &std::path::Path,
    output_dir: &std::path::Path,
) -> MutationTestReport {
    let mutations = generate_mutations(config);
    let mutants_dir = output_dir.join("mutants");
    let _ = std::fs::create_dir_all(&mutants_dir);

    // Check if iverilog is available
    let iverilog_available = std::process::Command::new("iverilog")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let mut details = Vec::new();
    let mut killed = 0usize;
    let mut survived = 0usize;
    let mut errors = 0usize;

    for (i, (m, mutated_config)) in mutations.iter().enumerate() {
        let mutant_dir = mutants_dir.join(format!("mut_{}", i));
        let _ = std::fs::create_dir_all(&mutant_dir);

        // Write mutated YAML
        if let Ok(yaml) = serde_yaml::to_string(&mutated_config) {
            let _ = std::fs::write(mutant_dir.join("rules.yaml"), &yaml);
        }

        // Generate mutated Verilog + tests
        let verilog_ok = crate::verilog_gen::generate(mutated_config, templates_dir, &mutant_dir).is_ok();
        let cocotb_ok = crate::cocotb_gen::generate(mutated_config, templates_dir, &mutant_dir).is_ok();

        if !verilog_ok || !cocotb_ok {
            // Generation failed — counts as error (mutation too severe)
            errors += 1;
            details.push(MutantResult {
                name: m.name.clone(),
                status: "error".to_string(),
                description: format!("{} — generation failed", m.description),
            });
            continue;
        }

        // If iverilog is available, lint the mutant Verilog
        if iverilog_available {
            let rtl_dir = mutant_dir.join("rtl");
            if rtl_dir.exists() {
                let mut verilog_files: Vec<String> = Vec::new();
                if let Ok(entries) = std::fs::read_dir(&rtl_dir) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        if entry.path().extension().map(|x| x == "v").unwrap_or(false) {
                            verilog_files.push(entry.path().to_string_lossy().to_string());
                        }
                    }
                }

                if !verilog_files.is_empty() {
                    let lint_result = std::process::Command::new("iverilog")
                        .arg("-g2012")
                        .arg("-o")
                        .arg("/dev/null")
                        .args(&verilog_files)
                        .arg("rtl/frame_parser.v")
                        .output();

                    match lint_result {
                        Ok(output) if !output.status.success() => {
                            // Lint failed — mutation killed
                            killed += 1;
                            details.push(MutantResult {
                                name: m.name.clone(),
                                status: "killed".to_string(),
                                description: format!("{} — lint failed (killed)", m.description),
                            });
                            continue;
                        }
                        Err(_) => {
                            errors += 1;
                            details.push(MutantResult {
                                name: m.name.clone(),
                                status: "error".to_string(),
                                description: format!("{} — lint error", m.description),
                            });
                            continue;
                        }
                        _ => {}
                    }
                }
            }
        }

        // If we get here, mutant survived (or we can't tell without full sim)
        survived += 1;
        details.push(MutantResult {
            name: m.name.clone(),
            status: "survived".to_string(),
            description: format!("{} — survived (needs cocotb sim to verify)", m.description),
        });
    }

    let total = details.len();
    let kill_rate = if total > 0 { killed as f64 / total as f64 * 100.0 } else { 0.0 };

    MutationTestReport {
        total,
        killed,
        survived,
        errors,
        kill_rate,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn make_test_config() -> FilterConfig {
        FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
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
                        rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                    StatelessRule {
                        name: "allow_ipv4".to_string(),
                        priority: 90,
                        match_criteria: MatchCriteria {
                            ethertype: Some("0x0800".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None,
                        fsm: None,
                        ports: None,
                        rate_limit: None,
                        rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        }
    }

    #[test]
    fn generate_mutations_creates_variants() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        assert!(mutations.len() >= 4, "expected at least 4 mutations, got {}", mutations.len());
    }

    #[test]
    fn flip_action_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let flip = mutations.iter().find(|(m, _)| m.name.starts_with("flip_action_")).unwrap();
        let mutated = &flip.1;
        // At least one rule should have opposite action from original
        assert!(mutated.pacgate.rules.iter().any(|r| r.action() == Action::Drop));
    }

    #[test]
    fn remove_rule_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let remove = mutations.iter().find(|(m, _)| m.name.starts_with("remove_")).unwrap();
        assert_eq!(remove.1.pacgate.rules.len(), 1);
    }

    #[test]
    fn swap_priority_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let swap = mutations.iter().find(|(m, _)| m.name.starts_with("swap_priority_"));
        assert!(swap.is_some(), "should generate priority swap mutation");
    }

    #[test]
    fn flip_default_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let flip = mutations.iter().find(|(m, _)| m.name == "flip_default_action").unwrap();
        assert_eq!(flip.1.pacgate.defaults.action, Action::Pass);
    }

    #[test]
    fn mutation_report_json() {
        let config = make_test_config();
        let report = generate_mutation_report(&config);
        assert_eq!(report["status"], "ok");
        assert!(report["total_mutations"].as_u64().unwrap() > 0);
        assert!(report["mutations"].is_array());
    }

    #[test]
    fn remove_ethertype_mutation() {
        let config = make_test_config();
        let mutations = generate_mutations(&config);
        let rm_et = mutations.iter().find(|(m, _)| m.name.starts_with("remove_ethertype_")).unwrap();
        let mutated_rule = &rm_et.1.pacgate.rules.iter()
            .find(|r| r.name == "allow_arp")
            .unwrap();
        assert!(mutated_rule.match_criteria.ethertype.is_none() ||
                rm_et.0.name.contains("allow_ipv4"));
    }

    #[test]
    fn widen_src_ip_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "subnet_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            src_ip: Some("10.0.0.0/24".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let widen = mutations.iter().find(|(m, _)| m.name.starts_with("widen_src_ip_")).unwrap();
        let mutated_ip = widen.1.pacgate.rules[0].match_criteria.src_ip.as_ref().unwrap();
        assert!(mutated_ip.ends_with("/16"), "expected /16, got {}", mutated_ip);
    }

    #[test]
    fn shift_dst_port_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "web_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            dst_port: Some(PortMatch::Exact(80)),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let shift = mutations.iter().find(|(m, _)| m.name.starts_with("shift_dst_port_")).unwrap();
        assert_eq!(shift.1.pacgate.rules[0].match_criteria.dst_port, Some(PortMatch::Exact(81)));
    }

    #[test]
    fn remove_gtp_teid_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "gtp_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            gtp_teid: Some(1000),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_gtp_teid_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.gtp_teid.is_none());
    }

    #[test]
    fn remove_ip_dscp_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "dscp_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ip_dscp: Some(46),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_ip_dscp_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.ip_dscp.is_none());
    }

    #[test]
    fn remove_ip_ecn_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "ecn_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ip_ecn: Some(1),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_ip_ecn_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.ip_ecn.is_none());
    }

    #[test]
    fn remove_mpls_label_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "mpls_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            mpls_label: Some(100),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_mpls_label_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.mpls_label.is_none());
    }

    #[test]
    fn remove_tcp_flags_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "syn_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            tcp_flags: Some(0x02),
                            tcp_flags_mask: Some(0x12),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_tcp_flags_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.tcp_flags.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.tcp_flags_mask.is_none());
    }

    #[test]
    fn remove_icmp_type_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "echo_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            icmp_type: Some(8),
                            icmp_code: Some(0),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_icmp_type_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.icmp_type.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.icmp_code.is_none());
    }

    #[test]
    fn remove_ipv6_dscp_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "ipv6_ef_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ipv6_dscp: Some(46),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_ipv6_dscp_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.ipv6_dscp.is_none());
    }

    #[test]
    fn remove_icmpv6_type_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "ndp_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            icmpv6_type: Some(135),
                            icmpv6_code: Some(0),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_icmpv6_type_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.icmpv6_type.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.icmpv6_code.is_none());
    }

    #[test]
    fn remove_arp_opcode_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "arp_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            arp_opcode: Some(1),
                            arp_spa: Some("10.0.0.1".to_string()),
                            arp_tpa: Some("10.0.0.2".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_arp_opcode_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.arp_opcode.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.arp_spa.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.arp_tpa.is_none());
    }

    #[test]
    fn remove_ipv6_hop_limit_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "hop_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ipv6_hop_limit: Some(64),
                            ipv6_flow_label: Some(12345),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_ipv6_hop_limit_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.ipv6_hop_limit.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.ipv6_flow_label.is_none());
    }

    #[test]
    fn remove_outer_vlan_id_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "qinq_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            outer_vlan_id: Some(100),
                            outer_vlan_pcp: Some(5),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_outer_vlan_id_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.outer_vlan_id.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.outer_vlan_pcp.is_none());
    }

    #[test]
    fn remove_ip_frag_offset_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "frag_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ip_frag_offset: Some(185),
                            ip_dont_fragment: Some(false),
                            ip_more_fragments: Some(true),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_ip_frag_offset_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.ip_frag_offset.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.ip_dont_fragment.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.ip_more_fragments.is_none());
    }

    #[test]
    fn remove_gre_protocol_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "gre_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            gre_protocol: Some(0x0800),
                            gre_key: Some(12345),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_gre_protocol_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.gre_protocol.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.gre_key.is_none());
    }

    #[test]
    fn remove_conntrack_state_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "ct_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            conntrack_state: Some("established".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_conntrack_state_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.conntrack_state.is_none());
    }

    #[test]
    fn remove_set_src_port_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "port_rewrite_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None,
                        fsm: None,
                        ports: None,
                        rate_limit: None,
                        rewrite: Some(RewriteAction {
                            set_src_port: Some(8080),
                            set_dst_mac: None,
                            set_src_mac: None,
                            set_vlan_id: None,
                            set_ttl: None,
                            dec_ttl: None,
                            set_src_ip: None,
                            set_dst_ip: None,
                            set_dscp: None,
                            set_dst_port: None,
                            dec_hop_limit: None,
                            set_hop_limit: None,
                            set_ecn: None,
                            set_vlan_pcp: None,
                            set_outer_vlan_id: None,
                        }),
                        mirror_port: None,
                        redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_set_src_port_")).unwrap();
        assert!(rm.1.pacgate.rules[0].rewrite.as_ref().unwrap().set_src_port.is_none());
    }

    #[test]
    fn remove_mirror_port_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "mirror_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ethertype: Some("0x0800".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None,
                        mirror_port: Some(2),
                        redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_mirror_port_")).unwrap();
        assert!(rm.1.pacgate.rules[0].mirror_port.is_none());
    }

    #[test]
    fn remove_redirect_port_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "redirect_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ethertype: Some("0x0800".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None,
                        mirror_port: None,
                        redirect_port: Some(5),
                        rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_redirect_port_")).unwrap();
        assert!(rm.1.pacgate.rules[0].redirect_port.is_none());
    }

    #[test]
    fn remove_flow_counters_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "test_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ethertype: Some("0x0800".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None,
                        mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: Some(ConntrackConfig {
                    table_size: 1024,
                    timeout_cycles: 100000,
                    fields: vec![
                        "src_ip".to_string(), "dst_ip".to_string(),
                        "ip_protocol".to_string(), "src_port".to_string(), "dst_port".to_string(),
                    ],
                    enable_flow_counters: Some(true),
                }),
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name == "remove_flow_counters").unwrap();
        assert!(rm.1.pacgate.conntrack.as_ref().unwrap().enable_flow_counters.is_none());
    }

    #[test]
    fn remove_oam_level_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "oam_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            oam_level: Some(3),
                            oam_opcode: Some(1),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_oam_level_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.oam_level.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.oam_opcode.is_none());
    }

    #[test]
    fn remove_nsh_spi_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "nsh_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            nsh_spi: Some(100),
                            nsh_si: Some(255),
                            nsh_next_protocol: Some(1),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_nsh_spi_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.nsh_spi.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.nsh_si.is_none());
        assert!(rm.1.pacgate.rules[0].match_criteria.nsh_next_protocol.is_none());
    }

    #[test]
    fn no_remove_flow_counters_when_disabled() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "test_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ethertype: Some("0x0800".to_string()),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None,
                        mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: Some(ConntrackConfig {
                    table_size: 1024,
                    timeout_cycles: 100000,
                    fields: vec![
                        "src_ip".to_string(), "dst_ip".to_string(),
                        "ip_protocol".to_string(), "src_port".to_string(), "dst_port".to_string(),
                    ],
                    enable_flow_counters: None,
                }),
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        assert!(mutations.iter().find(|(m, _)| m.name == "remove_flow_counters").is_none());
    }

    #[test]
    fn remove_geneve_vni_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "geneve_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            geneve_vni: Some(5000),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_geneve_vni_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.geneve_vni.is_none());
    }

    #[test]
    fn remove_ip_ttl_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "ttl_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ip_ttl: Some(64),
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None, fsm: None, ports: None, rate_limit: None, rewrite: None, mirror_port: None, redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_ip_ttl_")).unwrap();
        assert!(rm.1.pacgate.rules[0].match_criteria.ip_ttl.is_none());
    }

    #[test]
    fn remove_dec_hop_limit_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "hop_rewrite_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None,
                        fsm: None,
                        ports: None,
                        rate_limit: None,
                        rewrite: Some(RewriteAction {
                            dec_hop_limit: Some(true),
                            set_hop_limit: None,
                            set_dst_mac: None,
                            set_src_mac: None,
                            set_vlan_id: None,
                            set_ttl: None,
                            dec_ttl: None,
                            set_src_ip: None,
                            set_dst_ip: None,
                            set_dscp: None,
                            set_src_port: None,
                            set_dst_port: None,
                            set_ecn: None,
                            set_vlan_pcp: None,
                            set_outer_vlan_id: None,
                        }),
                        mirror_port: None,
                        redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_dec_hop_limit_")).unwrap();
        assert!(rm.1.pacgate.rules[0].rewrite.as_ref().unwrap().dec_hop_limit.is_none());
        assert!(rm.1.pacgate.rules[0].rewrite.as_ref().unwrap().set_hop_limit.is_none());
    }

    #[test]
    fn remove_set_vlan_pcp_mutation() {
        let config = FilterConfig {
            pacgate: PacgateConfig {
                version: "1.0".to_string(),
                defaults: Defaults { action: Action::Drop },
                rules: vec![
                    StatelessRule {
                        name: "vlan_pcp_rule".to_string(),
                        priority: 100,
                        match_criteria: MatchCriteria {
                            ..Default::default()
                        },
                        action: Some(Action::Pass),
                        rule_type: None,
                        fsm: None,
                        ports: None,
                        rate_limit: None,
                        rewrite: Some(RewriteAction {
                            set_vlan_pcp: Some(6),
                            set_dst_mac: None,
                            set_src_mac: None,
                            set_vlan_id: None,
                            set_ttl: None,
                            dec_ttl: None,
                            set_src_ip: None,
                            set_dst_ip: None,
                            set_dscp: None,
                            set_src_port: None,
                            set_dst_port: None,
                            dec_hop_limit: None,
                            set_hop_limit: None,
                            set_ecn: None,
                            set_outer_vlan_id: None,
                        }),
                        mirror_port: None,
                        redirect_port: None, rss_queue: None,
                    },
                ],
                conntrack: None,
                tables: None,
            },
        };
        let mutations = generate_mutations(&config);
        let rm = mutations.iter().find(|(m, _)| m.name.starts_with("remove_set_vlan_pcp_")).unwrap();
        assert!(rm.1.pacgate.rules[0].rewrite.as_ref().unwrap().set_vlan_pcp.is_none());
    }
}
