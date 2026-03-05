// Wireshark Display Filter Import: Parse Wireshark display filter syntax into PacGate FilterConfig
//
// Converts filters like "tcp.port == 80 && ip.src == 10.0.0.0/8" into YAML rules.
// Tokenizer → recursive descent parser → field mapper → AST-to-rules converter.

use anyhow::{bail, Result};

use crate::model::*;

// ============================================================
// Tokens
// ============================================================

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Field(String),
    IntLit(u64),
    StringLit(String),
    Op(CompareOp),
    And,
    Or,
    Not,
    In,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    DotDot,
    Eof,
}

#[derive(Debug, Clone, PartialEq)]
enum CompareOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

// ============================================================
// Tokenizer
// ============================================================

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Skip whitespace
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }

        // Two-character operators
        if i + 1 < len {
            let two = format!("{}{}", chars[i], chars[i + 1]);
            match two.as_str() {
                "==" => { tokens.push(Token::Op(CompareOp::Eq)); i += 2; continue; }
                "!=" => { tokens.push(Token::Op(CompareOp::Ne)); i += 2; continue; }
                ">=" => { tokens.push(Token::Op(CompareOp::Ge)); i += 2; continue; }
                "<=" => { tokens.push(Token::Op(CompareOp::Le)); i += 2; continue; }
                "&&" => { tokens.push(Token::And); i += 2; continue; }
                "||" => { tokens.push(Token::Or); i += 2; continue; }
                ".." => { tokens.push(Token::DotDot); i += 2; continue; }
                _ => {}
            }
        }

        // Single-character tokens
        match chars[i] {
            '(' => { tokens.push(Token::LParen); i += 1; continue; }
            ')' => { tokens.push(Token::RParen); i += 1; continue; }
            '{' => { tokens.push(Token::LBrace); i += 1; continue; }
            '}' => { tokens.push(Token::RBrace); i += 1; continue; }
            ',' => { tokens.push(Token::Comma); i += 1; continue; }
            '!' => { tokens.push(Token::Not); i += 1; continue; }
            '>' => { tokens.push(Token::Op(CompareOp::Gt)); i += 1; continue; }
            '<' => { tokens.push(Token::Op(CompareOp::Lt)); i += 1; continue; }
            _ => {}
        }

        // Hex literal: 0x...
        if chars[i] == '0' && i + 1 < len && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
            let start = i;
            i += 2;
            while i < len && chars[i].is_ascii_hexdigit() {
                i += 1;
            }
            let hex_str = &input[start + 2..i];
            if hex_str.is_empty() {
                bail!("Empty hex literal at position {}", start);
            }
            tokens.push(Token::IntLit(u64::from_str_radix(hex_str, 16)?));
            continue;
        }

        // Number (decimal), but be careful — could be an IP address or MAC
        if chars[i].is_ascii_digit() {
            // Look ahead to determine if this is an IP/CIDR, MAC, or plain number
            let start = i;
            // Collect the full token including dots, colons, slashes, hex digits
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '.' || chars[i] == ':' || chars[i] == '/') {
                i += 1;
            }
            let token_str = &input[start..i];

            if token_str.contains(':') {
                // MAC address (e.g., "aa:bb:cc:dd:ee:ff") or IPv6
                tokens.push(Token::StringLit(token_str.to_string()));
            } else if token_str.contains('/') || (token_str.contains('.') && token_str.matches('.').count() == 3) {
                // IPv4 CIDR (e.g., "10.0.0.0/8") or dotted-quad (e.g., "192.168.1.1")
                tokens.push(Token::StringLit(token_str.to_string()));
            } else if token_str.contains('.') {
                // Could be a partial IP-like thing — treat as string
                tokens.push(Token::StringLit(token_str.to_string()));
            } else {
                // Plain decimal number
                let val: u64 = token_str.parse()
                    .map_err(|_| anyhow::anyhow!("Invalid number: '{}'", token_str))?;
                tokens.push(Token::IntLit(val));
            }
            continue;
        }

        // Identifiers, keywords, and MAC/IPv6 addresses starting with hex letter
        if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
            let start = i;
            // First pass: collect alphanumeric + underscore + dot (field name or hex prefix)
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '.') {
                i += 1;
            }
            // Check if this continues with colon (MAC address like aa:bb:cc:dd:ee:ff or IPv6)
            if i < len && chars[i] == ':' && i > start {
                let prefix = &input[start..i];
                // If prefix looks like hex digits only (no dots/underscores), could be MAC/IPv6
                if prefix.chars().all(|c| c.is_ascii_hexdigit()) {
                    // Extend to include colons and hex digits
                    while i < len && (chars[i].is_ascii_hexdigit() || chars[i] == ':' || chars[i] == '/') {
                        i += 1;
                    }
                    tokens.push(Token::StringLit(input[start..i].to_string()));
                    continue;
                }
            }
            let word = &input[start..i];
            match word.to_lowercase().as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                "in" => tokens.push(Token::In),
                "true" => tokens.push(Token::IntLit(1)),
                "false" => tokens.push(Token::IntLit(0)),
                _ => tokens.push(Token::Field(word.to_string())),
            }
            continue;
        }

        bail!("Unexpected character '{}' at position {}", chars[i], i);
    }

    tokens.push(Token::Eof);
    Ok(tokens)
}

// ============================================================
// AST
// ============================================================

#[derive(Debug, Clone)]
enum FilterExpr {
    Comparison { field: String, op: CompareOp, value: FilterValue },
    ProtocolPresence(String),
    InSet { field: String, values: Vec<FilterValue> },
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
}

#[derive(Debug, Clone)]
enum FilterValue {
    Integer(u64),
    Str(String),
}

impl FilterValue {
    fn as_u64(&self) -> Result<u64> {
        match self {
            FilterValue::Integer(v) => Ok(*v),
            FilterValue::Str(s) => {
                if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    Ok(u64::from_str_radix(hex, 16)?)
                } else {
                    s.parse::<u64>().map_err(|_| anyhow::anyhow!("Expected integer, got '{}'", s))
                }
            }
        }
    }

    fn as_str(&self) -> String {
        match self {
            FilterValue::Integer(v) => v.to_string(),
            FilterValue::Str(s) => s.clone(),
        }
    }
}

// ============================================================
// Parser — recursive descent, precedence: NOT > AND > OR
// ============================================================

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        tok
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        let tok = self.advance();
        if std::mem::discriminant(&tok) != std::mem::discriminant(expected) {
            bail!("Expected {:?}, got {:?}", expected, tok);
        }
        Ok(())
    }

    fn parse(&mut self) -> Result<FilterExpr> {
        let expr = self.parse_or()?;
        if *self.peek() != Token::Eof {
            bail!("Unexpected token after expression: {:?}", self.peek());
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<FilterExpr> {
        let mut left = self.parse_and()?;
        while *self.peek() == Token::Or {
            self.advance();
            let right = self.parse_and()?;
            left = FilterExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<FilterExpr> {
        let mut left = self.parse_not()?;
        while *self.peek() == Token::And {
            self.advance();
            let right = self.parse_not()?;
            left = FilterExpr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<FilterExpr> {
        if *self.peek() == Token::Not {
            self.advance();
            let expr = self.parse_not()?;
            return Ok(FilterExpr::Not(Box::new(expr)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<FilterExpr> {
        if *self.peek() == Token::LParen {
            self.advance();
            let expr = self.parse_or()?;
            self.expect(&Token::RParen)?;
            return Ok(expr);
        }

        match self.advance() {
            Token::Field(field) => {
                match self.peek().clone() {
                    Token::Op(op) => {
                        self.advance();
                        let value = self.parse_value()?;
                        Ok(FilterExpr::Comparison { field, op, value })
                    }
                    Token::In => {
                        self.advance();
                        self.expect(&Token::LBrace)?;
                        let mut values = Vec::new();
                        loop {
                            if *self.peek() == Token::RBrace {
                                break;
                            }
                            values.push(self.parse_value()?);
                            if *self.peek() == Token::Comma {
                                self.advance();
                            }
                        }
                        self.expect(&Token::RBrace)?;
                        // Check for range syntax: "in { low .. high }"
                        if values.len() == 1 {
                            if let Token::DotDot = self.peek() {
                                // Actually, range is inside braces as "low .. high"
                                // Already consumed, won't happen here. Keep InSet.
                            }
                        }
                        Ok(FilterExpr::InSet { field, values })
                    }
                    _ => {
                        // Bare field name = protocol presence
                        Ok(FilterExpr::ProtocolPresence(field))
                    }
                }
            }
            other => bail!("Expected field name or '(', got {:?}", other),
        }
    }

    fn parse_value(&mut self) -> Result<FilterValue> {
        match self.advance() {
            Token::IntLit(v) => Ok(FilterValue::Integer(v)),
            Token::StringLit(s) => Ok(FilterValue::Str(s)),
            Token::Field(f) => {
                // Bare identifiers can be values in some contexts (e.g., "true", "false")
                Ok(FilterValue::Str(f))
            }
            other => bail!("Expected value, got {:?}", other),
        }
    }
}

fn parse_filter(input: &str) -> Result<FilterExpr> {
    let tokens = tokenize(input)?;
    let mut parser = Parser::new(tokens);
    parser.parse()
}

// ============================================================
// Field mapper: Wireshark field → PacGate MatchCriteria
// ============================================================

/// Result of mapping a field — may produce multiple rules for bidirectional fields
#[derive(Debug)]
enum FieldMapResult {
    /// Single rule modification
    Single,
    /// Bidirectional field needs OR expansion (tcp.port / udp.port)
    Bidirectional { src_field: String, dst_field: String },
}

fn apply_wireshark_field(
    mc: &mut MatchCriteria,
    field: &str,
    op: &CompareOp,
    value: &FilterValue,
    warnings: &mut Vec<String>,
) -> Result<FieldMapResult> {
    match field {
        // ---- L2 ----
        "eth.dst" => {
            mc.dst_mac = Some(value.as_str());
            Ok(FieldMapResult::Single)
        }
        "eth.src" => {
            mc.src_mac = Some(value.as_str());
            Ok(FieldMapResult::Single)
        }
        "eth.type" => {
            let v = value.as_u64()?;
            mc.ethertype = Some(format!("0x{:04X}", v));
            Ok(FieldMapResult::Single)
        }

        // ---- VLAN ----
        "vlan.id" => {
            mc.vlan_id = Some(value.as_u64()? as u16);
            Ok(FieldMapResult::Single)
        }
        "vlan.priority" => {
            mc.vlan_pcp = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }

        // ---- IPv4 ----
        "ip.src" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.src_ip = Some(value.as_str());
            Ok(FieldMapResult::Single)
        }
        "ip.dst" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.dst_ip = Some(value.as_str());
            Ok(FieldMapResult::Single)
        }
        "ip.proto" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_protocol = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }
        "ip.ttl" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_ttl = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }
        "ip.dsfield.dscp" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_dscp = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }
        "ip.dsfield.ecn" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_ecn = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }
        "ip.flags.df" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_dont_fragment = Some(value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }
        "ip.flags.mf" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_more_fragments = Some(value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }
        "ip.frag_offset" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_frag_offset = Some(value.as_u64()? as u16);
            Ok(FieldMapResult::Single)
        }

        // ---- TCP ----
        "tcp.srcport" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_port_match(&mut mc.src_port, op, value)?;
            Ok(FieldMapResult::Single)
        }
        "tcp.dstport" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_port_match(&mut mc.dst_port, op, value)?;
            Ok(FieldMapResult::Single)
        }
        "tcp.port" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            Ok(FieldMapResult::Bidirectional {
                src_field: "tcp.srcport".to_string(),
                dst_field: "tcp.dstport".to_string(),
            })
        }
        "tcp.flags" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            let v = value.as_u64()? as u8;
            mc.tcp_flags = Some(v);
            mc.tcp_flags_mask = Some(0xFF);
            Ok(FieldMapResult::Single)
        }
        "tcp.flags.syn" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_tcp_flag_bit(mc, 1, value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }
        "tcp.flags.ack" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_tcp_flag_bit(mc, 4, value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }
        "tcp.flags.fin" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_tcp_flag_bit(mc, 0, value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }
        "tcp.flags.rst" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_tcp_flag_bit(mc, 2, value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }
        "tcp.flags.push" | "tcp.flags.psh" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_tcp_flag_bit(mc, 3, value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }
        "tcp.flags.urg" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_tcp_flag_bit(mc, 5, value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }
        "tcp.flags.ece" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_tcp_flag_bit(mc, 6, value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }
        "tcp.flags.cwr" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(6); }
            apply_tcp_flag_bit(mc, 7, value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }

        // ---- UDP ----
        "udp.srcport" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(17); }
            apply_port_match(&mut mc.src_port, op, value)?;
            Ok(FieldMapResult::Single)
        }
        "udp.dstport" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(17); }
            apply_port_match(&mut mc.dst_port, op, value)?;
            Ok(FieldMapResult::Single)
        }
        "udp.port" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(17); }
            Ok(FieldMapResult::Bidirectional {
                src_field: "udp.srcport".to_string(),
                dst_field: "udp.dstport".to_string(),
            })
        }

        // ---- ICMP ----
        "icmp.type" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(1); }
            mc.icmp_type = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }
        "icmp.code" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(1); }
            mc.icmp_code = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }

        // ---- ICMPv6 ----
        "icmpv6.type" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x86DD".to_string()); }
            if mc.ipv6_next_header.is_none() { mc.ipv6_next_header = Some(58); }
            mc.icmpv6_type = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }
        "icmpv6.code" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x86DD".to_string()); }
            if mc.ipv6_next_header.is_none() { mc.ipv6_next_header = Some(58); }
            mc.icmpv6_code = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }

        // ---- ARP ----
        "arp.opcode" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0806".to_string()); }
            mc.arp_opcode = Some(value.as_u64()? as u16);
            Ok(FieldMapResult::Single)
        }
        "arp.src.proto_ipv4" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0806".to_string()); }
            mc.arp_spa = Some(value.as_str());
            Ok(FieldMapResult::Single)
        }
        "arp.dst.proto_ipv4" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0806".to_string()); }
            mc.arp_tpa = Some(value.as_str());
            Ok(FieldMapResult::Single)
        }

        // ---- IPv6 ----
        "ipv6.src" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x86DD".to_string()); }
            mc.src_ipv6 = Some(value.as_str());
            Ok(FieldMapResult::Single)
        }
        "ipv6.dst" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x86DD".to_string()); }
            mc.dst_ipv6 = Some(value.as_str());
            Ok(FieldMapResult::Single)
        }
        "ipv6.nxt" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x86DD".to_string()); }
            mc.ipv6_next_header = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }
        "ipv6.hlim" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x86DD".to_string()); }
            mc.ipv6_hop_limit = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }
        "ipv6.flow" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x86DD".to_string()); }
            mc.ipv6_flow_label = Some(value.as_u64()? as u32);
            Ok(FieldMapResult::Single)
        }

        // ---- GRE ----
        "gre.proto" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(47); }
            let v = value.as_u64()? as u16;
            mc.gre_protocol = Some(v);
            Ok(FieldMapResult::Single)
        }
        "gre.key" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            if mc.ip_protocol.is_none() { mc.ip_protocol = Some(47); }
            mc.gre_key = Some(value.as_u64()? as u32);
            Ok(FieldMapResult::Single)
        }

        // ---- MPLS ----
        "mpls.label" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x8847".to_string()); }
            mc.mpls_label = Some(value.as_u64()? as u32);
            Ok(FieldMapResult::Single)
        }
        "mpls.exp" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x8847".to_string()); }
            mc.mpls_tc = Some(value.as_u64()? as u8);
            Ok(FieldMapResult::Single)
        }
        "mpls.bottom" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x8847".to_string()); }
            mc.mpls_bos = Some(value.as_u64()? != 0);
            Ok(FieldMapResult::Single)
        }

        // ---- Tunnels ----
        "vxlan.vni" => {
            mc.vxlan_vni = Some(value.as_u64()? as u32);
            Ok(FieldMapResult::Single)
        }
        "geneve.vni" => {
            mc.geneve_vni = Some(value.as_u64()? as u32);
            Ok(FieldMapResult::Single)
        }

        // ---- Frame length ----
        "frame.len" => {
            let v = value.as_u64()? as u16;
            match op {
                CompareOp::Eq => {
                    mc.frame_len_min = Some(v);
                    mc.frame_len_max = Some(v);
                }
                CompareOp::Ge => { mc.frame_len_min = Some(v); }
                CompareOp::Le => { mc.frame_len_max = Some(v); }
                CompareOp::Gt => { mc.frame_len_min = Some(v + 1); }
                CompareOp::Lt => {
                    if v > 0 { mc.frame_len_max = Some(v - 1); }
                }
                CompareOp::Ne => {
                    warnings.push(format!("frame.len != {} not directly supported, skipping", v));
                }
            }
            Ok(FieldMapResult::Single)
        }

        _ => {
            warnings.push(format!("Unsupported Wireshark field '{}', skipping", field));
            Ok(FieldMapResult::Single)
        }
    }
}

/// Apply a port comparison with range support
fn apply_port_match(port: &mut Option<PortMatch>, op: &CompareOp, value: &FilterValue) -> Result<()> {
    let v = value.as_u64()? as u16;
    match op {
        CompareOp::Eq => { *port = Some(PortMatch::Exact(v)); }
        CompareOp::Ge => { *port = Some(PortMatch::Range { range: [v, 65535] }); }
        CompareOp::Le => { *port = Some(PortMatch::Range { range: [0, v] }); }
        CompareOp::Gt => { *port = Some(PortMatch::Range { range: [v + 1, 65535] }); }
        CompareOp::Lt => {
            if v > 0 {
                *port = Some(PortMatch::Range { range: [0, v - 1] });
            }
        }
        CompareOp::Ne => {
            // Can't represent != in a single range — skip with implied warning
            return Ok(());
        }
    }
    Ok(())
}

/// Accumulate a TCP flag bit into tcp_flags and tcp_flags_mask
fn apply_tcp_flag_bit(mc: &mut MatchCriteria, bit: u8, set: bool) {
    let current_flags = mc.tcp_flags.unwrap_or(0);
    let current_mask = mc.tcp_flags_mask.unwrap_or(0);
    let bit_val = 1u8 << bit;
    mc.tcp_flags_mask = Some(current_mask | bit_val);
    if set {
        mc.tcp_flags = Some(current_flags | bit_val);
    } else {
        mc.tcp_flags = Some(current_flags & !bit_val);
    }
}

/// Apply protocol presence: bare "arp", "tcp", etc.
fn apply_protocol_presence(mc: &mut MatchCriteria, protocol: &str) -> Result<bool> {
    match protocol {
        "arp" => {
            mc.ethertype = Some("0x0806".to_string());
            Ok(true)
        }
        "ip" => {
            mc.ethertype = Some("0x0800".to_string());
            Ok(true)
        }
        "ipv6" => {
            mc.ethertype = Some("0x86DD".to_string());
            Ok(true)
        }
        "tcp" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_protocol = Some(6);
            Ok(true)
        }
        "udp" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_protocol = Some(17);
            Ok(true)
        }
        "icmp" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_protocol = Some(1);
            Ok(true)
        }
        "icmpv6" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x86DD".to_string()); }
            mc.ipv6_next_header = Some(58);
            Ok(true)
        }
        "gre" => {
            if mc.ethertype.is_none() { mc.ethertype = Some("0x0800".to_string()); }
            mc.ip_protocol = Some(47);
            Ok(true)
        }
        "mpls" => {
            mc.ethertype = Some("0x8847".to_string());
            Ok(true)
        }
        _ => Ok(false),
    }
}

// ============================================================
// AST → Rules converter
// ============================================================

struct RuleBuilder {
    name_prefix: String,
    counter: usize,
    priority: u32,
    warnings: Vec<String>,
}

impl RuleBuilder {
    fn new(name: &str) -> Self {
        RuleBuilder {
            name_prefix: name.to_string(),
            counter: 0,
            priority: 100,
            warnings: Vec::new(),
        }
    }

    fn next_rule_name(&mut self) -> String {
        self.counter += 1;
        format!("{}_r{}", self.name_prefix, self.counter)
    }

    fn next_priority(&mut self) -> u32 {
        let p = self.priority;
        if self.priority >= 10 {
            self.priority -= 10;
        }
        p
    }

    fn make_rule(&self, name: String, priority: u32, mc: MatchCriteria, action: Action) -> StatelessRule {
        StatelessRule {
            name,
            priority,
            match_criteria: mc,
            action: Some(action),
            rule_type: None,
            fsm: None,
            ports: None,
            rate_limit: None,
            rewrite: None,
            mirror_port: None,
            redirect_port: None,
            rss_queue: None,
            int_insert: None,
        }
    }

    /// Convert AST to rules. Returns list of rules.
    fn ast_to_rules(&mut self, expr: &FilterExpr, action: &Action) -> Result<Vec<StatelessRule>> {
        match expr {
            FilterExpr::Comparison { field, op, value } => {
                let mut mc = MatchCriteria::default();
                let result = apply_wireshark_field(&mut mc, field, op, value, &mut self.warnings)?;
                match result {
                    FieldMapResult::Single => {
                        let name = self.next_rule_name();
                        let priority = self.next_priority();
                        Ok(vec![self.make_rule(name, priority, mc, action.clone())])
                    }
                    FieldMapResult::Bidirectional { src_field, dst_field } => {
                        // Expand to two rules: one for src, one for dst
                        let mut mc_src = mc.clone();
                        apply_wireshark_field(&mut mc_src, &src_field, op, value, &mut self.warnings)?;
                        let name1 = self.next_rule_name();
                        let pri1 = self.next_priority();

                        let mut mc_dst = mc;
                        apply_wireshark_field(&mut mc_dst, &dst_field, op, value, &mut self.warnings)?;
                        let name2 = self.next_rule_name();
                        let pri2 = self.next_priority();

                        Ok(vec![
                            self.make_rule(name1, pri1, mc_src, action.clone()),
                            self.make_rule(name2, pri2, mc_dst, action.clone()),
                        ])
                    }
                }
            }

            FilterExpr::ProtocolPresence(protocol) => {
                let mut mc = MatchCriteria::default();
                let recognized = apply_protocol_presence(&mut mc, protocol)?;
                if !recognized {
                    self.warnings.push(format!("Unknown protocol presence '{}', skipping", protocol));
                    return Ok(vec![]);
                }
                let name = self.next_rule_name();
                let priority = self.next_priority();
                Ok(vec![self.make_rule(name, priority, mc, action.clone())])
            }

            FilterExpr::InSet { field, values } => {
                let mut rules = Vec::new();
                for v in values {
                    let mut mc = MatchCriteria::default();
                    let result = apply_wireshark_field(&mut mc, field, &CompareOp::Eq, v, &mut self.warnings)?;
                    match result {
                        FieldMapResult::Single => {
                            let name = self.next_rule_name();
                            let priority = self.next_priority();
                            rules.push(self.make_rule(name, priority, mc, action.clone()));
                        }
                        FieldMapResult::Bidirectional { src_field, dst_field } => {
                            let mut mc_src = mc.clone();
                            apply_wireshark_field(&mut mc_src, &src_field, &CompareOp::Eq, v, &mut self.warnings)?;
                            let name1 = self.next_rule_name();
                            let pri1 = self.next_priority();
                            rules.push(self.make_rule(name1, pri1, mc_src, action.clone()));

                            let mut mc_dst = mc;
                            apply_wireshark_field(&mut mc_dst, &dst_field, &CompareOp::Eq, v, &mut self.warnings)?;
                            let name2 = self.next_rule_name();
                            let pri2 = self.next_priority();
                            rules.push(self.make_rule(name2, pri2, mc_dst, action.clone()));
                        }
                    }
                }
                Ok(rules)
            }

            FilterExpr::And(_left, _right) => {
                // AND → merge into a single rule's MatchCriteria
                // We collect all leaf comparisons and merge them
                let mut mc = MatchCriteria::default();
                let mut pending_bidi = Vec::new();
                self.collect_and_fields(expr, &mut mc, &mut pending_bidi)?;

                if pending_bidi.is_empty() {
                    let name = self.next_rule_name();
                    let priority = self.next_priority();
                    Ok(vec![self.make_rule(name, priority, mc, action.clone())])
                } else {
                    // Bidirectional fields in AND context: expand each
                    let mut rules = Vec::new();
                    for (src_f, dst_f, op, val) in &pending_bidi {
                        let mut mc_src = mc.clone();
                        apply_wireshark_field(&mut mc_src, src_f, op, val, &mut self.warnings)?;
                        let name1 = self.next_rule_name();
                        let pri1 = self.next_priority();
                        rules.push(self.make_rule(name1, pri1, mc_src, action.clone()));

                        let mut mc_dst = mc.clone();
                        apply_wireshark_field(&mut mc_dst, dst_f, op, val, &mut self.warnings)?;
                        let name2 = self.next_rule_name();
                        let pri2 = self.next_priority();
                        rules.push(self.make_rule(name2, pri2, mc_dst, action.clone()));
                    }
                    Ok(rules)
                }
            }

            FilterExpr::Or(left, right) => {
                // OR → separate rules
                let mut rules = self.ast_to_rules(left, action)?;
                rules.extend(self.ast_to_rules(right, action)?);
                Ok(rules)
            }

            FilterExpr::Not(inner) => {
                // NOT at top level → invert action
                let inverted = match action {
                    Action::Pass => Action::Drop,
                    Action::Drop => Action::Pass,
                };
                self.ast_to_rules(inner, &inverted)
            }
        }
    }

    /// Recursively collect AND-combined fields into a single MatchCriteria
    fn collect_and_fields(
        &mut self,
        expr: &FilterExpr,
        mc: &mut MatchCriteria,
        pending_bidi: &mut Vec<(String, String, CompareOp, FilterValue)>,
    ) -> Result<()> {
        match expr {
            FilterExpr::And(left, right) => {
                self.collect_and_fields(left, mc, pending_bidi)?;
                self.collect_and_fields(right, mc, pending_bidi)?;
            }
            FilterExpr::Comparison { field, op, value } => {
                let result = apply_wireshark_field(mc, field, op, value, &mut self.warnings)?;
                if let FieldMapResult::Bidirectional { src_field, dst_field } = result {
                    pending_bidi.push((src_field, dst_field, op.clone(), value.clone()));
                }
            }
            FilterExpr::ProtocolPresence(protocol) => {
                apply_protocol_presence(mc, protocol)?;
            }
            FilterExpr::Not(inner) => {
                self.warnings.push("Nested NOT in AND context not fully supported".to_string());
                // Try to handle simple cases
                self.collect_and_fields(inner, mc, pending_bidi)?;
            }
            FilterExpr::InSet { field, values } => {
                // In AND context, InSet doesn't merge well — emit warning
                if let Some(first) = values.first() {
                    apply_wireshark_field(mc, field, &CompareOp::Eq, first, &mut self.warnings)?;
                    if values.len() > 1 {
                        self.warnings.push(format!("'in' set for '{}' in AND context: using first value only", field));
                    }
                }
            }
            _ => {
                self.warnings.push("Complex expression in AND branch, may produce inaccurate rules".to_string());
            }
        }
        Ok(())
    }
}

// ============================================================
// Public API
// ============================================================

/// Import a Wireshark display filter string into a FilterConfig.
/// Returns (FilterConfig, warnings).
pub fn import_wireshark_filter(
    filter: &str,
    default_action: &str,
    name: &str,
) -> Result<(FilterConfig, Vec<String>)> {
    let filter = filter.trim();
    if filter.is_empty() {
        bail!("Empty filter expression");
    }

    let ast = parse_filter(filter)?;

    let default = match default_action {
        "pass" => Action::Pass,
        "drop" => Action::Drop,
        _ => bail!("Invalid default action '{}', expected 'pass' or 'drop'", default_action),
    };

    // The action for matched rules is the opposite of default
    let match_action = match &default {
        Action::Drop => Action::Pass,
        Action::Pass => Action::Drop,
    };

    let mut builder = RuleBuilder::new(name);
    let rules = builder.ast_to_rules(&ast, &match_action)?;

    if rules.is_empty() {
        bail!("No rules generated from filter expression");
    }

    let config = FilterConfig {
        pacgate: PacgateConfig {
            version: "1.0".to_string(),
            defaults: Defaults { action: default },
            rules,
            conntrack: None,
            tables: None,
        },
    };

    Ok((config, builder.warnings))
}

/// Generate JSON summary of a Wireshark filter import.
pub fn import_wireshark_summary(
    filter: &str,
    default_action: &str,
    name: &str,
) -> serde_json::Value {
    match import_wireshark_filter(filter, default_action, name) {
        Ok((config, warnings)) => {
            serde_json::json!({
                "status": "ok",
                "filter": filter,
                "rule_count": config.pacgate.rules.len(),
                "default_action": format!("{:?}", config.pacgate.defaults.action).to_lowercase(),
                "rules": config.pacgate.rules.iter().map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "priority": r.priority,
                        "action": format!("{:?}", r.action()).to_lowercase(),
                    })
                }).collect::<Vec<_>>(),
                "warnings": warnings,
            })
        }
        Err(e) => {
            serde_json::json!({
                "status": "error",
                "filter": filter,
                "error": e.to_string(),
            })
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p4_import::config_to_yaml;

    // ---- Tokenizer tests ----

    #[test]
    fn test_tokenize_simple_eq() {
        let tokens = tokenize("tcp.port == 80").unwrap();
        assert_eq!(tokens.len(), 4); // Field, Op, IntLit, Eof
        assert!(matches!(&tokens[0], Token::Field(f) if f == "tcp.port"));
        assert!(matches!(&tokens[1], Token::Op(CompareOp::Eq)));
        assert!(matches!(&tokens[2], Token::IntLit(80)));
    }

    #[test]
    fn test_tokenize_hex_value() {
        let tokens = tokenize("eth.type == 0x0800").unwrap();
        assert!(matches!(&tokens[2], Token::IntLit(2048)));
    }

    #[test]
    fn test_tokenize_and_or() {
        let tokens = tokenize("a == 1 && b == 2 || c == 3").unwrap();
        assert!(tokens.iter().any(|t| matches!(t, Token::And)));
        assert!(tokens.iter().any(|t| matches!(t, Token::Or)));
    }

    #[test]
    fn test_tokenize_not() {
        let tokens = tokenize("!arp").unwrap();
        assert!(matches!(&tokens[0], Token::Not));
        assert!(matches!(&tokens[1], Token::Field(f) if f == "arp"));
    }

    #[test]
    fn test_tokenize_in_set() {
        let tokens = tokenize("tcp.port in {80, 443, 8080}").unwrap();
        assert!(tokens.iter().any(|t| matches!(t, Token::In)));
        assert!(tokens.iter().any(|t| matches!(t, Token::LBrace)));
        assert!(tokens.iter().any(|t| matches!(t, Token::RBrace)));
    }

    #[test]
    fn test_tokenize_ip_cidr() {
        let tokens = tokenize("ip.src == 10.0.0.0/8").unwrap();
        assert!(matches!(&tokens[2], Token::StringLit(s) if s == "10.0.0.0/8"));
    }

    #[test]
    fn test_tokenize_mac_address() {
        let tokens = tokenize("eth.dst == aa:bb:cc:dd:ee:ff").unwrap();
        assert!(matches!(&tokens[2], Token::StringLit(s) if s == "aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_tokenize_keywords_case_insensitive() {
        let tokens = tokenize("a == 1 AND b == 2 OR c == 3").unwrap();
        assert!(tokens.iter().any(|t| matches!(t, Token::And)));
        assert!(tokens.iter().any(|t| matches!(t, Token::Or)));
    }

    // ---- Parser tests ----

    #[test]
    fn test_parse_comparison() {
        let expr = parse_filter("tcp.port == 80").unwrap();
        assert!(matches!(expr, FilterExpr::Comparison { .. }));
    }

    #[test]
    fn test_parse_and() {
        let expr = parse_filter("ip.src == 10.0.0.1 && tcp.dstport == 80").unwrap();
        assert!(matches!(expr, FilterExpr::And(_, _)));
    }

    #[test]
    fn test_parse_or() {
        let expr = parse_filter("tcp.port == 80 || tcp.port == 443").unwrap();
        assert!(matches!(expr, FilterExpr::Or(_, _)));
    }

    #[test]
    fn test_parse_not() {
        let expr = parse_filter("!arp").unwrap();
        assert!(matches!(expr, FilterExpr::Not(_)));
    }

    #[test]
    fn test_parse_in_set() {
        let expr = parse_filter("tcp.port in {80, 443}").unwrap();
        assert!(matches!(expr, FilterExpr::InSet { .. }));
    }

    #[test]
    fn test_parse_precedence() {
        // NOT > AND > OR: "!a && b || c" = ((NOT a) AND b) OR c
        let expr = parse_filter("!arp && ip || ipv6").unwrap();
        assert!(matches!(expr, FilterExpr::Or(_, _)));
    }

    #[test]
    fn test_parse_parens() {
        let expr = parse_filter("(tcp.port == 80 || tcp.port == 443) && ip.src == 10.0.0.0/8").unwrap();
        assert!(matches!(expr, FilterExpr::And(_, _)));
    }

    // ---- Field mapping tests ----

    #[test]
    fn test_field_tcp_port_bidirectional() {
        let mut mc = MatchCriteria::default();
        let mut warnings = Vec::new();
        let result = apply_wireshark_field(&mut mc, "tcp.port", &CompareOp::Eq, &FilterValue::Integer(80), &mut warnings).unwrap();
        assert!(matches!(result, FieldMapResult::Bidirectional { .. }));
        assert_eq!(mc.ip_protocol, Some(6));
    }

    #[test]
    fn test_field_ip_src_cidr() {
        let mut mc = MatchCriteria::default();
        let mut warnings = Vec::new();
        apply_wireshark_field(&mut mc, "ip.src", &CompareOp::Eq, &FilterValue::Str("10.0.0.0/8".to_string()), &mut warnings).unwrap();
        assert_eq!(mc.src_ip, Some("10.0.0.0/8".to_string()));
        assert_eq!(mc.ethertype, Some("0x0800".to_string()));
    }

    #[test]
    fn test_field_tcp_flags_syn() {
        let mut mc = MatchCriteria::default();
        let mut warnings = Vec::new();
        apply_wireshark_field(&mut mc, "tcp.flags.syn", &CompareOp::Eq, &FilterValue::Integer(1), &mut warnings).unwrap();
        assert_eq!(mc.tcp_flags, Some(0x02));     // SYN is bit 1
        assert_eq!(mc.tcp_flags_mask, Some(0x02));
    }

    #[test]
    fn test_field_frame_len_ge() {
        let mut mc = MatchCriteria::default();
        let mut warnings = Vec::new();
        apply_wireshark_field(&mut mc, "frame.len", &CompareOp::Ge, &FilterValue::Integer(64), &mut warnings).unwrap();
        assert_eq!(mc.frame_len_min, Some(64));
        assert_eq!(mc.frame_len_max, None);
    }

    #[test]
    fn test_protocol_presence_tcp() {
        let mut mc = MatchCriteria::default();
        let recognized = apply_protocol_presence(&mut mc, "tcp").unwrap();
        assert!(recognized);
        assert_eq!(mc.ethertype, Some("0x0800".to_string()));
        assert_eq!(mc.ip_protocol, Some(6));
    }

    #[test]
    fn test_protocol_presence_arp() {
        let mut mc = MatchCriteria::default();
        let recognized = apply_protocol_presence(&mut mc, "arp").unwrap();
        assert!(recognized);
        assert_eq!(mc.ethertype, Some("0x0806".to_string()));
    }

    #[test]
    fn test_field_port_range_ge() {
        let mut mc = MatchCriteria::default();
        let mut warnings = Vec::new();
        apply_wireshark_field(&mut mc, "tcp.dstport", &CompareOp::Ge, &FilterValue::Integer(1024), &mut warnings).unwrap();
        assert_eq!(mc.dst_port, Some(PortMatch::Range { range: [1024, 65535] }));
    }

    #[test]
    fn test_field_arp_opcode() {
        let mut mc = MatchCriteria::default();
        let mut warnings = Vec::new();
        apply_wireshark_field(&mut mc, "arp.opcode", &CompareOp::Eq, &FilterValue::Integer(1), &mut warnings).unwrap();
        assert_eq!(mc.arp_opcode, Some(1));
        assert_eq!(mc.ethertype, Some("0x0806".to_string()));
    }

    #[test]
    fn test_field_vxlan_vni() {
        let mut mc = MatchCriteria::default();
        let mut warnings = Vec::new();
        apply_wireshark_field(&mut mc, "vxlan.vni", &CompareOp::Eq, &FilterValue::Integer(100), &mut warnings).unwrap();
        assert_eq!(mc.vxlan_vni, Some(100));
    }

    // ---- Full import tests ----

    #[test]
    fn test_import_simple_filter() {
        let (config, warnings) = import_wireshark_filter("tcp.dstport == 80", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        assert_eq!(config.pacgate.rules[0].match_criteria.dst_port, Some(PortMatch::Exact(80)));
        assert_eq!(config.pacgate.rules[0].action(), Action::Pass);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_import_and_filter() {
        let (config, _) = import_wireshark_filter(
            "ip.src == 10.0.0.0/8 && tcp.dstport == 443", "drop", "test"
        ).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let rule = &config.pacgate.rules[0];
        assert_eq!(rule.match_criteria.src_ip, Some("10.0.0.0/8".to_string()));
        assert_eq!(rule.match_criteria.dst_port, Some(PortMatch::Exact(443)));
    }

    #[test]
    fn test_import_or_filter() {
        let (config, _) = import_wireshark_filter(
            "tcp.dstport == 80 || tcp.dstport == 443", "drop", "test"
        ).unwrap();
        assert_eq!(config.pacgate.rules.len(), 2);
    }

    #[test]
    fn test_import_not_filter() {
        let (config, _) = import_wireshark_filter("!arp", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        // NOT inverts action: default=drop, match=pass, NOT match=drop
        assert_eq!(config.pacgate.rules[0].action(), Action::Drop);
    }

    #[test]
    fn test_import_in_set() {
        let (config, _) = import_wireshark_filter(
            "tcp.dstport in {80, 443, 8080}", "drop", "test"
        ).unwrap();
        assert_eq!(config.pacgate.rules.len(), 3);
    }

    #[test]
    fn test_import_bidirectional_port() {
        let (config, _) = import_wireshark_filter("tcp.port == 80", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2); // src + dst
        assert!(config.pacgate.rules[0].match_criteria.src_port.is_some()
            || config.pacgate.rules[0].match_criteria.dst_port.is_some());
    }

    #[test]
    fn test_import_json_summary() {
        let summary = import_wireshark_summary("tcp.dstport == 80", "drop", "test");
        assert_eq!(summary["status"], "ok");
        assert_eq!(summary["rule_count"], 1);
    }

    #[test]
    fn test_import_yaml_output() {
        let (config, _) = import_wireshark_filter("tcp.dstport == 80", "drop", "test").unwrap();
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("dst_port"));
        assert!(yaml.contains("pass"));
    }

    #[test]
    fn test_import_complex_filter() {
        let (config, _) = import_wireshark_filter(
            "ip.src == 10.0.0.0/8 && tcp.dstport == 443 || udp.port == 53",
            "drop", "test"
        ).unwrap();
        // Should produce: 1 rule for the AND + 2 rules for udp.port (bidirectional) = 3
        assert!(config.pacgate.rules.len() >= 3);
    }

    #[test]
    fn test_import_tcp_flags_combo() {
        let (config, _) = import_wireshark_filter(
            "tcp.flags.syn == 1 && tcp.flags.ack == 0", "drop", "test"
        ).unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let rule = &config.pacgate.rules[0];
        // SYN=1 (bit 1) → flags=0x02, ACK=0 (bit 4) → flags stays 0x02, mask=0x12
        assert_eq!(rule.match_criteria.tcp_flags, Some(0x02));
        assert_eq!(rule.match_criteria.tcp_flags_mask, Some(0x12));
    }

    #[test]
    fn test_import_empty_filter_error() {
        assert!(import_wireshark_filter("", "drop", "test").is_err());
    }

    #[test]
    fn test_import_invalid_default_action() {
        assert!(import_wireshark_filter("tcp.port == 80", "invalid", "test").is_err());
    }
}
