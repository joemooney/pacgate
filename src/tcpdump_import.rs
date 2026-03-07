// tcpdump/BPF Filter Import: Parse tcpdump/pcap-filter expressions into PacGate FilterConfig
//
// Converts filters like "tcp port 80 and host 10.0.0.1" into YAML rules.
// Tokenizer → recursive descent parser → AST-to-rules converter.

use anyhow::{bail, Result};

use crate::model::*;

// ============================================================
// Tokens
// ============================================================

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Direction qualifiers
    Src,
    Dst,
    // Type qualifiers
    Host,
    Net,
    Port,
    Portrange,
    Proto,
    Ether,
    // Protocol keywords
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    Arp,
    Ip,
    Ip6,
    Igmp,
    Gre,
    // Tunnel / encapsulation
    Vlan,
    Mpls,
    // Length
    Greater,
    Less,
    // Boolean
    And,
    Or,
    Not,
    LParen,
    RParen,
    // Byte-offset
    LBracket,
    RBracket,
    Ampersand,
    Pipe,
    // Comparison
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    // Literals
    Number(u64),
    Ident(String),
    // End
    Eof,
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
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }

        // Two-character operators
        if i + 1 < len {
            let two = format!("{}{}", chars[i], chars[i + 1]);
            match two.as_str() {
                "==" => { tokens.push(Token::Eq); i += 2; continue; }
                "!=" => { tokens.push(Token::Ne); i += 2; continue; }
                ">=" => { tokens.push(Token::Ge); i += 2; continue; }
                "<=" => { tokens.push(Token::Le); i += 2; continue; }
                "&&" => { tokens.push(Token::And); i += 2; continue; }
                "||" => { tokens.push(Token::Or); i += 2; continue; }
                _ => {}
            }
        }

        // Single-character tokens
        match chars[i] {
            '(' => { tokens.push(Token::LParen); i += 1; continue; }
            ')' => { tokens.push(Token::RParen); i += 1; continue; }
            '[' => { tokens.push(Token::LBracket); i += 1; continue; }
            ']' => { tokens.push(Token::RBracket); i += 1; continue; }
            '&' => { tokens.push(Token::Ampersand); i += 1; continue; }
            '|' => { tokens.push(Token::Pipe); i += 1; continue; }
            '!' => { tokens.push(Token::Not); i += 1; continue; }
            '>' => { tokens.push(Token::Gt); i += 1; continue; }
            '<' => { tokens.push(Token::Lt); i += 1; continue; }
            '=' => { tokens.push(Token::Eq); i += 1; continue; }
            _ => {}
        }

        // Hex literal: 0x...
        if chars[i] == '0' && i + 1 < len && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
            i += 2;
            let start = i;
            while i < len && chars[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i == start {
                bail!("Empty hex literal at position {}", start - 2);
            }
            let hex_str: String = chars[start..i].iter().collect();
            tokens.push(Token::Number(u64::from_str_radix(&hex_str, 16)?));
            continue;
        }

        // Number or IP/CIDR (digit-started identifiers like 10.0.0.1, 192.168.0.0/16, 1024-65535)
        if chars[i].is_ascii_digit() {
            let start = i;
            // Scan ahead to see if this is a plain number or contains dots/colons/slashes/hyphens
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '.' || chars[i] == ':' || chars[i] == '/' || chars[i] == '-') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            // If it contains dots, colons, slashes, or hyphens, it's an identifier (IP, CIDR, portrange, MAC)
            if word.contains('.') || word.contains(':') || word.contains('/') || word.contains('-') {
                tokens.push(Token::Ident(word));
            } else if let Ok(n) = word.parse::<u64>() {
                tokens.push(Token::Number(n));
            } else {
                tokens.push(Token::Ident(word));
            }
            continue;
        }

        // Identifier (including IPs, CIDRs, MACs, port names, etc.)
        if chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '-' || chars[i] == ':' || chars[i] == '.' || chars[i] == '/' {
            let start = i;
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '-' || chars[i] == ':' || chars[i] == '.' || chars[i] == '/') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();

            // Classify keyword tokens
            match word.to_lowercase().as_str() {
                "src" => tokens.push(Token::Src),
                "dst" => tokens.push(Token::Dst),
                "host" => tokens.push(Token::Host),
                "net" => tokens.push(Token::Net),
                "port" => tokens.push(Token::Port),
                "portrange" => tokens.push(Token::Portrange),
                "proto" => tokens.push(Token::Proto),
                "ether" => tokens.push(Token::Ether),
                "tcp" => tokens.push(Token::Tcp),
                "udp" => tokens.push(Token::Udp),
                "icmp" => tokens.push(Token::Icmp),
                "icmp6" => tokens.push(Token::Icmp6),
                "arp" => tokens.push(Token::Arp),
                "ip" => tokens.push(Token::Ip),
                "ip6" => tokens.push(Token::Ip6),
                "igmp" => tokens.push(Token::Igmp),
                "gre" => tokens.push(Token::Gre),
                "vlan" => tokens.push(Token::Vlan),
                "mpls" => tokens.push(Token::Mpls),
                "greater" => tokens.push(Token::Greater),
                "less" => tokens.push(Token::Less),
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                _ => {
                    // Check if it's a number in disguise (e.g., after port name resolution)
                    if let Ok(n) = word.parse::<u64>() {
                        tokens.push(Token::Number(n));
                    } else {
                        tokens.push(Token::Ident(word));
                    }
                }
            }
            continue;
        }

        bail!("Unexpected character '{}' at position {}", chars[i], i);
    }

    tokens.push(Token::Eof);
    Ok(tokens)
}

// ============================================================
// Named constant resolution
// ============================================================

fn resolve_port_name(name: &str) -> Option<u16> {
    match name.to_lowercase().as_str() {
        "http" => Some(80),
        "https" => Some(443),
        "ssh" => Some(22),
        "dns" | "domain" => Some(53),
        "ftp" => Some(21),
        "ftp-data" => Some(20),
        "smtp" => Some(25),
        "ntp" => Some(123),
        "snmp" => Some(161),
        "telnet" => Some(23),
        "pop3" => Some(110),
        "imap" => Some(143),
        "bgp" => Some(179),
        "ldap" => Some(389),
        "mysql" => Some(3306),
        "postgresql" => Some(5432),
        "redis" => Some(6379),
        "syslog" => Some(514),
        "bootps" => Some(67),
        "bootpc" => Some(68),
        _ => None,
    }
}

fn resolve_tcp_flag(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "tcp-fin" => Some(0x01),
        "tcp-syn" => Some(0x02),
        "tcp-rst" => Some(0x04),
        "tcp-push" => Some(0x08),
        "tcp-ack" => Some(0x10),
        "tcp-urg" => Some(0x20),
        "tcp-ece" => Some(0x40),
        "tcp-cwr" => Some(0x80),
        _ => None,
    }
}

fn resolve_icmp_type(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "icmp-echoreply" => Some(0),
        "icmp-unreach" => Some(3),
        "icmp-sourcequench" => Some(4),
        "icmp-redirect" => Some(5),
        "icmp-echo" => Some(8),
        "icmp-routeradvert" => Some(9),
        "icmp-routersolicit" => Some(10),
        "icmp-timxceed" | "icmp-timexceed" => Some(11),
        "icmp-paramprob" => Some(12),
        "icmp-tstamp" => Some(13),
        "icmp-tstampreply" => Some(14),
        "icmp-maskreq" => Some(17),
        "icmp-maskreply" => Some(18),
        _ => None,
    }
}

fn resolve_protocol_number(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "igmp" => Some(2),
        "gre" => Some(47),
        "icmp6" | "icmpv6" | "ipv6-icmp" => Some(58),
        "sctp" => Some(132),
        _ => None,
    }
}

// ============================================================
// AST
// ============================================================

#[derive(Debug, Clone, PartialEq)]
enum Direction {
    Src,
    Dst,
    Either,
}

#[derive(Debug, Clone, PartialEq)]
enum ProtoFamily {
    Ip,
    Ip6,
}

#[derive(Debug, Clone, PartialEq)]
enum CmpOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

#[derive(Debug, Clone, PartialEq)]
enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    Arp,
    Ip,
    Ip6,
    Igmp,
    Gre,
}

#[derive(Debug, Clone, PartialEq)]
enum BpfExpr {
    HostMatch { direction: Direction, addr: String },
    NetMatch { direction: Direction, cidr: String },
    PortMatch { direction: Direction, port: u16 },
    PortRangeMatch { direction: Direction, low: u16, high: u16 },
    EtherHostMatch { direction: Direction, mac: String },
    ProtoMatch { family: ProtoFamily, proto: u8 },
    ProtocolPresence(Protocol),
    VlanMatch(Option<u16>),
    MplsMatch(Option<u32>),
    Greater(u16),
    Less(u16),
    TcpFlagCheck { mask: u8, value: u8, op: CmpOp },
    IcmpTypeCheck { value: u8 },
    IcmpCodeCheck { value: u8 },
    Icmpv6TypeCheck { value: u8 },
    Icmpv6CodeCheck { value: u8 },
    And(Box<BpfExpr>, Box<BpfExpr>),
    Or(Box<BpfExpr>, Box<BpfExpr>),
    Not(Box<BpfExpr>),
}

// ============================================================
// Parser
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

    fn expect_number(&mut self) -> Result<u64> {
        match self.advance() {
            Token::Number(n) => Ok(n),
            Token::Ident(s) => {
                // Try port name, tcp flag, icmp type, or protocol name resolution
                if let Some(p) = resolve_port_name(&s) {
                    return Ok(p as u64);
                }
                if let Some(f) = resolve_tcp_flag(&s) {
                    return Ok(f as u64);
                }
                if let Some(t) = resolve_icmp_type(&s) {
                    return Ok(t as u64);
                }
                if let Some(p) = resolve_protocol_number(&s) {
                    return Ok(p as u64);
                }
                bail!("Expected number, got identifier '{}'", s)
            }
            // Protocol keyword tokens used as protocol numbers (e.g., "ip proto tcp")
            Token::Tcp => Ok(6),
            Token::Udp => Ok(17),
            Token::Icmp => Ok(1),
            Token::Igmp => Ok(2),
            Token::Gre => Ok(47),
            Token::Icmp6 => Ok(58),
            other => bail!("Expected number, got {:?}", other),
        }
    }

    fn expect_ident_or_number(&mut self) -> Result<String> {
        match self.advance() {
            Token::Ident(s) => Ok(s),
            Token::Number(n) => Ok(n.to_string()),
            other => bail!("Expected identifier or number, got {:?}", other),
        }
    }

    /// Check if current position starts a new primitive (for implicit AND).
    fn starts_primitive(&self) -> bool {
        matches!(
            self.peek(),
            Token::Src | Token::Dst | Token::Host | Token::Net | Token::Port
            | Token::Portrange | Token::Proto | Token::Ether
            | Token::Tcp | Token::Udp | Token::Icmp | Token::Icmp6
            | Token::Arp | Token::Ip | Token::Ip6 | Token::Igmp | Token::Gre
            | Token::Vlan | Token::Mpls
            | Token::Greater | Token::Less
            | Token::Not | Token::LParen
        )
    }

    fn parse(&mut self) -> Result<BpfExpr> {
        let expr = self.parse_or()?;
        if !matches!(self.peek(), Token::Eof) {
            bail!("Unexpected token {:?} after expression", self.peek());
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<BpfExpr> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Token::Or) {
            self.advance(); // consume 'or'
            let right = self.parse_and()?;
            left = BpfExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<BpfExpr> {
        let mut left = self.parse_not()?;
        loop {
            if matches!(self.peek(), Token::And) {
                self.advance(); // consume 'and'
                let right = self.parse_not()?;
                left = BpfExpr::And(Box::new(left), Box::new(right));
            } else if self.starts_primitive() {
                // Implicit AND
                let right = self.parse_not()?;
                left = BpfExpr::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<BpfExpr> {
        if matches!(self.peek(), Token::Not) {
            self.advance(); // consume 'not'
            let inner = self.parse_not()?;
            return Ok(BpfExpr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<BpfExpr> {
        match self.peek().clone() {
            Token::LParen => {
                self.advance(); // consume '('
                let expr = self.parse_or()?;
                if !matches!(self.peek(), Token::RParen) {
                    bail!("Expected ')' but got {:?}", self.peek());
                }
                self.advance(); // consume ')'
                Ok(expr)
            }

            // Direction qualifiers: src/dst
            Token::Src | Token::Dst => {
                let dir = if matches!(self.peek(), Token::Src) { Direction::Src } else { Direction::Dst };
                self.advance();
                self.parse_direction_qualified(dir)
            }

            // ether src/dst host
            Token::Ether => {
                self.advance(); // consume 'ether'
                let dir = match self.peek() {
                    Token::Src => { self.advance(); Direction::Src }
                    Token::Dst => { self.advance(); Direction::Dst }
                    _ => Direction::Either,
                };
                if !matches!(self.peek(), Token::Host) {
                    bail!("Expected 'host' after 'ether [src|dst]'");
                }
                self.advance(); // consume 'host'
                let mac = self.expect_ident_or_number()?;
                Ok(BpfExpr::EtherHostMatch { direction: dir, mac })
            }

            // Protocol keywords
            Token::Tcp => {
                self.advance();
                self.parse_protocol_qualified(Protocol::Tcp)
            }
            Token::Udp => {
                self.advance();
                self.parse_protocol_qualified(Protocol::Udp)
            }
            Token::Icmp => {
                self.advance();
                // Check for byte-offset: icmp[...]
                if matches!(self.peek(), Token::LBracket) {
                    return self.parse_byte_offset("icmp");
                }
                Ok(BpfExpr::ProtocolPresence(Protocol::Icmp))
            }
            Token::Icmp6 => {
                self.advance();
                if matches!(self.peek(), Token::LBracket) {
                    return self.parse_byte_offset("icmp6");
                }
                Ok(BpfExpr::ProtocolPresence(Protocol::Icmp6))
            }
            Token::Arp => {
                self.advance();
                Ok(BpfExpr::ProtocolPresence(Protocol::Arp))
            }
            Token::Ip => {
                self.advance();
                // Check for "ip proto N" or "ip[...]"
                if matches!(self.peek(), Token::Proto) {
                    self.advance();
                    let n = self.expect_number()?;
                    return Ok(BpfExpr::ProtoMatch { family: ProtoFamily::Ip, proto: n as u8 });
                }
                if matches!(self.peek(), Token::LBracket) {
                    return self.parse_byte_offset("ip");
                }
                Ok(BpfExpr::ProtocolPresence(Protocol::Ip))
            }
            Token::Ip6 => {
                self.advance();
                if matches!(self.peek(), Token::Proto) {
                    self.advance();
                    let n = self.expect_number()?;
                    return Ok(BpfExpr::ProtoMatch { family: ProtoFamily::Ip6, proto: n as u8 });
                }
                Ok(BpfExpr::ProtocolPresence(Protocol::Ip6))
            }
            Token::Igmp => {
                self.advance();
                Ok(BpfExpr::ProtocolPresence(Protocol::Igmp))
            }
            Token::Gre => {
                self.advance();
                Ok(BpfExpr::ProtocolPresence(Protocol::Gre))
            }

            // Unqualified host/net/port/portrange
            Token::Host => {
                self.advance();
                let addr = self.expect_ident_or_number()?;
                Ok(BpfExpr::HostMatch { direction: Direction::Either, addr })
            }
            Token::Net => {
                self.advance();
                let cidr = self.expect_ident_or_number()?;
                Ok(BpfExpr::NetMatch { direction: Direction::Either, cidr })
            }
            Token::Port => {
                self.advance();
                let port = self.resolve_port_value()?;
                Ok(BpfExpr::PortMatch { direction: Direction::Either, port })
            }
            Token::Portrange => {
                self.advance();
                let (low, high) = self.parse_portrange_value()?;
                Ok(BpfExpr::PortRangeMatch { direction: Direction::Either, low, high })
            }

            // Tunnel keywords
            Token::Vlan => {
                self.advance();
                let id = if matches!(self.peek(), Token::Number(_)) {
                    Some(self.expect_number()? as u16)
                } else {
                    None
                };
                Ok(BpfExpr::VlanMatch(id))
            }
            Token::Mpls => {
                self.advance();
                let label = if matches!(self.peek(), Token::Number(_)) {
                    Some(self.expect_number()? as u32)
                } else {
                    None
                };
                Ok(BpfExpr::MplsMatch(label))
            }

            // Length
            Token::Greater => {
                self.advance();
                let n = self.expect_number()? as u16;
                Ok(BpfExpr::Greater(n))
            }
            Token::Less => {
                self.advance();
                let n = self.expect_number()? as u16;
                Ok(BpfExpr::Less(n))
            }

            Token::Eof => bail!("Unexpected end of filter expression"),
            ref t => bail!("Unexpected token {:?}", t),
        }
    }

    /// Parse after a direction qualifier (src/dst)
    fn parse_direction_qualified(&mut self, dir: Direction) -> Result<BpfExpr> {
        match self.peek().clone() {
            Token::Host => {
                self.advance();
                let addr = self.expect_ident_or_number()?;
                Ok(BpfExpr::HostMatch { direction: dir, addr })
            }
            Token::Net => {
                self.advance();
                let cidr = self.expect_ident_or_number()?;
                Ok(BpfExpr::NetMatch { direction: dir, cidr })
            }
            Token::Port => {
                self.advance();
                let port = self.resolve_port_value()?;
                Ok(BpfExpr::PortMatch { direction: dir, port })
            }
            Token::Portrange => {
                self.advance();
                let (low, high) = self.parse_portrange_value()?;
                Ok(BpfExpr::PortRangeMatch { direction: dir, low, high })
            }
            // "src host" or "dst host" is common, but bare "src IP" is also valid
            Token::Ident(_) | Token::Number(_) => {
                // Treat as "src/dst host <addr>"
                let addr = self.expect_ident_or_number()?;
                Ok(BpfExpr::HostMatch { direction: dir, addr })
            }
            _ => bail!("Expected host/net/port/portrange after direction qualifier, got {:?}", self.peek()),
        }
    }

    /// Parse after a protocol keyword (tcp/udp): could be port, portrange, src, dst, or byte-offset
    fn parse_protocol_qualified(&mut self, proto: Protocol) -> Result<BpfExpr> {
        match self.peek() {
            Token::Port => {
                self.advance();
                let port = self.resolve_port_value()?;
                // Wrap in AND with protocol presence
                Ok(BpfExpr::And(
                    Box::new(BpfExpr::ProtocolPresence(proto)),
                    Box::new(BpfExpr::PortMatch { direction: Direction::Either, port }),
                ))
            }
            Token::Portrange => {
                self.advance();
                let (low, high) = self.parse_portrange_value()?;
                Ok(BpfExpr::And(
                    Box::new(BpfExpr::ProtocolPresence(proto)),
                    Box::new(BpfExpr::PortRangeMatch { direction: Direction::Either, low, high }),
                ))
            }
            Token::Src => {
                self.advance();
                if matches!(self.peek(), Token::Port) {
                    self.advance();
                    let port = self.resolve_port_value()?;
                    Ok(BpfExpr::And(
                        Box::new(BpfExpr::ProtocolPresence(proto)),
                        Box::new(BpfExpr::PortMatch { direction: Direction::Src, port }),
                    ))
                } else if matches!(self.peek(), Token::Portrange) {
                    self.advance();
                    let (low, high) = self.parse_portrange_value()?;
                    Ok(BpfExpr::And(
                        Box::new(BpfExpr::ProtocolPresence(proto)),
                        Box::new(BpfExpr::PortRangeMatch { direction: Direction::Src, low, high }),
                    ))
                } else {
                    bail!("Expected 'port' or 'portrange' after 'tcp/udp src'");
                }
            }
            Token::Dst => {
                self.advance();
                if matches!(self.peek(), Token::Port) {
                    self.advance();
                    let port = self.resolve_port_value()?;
                    Ok(BpfExpr::And(
                        Box::new(BpfExpr::ProtocolPresence(proto)),
                        Box::new(BpfExpr::PortMatch { direction: Direction::Dst, port }),
                    ))
                } else if matches!(self.peek(), Token::Portrange) {
                    self.advance();
                    let (low, high) = self.parse_portrange_value()?;
                    Ok(BpfExpr::And(
                        Box::new(BpfExpr::ProtocolPresence(proto)),
                        Box::new(BpfExpr::PortRangeMatch { direction: Direction::Dst, low, high }),
                    ))
                } else {
                    bail!("Expected 'port' or 'portrange' after 'tcp/udp dst'");
                }
            }
            Token::LBracket => {
                let proto_name = match proto {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    _ => bail!("Byte-offset not supported for {:?}", proto),
                };
                self.parse_byte_offset(proto_name)
            }
            _ => {
                // Bare "tcp" or "udp" → protocol presence
                Ok(BpfExpr::ProtocolPresence(proto))
            }
        }
    }

    /// Parse byte-offset expression: proto[offset] op value or proto[offset] & mask op value
    fn parse_byte_offset(&mut self, proto: &str) -> Result<BpfExpr> {
        // Consume '['
        if !matches!(self.advance(), Token::LBracket) {
            bail!("Expected '[' for byte offset");
        }

        // offset: number or named offset
        let offset_tok = self.advance();
        let offset_name = match &offset_tok {
            Token::Number(n) => n.to_string(),
            Token::Ident(s) => s.clone(),
            _ => bail!("Expected offset in byte-offset expression"),
        };

        // Consume ']'
        if !matches!(self.advance(), Token::RBracket) {
            bail!("Expected ']' in byte-offset expression");
        }

        // Check for mask: & value
        let mask = if matches!(self.peek(), Token::Ampersand) {
            self.advance(); // consume '&'
            Some(self.expect_number()? as u8)
        } else {
            None
        };

        // Comparison operator
        let op = match self.peek() {
            Token::Eq => { self.advance(); CmpOp::Eq }
            Token::Ne => { self.advance(); CmpOp::Ne }
            Token::Gt => { self.advance(); CmpOp::Gt }
            Token::Lt => { self.advance(); CmpOp::Lt }
            Token::Ge => { self.advance(); CmpOp::Ge }
            Token::Le => { self.advance(); CmpOp::Le }
            Token::Not => {
                self.advance();
                if matches!(self.peek(), Token::Eq) {
                    self.advance();
                    CmpOp::Ne
                } else {
                    bail!("Expected '=' after '!' in comparison");
                }
            }
            _ => bail!("Expected comparison operator after byte-offset expression"),
        };

        // Value (number or named constant)
        let raw_value = self.expect_number()?;
        let value = raw_value as u8;

        // Map well-known byte-offset patterns to typed AST nodes
        match proto {
            "tcp" => {
                if offset_name == "13" || offset_name == "tcpflags" {
                    let effective_mask = mask.unwrap_or(0xFF);
                    return Ok(BpfExpr::TcpFlagCheck { mask: effective_mask, value, op });
                }
            }
            "icmp" => {
                if offset_name == "0" || offset_name == "icmptype" {
                    return Ok(BpfExpr::IcmpTypeCheck { value });
                }
                if offset_name == "1" || offset_name == "icmpcode" {
                    return Ok(BpfExpr::IcmpCodeCheck { value });
                }
            }
            "icmp6" => {
                if offset_name == "0" || offset_name == "icmp6type" {
                    return Ok(BpfExpr::Icmpv6TypeCheck { value });
                }
                if offset_name == "1" || offset_name == "icmp6code" {
                    return Ok(BpfExpr::Icmpv6CodeCheck { value });
                }
            }
            _ => {}
        }

        // Unknown byte-offset: produce a warning via the generic pattern
        // We still produce a TcpFlagCheck for tcp or bail for unknown
        bail!("Unsupported byte-offset: {}[{}] — protocol-relative offsets cannot map to absolute frame offsets", proto, offset_name);
    }

    /// Resolve a port value: number or named port
    fn resolve_port_value(&mut self) -> Result<u16> {
        match self.advance() {
            Token::Number(n) => Ok(n as u16),
            Token::Ident(s) => {
                if let Some(p) = resolve_port_name(&s) {
                    Ok(p)
                } else {
                    bail!("Unknown port name '{}'", s)
                }
            }
            other => bail!("Expected port number or name, got {:?}", other),
        }
    }

    /// Parse portrange value: "low-high" as a single Ident token
    fn parse_portrange_value(&mut self) -> Result<(u16, u16)> {
        let s = self.expect_ident_or_number()?;
        if let Some(idx) = s.find('-') {
            let low: u16 = s[..idx].parse().map_err(|_| anyhow::anyhow!("Invalid portrange low: {}", &s[..idx]))?;
            let high: u16 = s[idx+1..].parse().map_err(|_| anyhow::anyhow!("Invalid portrange high: {}", &s[idx+1..]))?;
            Ok((low, high))
        } else {
            bail!("Expected portrange in format 'low-high', got '{}'", s)
        }
    }
}

fn parse_bpf(input: &str) -> Result<BpfExpr> {
    let tokens = tokenize(input)?;
    let mut parser = Parser::new(tokens);
    parser.parse()
}

// ============================================================
// AST to Rules
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

    fn ast_to_rules(&mut self, expr: &BpfExpr, action: &Action) -> Result<Vec<StatelessRule>> {
        match expr {
            BpfExpr::HostMatch { direction, addr } => {
                let is_ipv6 = addr.contains(':');
                match direction {
                    Direction::Src => {
                        let mut mc = MatchCriteria::default();
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.src_ipv6 = Some(addr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.src_ip = Some(addr.clone());
                        }
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Dst => {
                        let mut mc = MatchCriteria::default();
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.dst_ipv6 = Some(addr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.dst_ip = Some(addr.clone());
                        }
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Either => {
                        // Bidirectional: 2 rules
                        let mut rules = Vec::new();
                        let mut mc_src = MatchCriteria::default();
                        let mut mc_dst = MatchCriteria::default();
                        if is_ipv6 {
                            mc_src.ethertype = Some("0x86DD".to_string());
                            mc_src.src_ipv6 = Some(addr.clone());
                            mc_dst.ethertype = Some("0x86DD".to_string());
                            mc_dst.dst_ipv6 = Some(addr.clone());
                        } else {
                            mc_src.ethertype = Some("0x0800".to_string());
                            mc_src.src_ip = Some(addr.clone());
                            mc_dst.ethertype = Some("0x0800".to_string());
                            mc_dst.dst_ip = Some(addr.clone());
                        }
                        let n1 = self.next_rule_name();
                        let p1 = self.next_priority();
                        rules.push(self.make_rule(n1, p1, mc_src, action.clone()));
                        let n2 = self.next_rule_name();
                        let p2 = self.next_priority();
                        rules.push(self.make_rule(n2, p2, mc_dst, action.clone()));
                        Ok(rules)
                    }
                }
            }

            BpfExpr::NetMatch { direction, cidr } => {
                let is_ipv6 = cidr.contains(':');
                match direction {
                    Direction::Src => {
                        let mut mc = MatchCriteria::default();
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.src_ipv6 = Some(cidr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.src_ip = Some(cidr.clone());
                        }
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Dst => {
                        let mut mc = MatchCriteria::default();
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.dst_ipv6 = Some(cidr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.dst_ip = Some(cidr.clone());
                        }
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Either => {
                        let mut rules = Vec::new();
                        let mut mc_src = MatchCriteria::default();
                        let mut mc_dst = MatchCriteria::default();
                        if is_ipv6 {
                            mc_src.ethertype = Some("0x86DD".to_string());
                            mc_src.src_ipv6 = Some(cidr.clone());
                            mc_dst.ethertype = Some("0x86DD".to_string());
                            mc_dst.dst_ipv6 = Some(cidr.clone());
                        } else {
                            mc_src.ethertype = Some("0x0800".to_string());
                            mc_src.src_ip = Some(cidr.clone());
                            mc_dst.ethertype = Some("0x0800".to_string());
                            mc_dst.dst_ip = Some(cidr.clone());
                        }
                        let n1 = self.next_rule_name();
                        let p1 = self.next_priority();
                        rules.push(self.make_rule(n1, p1, mc_src, action.clone()));
                        let n2 = self.next_rule_name();
                        let p2 = self.next_priority();
                        rules.push(self.make_rule(n2, p2, mc_dst, action.clone()));
                        Ok(rules)
                    }
                }
            }

            BpfExpr::PortMatch { direction, port } => {
                match direction {
                    Direction::Src => {
                        let mut mc = MatchCriteria::default();
                        mc.ethertype = Some("0x0800".to_string());
                        mc.src_port = Some(PortMatch::Exact(*port));
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Dst => {
                        let mut mc = MatchCriteria::default();
                        mc.ethertype = Some("0x0800".to_string());
                        mc.dst_port = Some(PortMatch::Exact(*port));
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Either => {
                        // Bidirectional: src + dst rules
                        let mut rules = Vec::new();
                        let mut mc_src = MatchCriteria::default();
                        mc_src.ethertype = Some("0x0800".to_string());
                        mc_src.src_port = Some(PortMatch::Exact(*port));
                        let n1 = self.next_rule_name();
                        let p1 = self.next_priority();
                        rules.push(self.make_rule(n1, p1, mc_src, action.clone()));

                        let mut mc_dst = MatchCriteria::default();
                        mc_dst.ethertype = Some("0x0800".to_string());
                        mc_dst.dst_port = Some(PortMatch::Exact(*port));
                        let n2 = self.next_rule_name();
                        let p2 = self.next_priority();
                        rules.push(self.make_rule(n2, p2, mc_dst, action.clone()));
                        Ok(rules)
                    }
                }
            }

            BpfExpr::PortRangeMatch { direction, low, high } => {
                match direction {
                    Direction::Src => {
                        let mut mc = MatchCriteria::default();
                        mc.ethertype = Some("0x0800".to_string());
                        mc.src_port = Some(PortMatch::Range { range: [*low, *high] });
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Dst => {
                        let mut mc = MatchCriteria::default();
                        mc.ethertype = Some("0x0800".to_string());
                        mc.dst_port = Some(PortMatch::Range { range: [*low, *high] });
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Either => {
                        let mut rules = Vec::new();
                        let mut mc_src = MatchCriteria::default();
                        mc_src.ethertype = Some("0x0800".to_string());
                        mc_src.src_port = Some(PortMatch::Range { range: [*low, *high] });
                        let n1 = self.next_rule_name();
                        let p1 = self.next_priority();
                        rules.push(self.make_rule(n1, p1, mc_src, action.clone()));

                        let mut mc_dst = MatchCriteria::default();
                        mc_dst.ethertype = Some("0x0800".to_string());
                        mc_dst.dst_port = Some(PortMatch::Range { range: [*low, *high] });
                        let n2 = self.next_rule_name();
                        let p2 = self.next_priority();
                        rules.push(self.make_rule(n2, p2, mc_dst, action.clone()));
                        Ok(rules)
                    }
                }
            }

            BpfExpr::EtherHostMatch { direction, mac } => {
                match direction {
                    Direction::Src => {
                        let mut mc = MatchCriteria::default();
                        mc.src_mac = Some(mac.clone());
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Dst => {
                        let mut mc = MatchCriteria::default();
                        mc.dst_mac = Some(mac.clone());
                        let name = self.next_rule_name();
                        let pri = self.next_priority();
                        Ok(vec![self.make_rule(name, pri, mc, action.clone())])
                    }
                    Direction::Either => {
                        let mut rules = Vec::new();
                        let mut mc_src = MatchCriteria::default();
                        mc_src.src_mac = Some(mac.clone());
                        let n1 = self.next_rule_name();
                        let p1 = self.next_priority();
                        rules.push(self.make_rule(n1, p1, mc_src, action.clone()));

                        let mut mc_dst = MatchCriteria::default();
                        mc_dst.dst_mac = Some(mac.clone());
                        let n2 = self.next_rule_name();
                        let p2 = self.next_priority();
                        rules.push(self.make_rule(n2, p2, mc_dst, action.clone()));
                        Ok(rules)
                    }
                }
            }

            BpfExpr::ProtoMatch { family, proto } => {
                let mut mc = MatchCriteria::default();
                match family {
                    ProtoFamily::Ip => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(*proto);
                    }
                    ProtoFamily::Ip6 => {
                        mc.ethertype = Some("0x86DD".to_string());
                        mc.ipv6_next_header = Some(*proto);
                    }
                }
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::ProtocolPresence(proto) => {
                let mut mc = MatchCriteria::default();
                match proto {
                    Protocol::Tcp => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(6);
                    }
                    Protocol::Udp => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(17);
                    }
                    Protocol::Icmp => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(1);
                    }
                    Protocol::Icmp6 => {
                        mc.ethertype = Some("0x86DD".to_string());
                        mc.ipv6_next_header = Some(58);
                    }
                    Protocol::Arp => {
                        mc.ethertype = Some("0x0806".to_string());
                    }
                    Protocol::Ip => {
                        mc.ethertype = Some("0x0800".to_string());
                    }
                    Protocol::Ip6 => {
                        mc.ethertype = Some("0x86DD".to_string());
                    }
                    Protocol::Igmp => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(2);
                    }
                    Protocol::Gre => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(47);
                    }
                }
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::VlanMatch(id) => {
                let mut mc = MatchCriteria::default();
                if let Some(vid) = id {
                    mc.vlan_id = Some(*vid);
                }
                // If no id, just match VLAN presence (ethertype 0x8100 handled by loader)
                mc.ethertype = Some("0x8100".to_string());
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::MplsMatch(label) => {
                let mut mc = MatchCriteria::default();
                mc.ethertype = Some("0x8847".to_string());
                if let Some(l) = label {
                    mc.mpls_label = Some(*l);
                }
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::Greater(len) => {
                let mut mc = MatchCriteria::default();
                mc.frame_len_min = Some(*len + 1); // strictly greater
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::Less(len) => {
                let mut mc = MatchCriteria::default();
                if *len > 0 {
                    mc.frame_len_max = Some(*len - 1); // strictly less
                }
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::TcpFlagCheck { mask, value, op: _ } => {
                let mut mc = MatchCriteria::default();
                mc.ethertype = Some("0x0800".to_string());
                mc.ip_protocol = Some(6);
                mc.tcp_flags = Some(*value);
                mc.tcp_flags_mask = Some(*mask);
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::IcmpTypeCheck { value } => {
                let mut mc = MatchCriteria::default();
                mc.ethertype = Some("0x0800".to_string());
                mc.ip_protocol = Some(1);
                mc.icmp_type = Some(*value);
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::IcmpCodeCheck { value } => {
                let mut mc = MatchCriteria::default();
                mc.ethertype = Some("0x0800".to_string());
                mc.ip_protocol = Some(1);
                mc.icmp_code = Some(*value);
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::Icmpv6TypeCheck { value } => {
                let mut mc = MatchCriteria::default();
                mc.ethertype = Some("0x86DD".to_string());
                mc.ipv6_next_header = Some(58);
                mc.icmpv6_type = Some(*value);
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::Icmpv6CodeCheck { value } => {
                let mut mc = MatchCriteria::default();
                mc.ethertype = Some("0x86DD".to_string());
                mc.ipv6_next_header = Some(58);
                mc.icmpv6_code = Some(*value);
                let name = self.next_rule_name();
                let pri = self.next_priority();
                Ok(vec![self.make_rule(name, pri, mc, action.clone())])
            }

            BpfExpr::And(_left, _right) => {
                let mut mc = MatchCriteria::default();
                let mut pending_bidi: Vec<(Direction, u16)> = Vec::new(); // port bidirectional
                let mut pending_bidi_range: Vec<(Direction, u16, u16)> = Vec::new();
                self.collect_and_fields(expr, &mut mc, &mut pending_bidi, &mut pending_bidi_range)?;

                if pending_bidi.is_empty() && pending_bidi_range.is_empty() {
                    let name = self.next_rule_name();
                    let priority = self.next_priority();
                    Ok(vec![self.make_rule(name, priority, mc, action.clone())])
                } else {
                    let mut rules = Vec::new();
                    for (_dir, port) in &pending_bidi {
                        let mut mc_src = mc.clone();
                        mc_src.src_port = Some(PortMatch::Exact(*port));
                        let n1 = self.next_rule_name();
                        let p1 = self.next_priority();
                        rules.push(self.make_rule(n1, p1, mc_src, action.clone()));

                        let mut mc_dst = mc.clone();
                        mc_dst.dst_port = Some(PortMatch::Exact(*port));
                        let n2 = self.next_rule_name();
                        let p2 = self.next_priority();
                        rules.push(self.make_rule(n2, p2, mc_dst, action.clone()));
                    }
                    for (_dir, low, high) in &pending_bidi_range {
                        let mut mc_src = mc.clone();
                        mc_src.src_port = Some(PortMatch::Range { range: [*low, *high] });
                        let n1 = self.next_rule_name();
                        let p1 = self.next_priority();
                        rules.push(self.make_rule(n1, p1, mc_src, action.clone()));

                        let mut mc_dst = mc.clone();
                        mc_dst.dst_port = Some(PortMatch::Range { range: [*low, *high] });
                        let n2 = self.next_rule_name();
                        let p2 = self.next_priority();
                        rules.push(self.make_rule(n2, p2, mc_dst, action.clone()));
                    }
                    Ok(rules)
                }
            }

            BpfExpr::Or(left, right) => {
                let mut rules = self.ast_to_rules(left, action)?;
                rules.extend(self.ast_to_rules(right, action)?);
                Ok(rules)
            }

            BpfExpr::Not(inner) => {
                let inverted = match action {
                    Action::Pass => Action::Drop,
                    Action::Drop => Action::Pass,
                };
                self.ast_to_rules(inner, &inverted)
            }
        }
    }

    /// Recursively collect AND-combined fields into a single MatchCriteria.
    /// Bidirectional ports are deferred to pending lists.
    fn collect_and_fields(
        &mut self,
        expr: &BpfExpr,
        mc: &mut MatchCriteria,
        pending_bidi: &mut Vec<(Direction, u16)>,
        pending_bidi_range: &mut Vec<(Direction, u16, u16)>,
    ) -> Result<()> {
        match expr {
            BpfExpr::And(left, right) => {
                self.collect_and_fields(left, mc, pending_bidi, pending_bidi_range)?;
                self.collect_and_fields(right, mc, pending_bidi, pending_bidi_range)?;
            }

            BpfExpr::HostMatch { direction, addr } => {
                let is_ipv6 = addr.contains(':');
                match direction {
                    Direction::Src => {
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.src_ipv6 = Some(addr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.src_ip = Some(addr.clone());
                        }
                    }
                    Direction::Dst => {
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.dst_ipv6 = Some(addr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.dst_ip = Some(addr.clone());
                        }
                    }
                    Direction::Either => {
                        // In AND context, ambiguous — use src
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.src_ipv6 = Some(addr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.src_ip = Some(addr.clone());
                        }
                        self.warnings.push("Bidirectional 'host' in AND context: using src only".to_string());
                    }
                }
            }

            BpfExpr::NetMatch { direction, cidr } => {
                let is_ipv6 = cidr.contains(':');
                match direction {
                    Direction::Src => {
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.src_ipv6 = Some(cidr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.src_ip = Some(cidr.clone());
                        }
                    }
                    Direction::Dst => {
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.dst_ipv6 = Some(cidr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.dst_ip = Some(cidr.clone());
                        }
                    }
                    Direction::Either => {
                        if is_ipv6 {
                            mc.ethertype = Some("0x86DD".to_string());
                            mc.src_ipv6 = Some(cidr.clone());
                        } else {
                            mc.ethertype = Some("0x0800".to_string());
                            mc.src_ip = Some(cidr.clone());
                        }
                        self.warnings.push("Bidirectional 'net' in AND context: using src only".to_string());
                    }
                }
            }

            BpfExpr::PortMatch { direction, port } => {
                mc.ethertype = Some("0x0800".to_string());
                match direction {
                    Direction::Src => { mc.src_port = Some(PortMatch::Exact(*port)); }
                    Direction::Dst => { mc.dst_port = Some(PortMatch::Exact(*port)); }
                    Direction::Either => {
                        pending_bidi.push((Direction::Either, *port));
                    }
                }
            }

            BpfExpr::PortRangeMatch { direction, low, high } => {
                mc.ethertype = Some("0x0800".to_string());
                match direction {
                    Direction::Src => { mc.src_port = Some(PortMatch::Range { range: [*low, *high] }); }
                    Direction::Dst => { mc.dst_port = Some(PortMatch::Range { range: [*low, *high] }); }
                    Direction::Either => {
                        pending_bidi_range.push((Direction::Either, *low, *high));
                    }
                }
            }

            BpfExpr::EtherHostMatch { direction, mac } => {
                match direction {
                    Direction::Src => { mc.src_mac = Some(mac.clone()); }
                    Direction::Dst => { mc.dst_mac = Some(mac.clone()); }
                    Direction::Either => {
                        mc.src_mac = Some(mac.clone());
                        self.warnings.push("Bidirectional 'ether host' in AND context: using src only".to_string());
                    }
                }
            }

            BpfExpr::ProtoMatch { family, proto } => {
                match family {
                    ProtoFamily::Ip => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(*proto);
                    }
                    ProtoFamily::Ip6 => {
                        mc.ethertype = Some("0x86DD".to_string());
                        mc.ipv6_next_header = Some(*proto);
                    }
                }
            }

            BpfExpr::ProtocolPresence(proto) => {
                match proto {
                    Protocol::Tcp => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(6);
                    }
                    Protocol::Udp => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(17);
                    }
                    Protocol::Icmp => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(1);
                    }
                    Protocol::Icmp6 => {
                        mc.ethertype = Some("0x86DD".to_string());
                        mc.ipv6_next_header = Some(58);
                    }
                    Protocol::Arp => {
                        mc.ethertype = Some("0x0806".to_string());
                    }
                    Protocol::Ip => {
                        mc.ethertype = Some("0x0800".to_string());
                    }
                    Protocol::Ip6 => {
                        mc.ethertype = Some("0x86DD".to_string());
                    }
                    Protocol::Igmp => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(2);
                    }
                    Protocol::Gre => {
                        mc.ethertype = Some("0x0800".to_string());
                        mc.ip_protocol = Some(47);
                    }
                }
            }

            BpfExpr::VlanMatch(id) => {
                mc.ethertype = Some("0x8100".to_string());
                if let Some(vid) = id {
                    mc.vlan_id = Some(*vid);
                }
            }

            BpfExpr::MplsMatch(label) => {
                mc.ethertype = Some("0x8847".to_string());
                if let Some(l) = label {
                    mc.mpls_label = Some(*l);
                }
            }

            BpfExpr::Greater(len) => {
                mc.frame_len_min = Some(*len + 1);
            }

            BpfExpr::Less(len) => {
                if *len > 0 {
                    mc.frame_len_max = Some(*len - 1);
                }
            }

            BpfExpr::TcpFlagCheck { mask, value, op: _ } => {
                mc.ethertype = Some("0x0800".to_string());
                mc.ip_protocol = Some(6);
                mc.tcp_flags = Some(*value);
                mc.tcp_flags_mask = Some(*mask);
            }

            BpfExpr::IcmpTypeCheck { value } => {
                mc.ethertype = Some("0x0800".to_string());
                mc.ip_protocol = Some(1);
                mc.icmp_type = Some(*value);
            }

            BpfExpr::IcmpCodeCheck { value } => {
                mc.ethertype = Some("0x0800".to_string());
                mc.ip_protocol = Some(1);
                mc.icmp_code = Some(*value);
            }

            BpfExpr::Icmpv6TypeCheck { value } => {
                mc.ethertype = Some("0x86DD".to_string());
                mc.ipv6_next_header = Some(58);
                mc.icmpv6_type = Some(*value);
            }

            BpfExpr::Icmpv6CodeCheck { value } => {
                mc.ethertype = Some("0x86DD".to_string());
                mc.ipv6_next_header = Some(58);
                mc.icmpv6_code = Some(*value);
            }

            BpfExpr::Not(inner) => {
                self.warnings.push("Nested NOT in AND context not fully supported".to_string());
                self.collect_and_fields(inner, mc, pending_bidi, pending_bidi_range)?;
            }

            BpfExpr::Or(_, _) => {
                self.warnings.push("OR inside AND branch — may produce inaccurate rules".to_string());
            }
        }
        Ok(())
    }
}

// ============================================================
// Public API
// ============================================================

/// Import a tcpdump/BPF filter string into a FilterConfig.
/// Returns (FilterConfig, warnings).
pub fn import_tcpdump_filter(
    filter: &str,
    default_action: &str,
    name: &str,
) -> Result<(FilterConfig, Vec<String>)> {
    let filter = filter.trim();
    if filter.is_empty() {
        bail!("Empty filter expression");
    }

    let ast = parse_bpf(filter)?;

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

/// Generate JSON summary of a tcpdump filter import.
pub fn import_tcpdump_summary(
    filter: &str,
    default_action: &str,
    name: &str,
) -> serde_json::Value {
    match import_tcpdump_filter(filter, default_action, name) {
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
    fn test_tokenize_simple() {
        let tokens = tokenize("tcp port 80").unwrap();
        assert_eq!(tokens.len(), 4); // Tcp, Port, Number(80), Eof
        assert!(matches!(&tokens[0], Token::Tcp));
        assert!(matches!(&tokens[1], Token::Port));
        assert!(matches!(&tokens[2], Token::Number(80)));
        assert!(matches!(&tokens[3], Token::Eof));
    }

    #[test]
    fn test_tokenize_and_or() {
        let tokens = tokenize("tcp and udp or arp").unwrap();
        assert!(matches!(&tokens[0], Token::Tcp));
        assert!(matches!(&tokens[1], Token::And));
        assert!(matches!(&tokens[2], Token::Udp));
        assert!(matches!(&tokens[3], Token::Or));
        assert!(matches!(&tokens[4], Token::Arp));
    }

    #[test]
    fn test_tokenize_symbols() {
        let tokens = tokenize("tcp && udp || !arp").unwrap();
        assert!(matches!(&tokens[1], Token::And));
        assert!(matches!(&tokens[3], Token::Or));
        assert!(matches!(&tokens[4], Token::Not));
    }

    #[test]
    fn test_tokenize_hex() {
        let tokens = tokenize("0x0800").unwrap();
        assert!(matches!(&tokens[0], Token::Number(0x0800)));
    }

    #[test]
    fn test_tokenize_parens() {
        let tokens = tokenize("(tcp or udp)").unwrap();
        assert!(matches!(&tokens[0], Token::LParen));
        assert!(matches!(&tokens[4], Token::RParen));
    }

    #[test]
    fn test_tokenize_byte_offset() {
        let tokens = tokenize("tcp[13] & 0x02 != 0").unwrap();
        assert!(matches!(&tokens[0], Token::Tcp));
        assert!(matches!(&tokens[1], Token::LBracket));
        assert!(matches!(&tokens[2], Token::Number(13)));
        assert!(matches!(&tokens[3], Token::RBracket));
        assert!(matches!(&tokens[4], Token::Ampersand));
        assert!(matches!(&tokens[5], Token::Number(0x02)));
        assert!(matches!(&tokens[6], Token::Ne));
    }

    #[test]
    fn test_tokenize_host_ip() {
        let tokens = tokenize("host 10.0.0.1").unwrap();
        assert!(matches!(&tokens[0], Token::Host));
        assert!(matches!(&tokens[1], Token::Ident(ref s) if s == "10.0.0.1"));
    }

    #[test]
    fn test_tokenize_cidr() {
        let tokens = tokenize("net 192.168.0.0/16").unwrap();
        assert!(matches!(&tokens[0], Token::Net));
        assert!(matches!(&tokens[1], Token::Ident(ref s) if s == "192.168.0.0/16"));
    }

    #[test]
    fn test_tokenize_portrange() {
        let tokens = tokenize("portrange 1024-65535").unwrap();
        assert!(matches!(&tokens[0], Token::Portrange));
        assert!(matches!(&tokens[1], Token::Ident(ref s) if s == "1024-65535"));
    }

    #[test]
    fn test_tokenize_mac() {
        let tokens = tokenize("ether host aa:bb:cc:dd:ee:ff").unwrap();
        assert!(matches!(&tokens[0], Token::Ether));
        assert!(matches!(&tokens[1], Token::Host));
        assert!(matches!(&tokens[2], Token::Ident(ref s) if s == "aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_tokenize_comparison_ops() {
        let tokens = tokenize(">= <= == !=").unwrap();
        assert!(matches!(&tokens[0], Token::Ge));
        assert!(matches!(&tokens[1], Token::Le));
        assert!(matches!(&tokens[2], Token::Eq));
        assert!(matches!(&tokens[3], Token::Ne));
    }

    #[test]
    fn test_tokenize_greater_less() {
        let tokens = tokenize("greater 1500").unwrap();
        assert!(matches!(&tokens[0], Token::Greater));
        assert!(matches!(&tokens[1], Token::Number(1500)));
    }

    // ---- Named constant tests ----

    #[test]
    fn test_resolve_port_names() {
        assert_eq!(resolve_port_name("http"), Some(80));
        assert_eq!(resolve_port_name("https"), Some(443));
        assert_eq!(resolve_port_name("ssh"), Some(22));
        assert_eq!(resolve_port_name("dns"), Some(53));
        assert_eq!(resolve_port_name("unknown"), None);
    }

    #[test]
    fn test_resolve_tcp_flags() {
        assert_eq!(resolve_tcp_flag("tcp-syn"), Some(0x02));
        assert_eq!(resolve_tcp_flag("tcp-ack"), Some(0x10));
        assert_eq!(resolve_tcp_flag("tcp-fin"), Some(0x01));
        assert_eq!(resolve_tcp_flag("tcp-rst"), Some(0x04));
    }

    #[test]
    fn test_resolve_icmp_types() {
        assert_eq!(resolve_icmp_type("icmp-echo"), Some(8));
        assert_eq!(resolve_icmp_type("icmp-echoreply"), Some(0));
        assert_eq!(resolve_icmp_type("icmp-unreach"), Some(3));
    }

    #[test]
    fn test_resolve_protocol_numbers() {
        assert_eq!(resolve_protocol_number("tcp"), Some(6));
        assert_eq!(resolve_protocol_number("udp"), Some(17));
        assert_eq!(resolve_protocol_number("icmp"), Some(1));
        assert_eq!(resolve_protocol_number("gre"), Some(47));
    }

    #[test]
    fn test_resolve_port_in_parser() {
        let tokens = tokenize("port http").unwrap();
        let mut parser = Parser::new(tokens);
        let expr = parser.parse().unwrap();
        assert!(matches!(expr, BpfExpr::PortMatch { port: 80, .. }));
    }

    #[test]
    fn test_resolve_named_protocol() {
        let tokens = tokenize("ip proto tcp").unwrap();
        let mut parser = Parser::new(tokens);
        let expr = parser.parse().unwrap();
        assert!(matches!(expr, BpfExpr::ProtoMatch { proto: 6, .. }));
    }

    // ---- Parser tests ----

    #[test]
    fn test_parse_simple_tcp() {
        let expr = parse_bpf("tcp").unwrap();
        assert!(matches!(expr, BpfExpr::ProtocolPresence(Protocol::Tcp)));
    }

    #[test]
    fn test_parse_tcp_port() {
        let expr = parse_bpf("tcp port 80").unwrap();
        // tcp port 80 → And(ProtocolPresence(Tcp), PortMatch(Either, 80))
        assert!(matches!(expr, BpfExpr::And(..)));
    }

    #[test]
    fn test_parse_src_host() {
        let expr = parse_bpf("src host 10.0.0.1").unwrap();
        assert!(matches!(expr, BpfExpr::HostMatch { direction: Direction::Src, .. }));
    }

    #[test]
    fn test_parse_and() {
        let expr = parse_bpf("tcp and udp").unwrap();
        assert!(matches!(expr, BpfExpr::And(..)));
    }

    #[test]
    fn test_parse_or() {
        let expr = parse_bpf("tcp or udp").unwrap();
        assert!(matches!(expr, BpfExpr::Or(..)));
    }

    #[test]
    fn test_parse_not() {
        let expr = parse_bpf("not arp").unwrap();
        assert!(matches!(expr, BpfExpr::Not(..)));
    }

    #[test]
    fn test_parse_parens() {
        let expr = parse_bpf("(tcp or udp) and port 80").unwrap();
        assert!(matches!(expr, BpfExpr::And(..)));
    }

    #[test]
    fn test_parse_implicit_and() {
        // "tcp port 80" is "tcp AND port 80" — the parse_protocol_qualified handles this
        // "host 10.0.0.1 port 80" should be implicit AND
        let expr = parse_bpf("host 10.0.0.1 port 80").unwrap();
        assert!(matches!(expr, BpfExpr::And(..)));
    }

    #[test]
    fn test_parse_tcp_flags() {
        let expr = parse_bpf("tcp[13] & 0x02 != 0").unwrap();
        // tcp[13] is parsed as byte-offset on tcp protocol → TcpFlagCheck directly
        assert!(matches!(expr, BpfExpr::TcpFlagCheck { mask: 0x02, value: 0, op: CmpOp::Ne }));
    }

    #[test]
    fn test_parse_icmp_type_named() {
        let expr = parse_bpf("icmp[icmptype] == icmp-echo").unwrap();
        assert!(matches!(expr, BpfExpr::IcmpTypeCheck { value: 8 }));
    }

    // ---- Full import tests ----

    #[test]
    fn test_import_host() {
        let (config, _warnings) = import_tcpdump_filter("host 10.0.0.1", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2); // bidirectional
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("10.0.0.1"));
    }

    #[test]
    fn test_import_src_host() {
        let (config, _) = import_tcpdump_filter("src host 10.0.0.1", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("src_ip"));
    }

    #[test]
    fn test_import_tcp_port() {
        let (config, _) = import_tcpdump_filter("tcp port 80", "drop", "test").unwrap();
        // tcp port 80 → AND(tcp, port 80 bidi) → 2 rules (src/dst)
        assert!(config.pacgate.rules.len() >= 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("ip_protocol: 6"));
    }

    #[test]
    fn test_import_dst_port() {
        let (config, _) = import_tcpdump_filter("dst port 80", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("dst_port: 80"));
    }

    #[test]
    fn test_import_net() {
        let (config, _) = import_tcpdump_filter("net 192.168.0.0/16", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 2); // bidirectional
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("192.168.0.0/16"));
    }

    #[test]
    fn test_import_portrange() {
        let (config, _) = import_tcpdump_filter("tcp portrange 1024-65535", "drop", "test").unwrap();
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("1024"));
        assert!(yaml.contains("65535"));
    }

    #[test]
    fn test_import_ether_host() {
        let (config, _) = import_tcpdump_filter("ether dst host aa:bb:cc:dd:ee:ff", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_import_vlan() {
        let (config, _) = import_tcpdump_filter("vlan 100", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("vlan_id: 100"));
    }

    #[test]
    fn test_import_mpls() {
        let (config, _) = import_tcpdump_filter("mpls 1000", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("mpls_label: 1000"));
    }

    #[test]
    fn test_import_tcp_flags() {
        let (config, _) = import_tcpdump_filter("tcp[13] & 0x02 != 0", "drop", "test").unwrap();
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("tcp_flags"));
    }

    #[test]
    fn test_import_icmp_type() {
        let (config, _) = import_tcpdump_filter("icmp[icmptype] == icmp-echo", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("icmp_type: 8"));
    }

    #[test]
    fn test_import_or() {
        let (config, _) = import_tcpdump_filter("port 80 or port 443", "drop", "test").unwrap();
        // Each bare port → 2 bidi rules → 4 total
        assert_eq!(config.pacgate.rules.len(), 4);
    }

    #[test]
    fn test_import_and() {
        let (config, _) = import_tcpdump_filter("src host 10.0.0.1 and dst port 80", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("src_ip"));
        assert!(yaml.contains("dst_port"));
    }

    #[test]
    fn test_import_not() {
        let (config, _) = import_tcpdump_filter("not arp", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        // "not arp" with default=drop → match_action=pass, inverted→drop
        let rule = &config.pacgate.rules[0];
        assert_eq!(rule.action(), Action::Drop);
    }

    #[test]
    fn test_import_complex() {
        let (config, _) = import_tcpdump_filter(
            "(tcp and port 22) or (tcp and port 443) or arp",
            "drop", "test"
        ).unwrap();
        assert!(config.pacgate.rules.len() >= 3);
    }

    #[test]
    fn test_import_ipv6() {
        let (config, _) = import_tcpdump_filter("src host 2001:db8::1", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("src_ipv6"));
        assert!(yaml.contains("0x86DD"));
    }

    #[test]
    fn test_import_greater_less() {
        let (config, _) = import_tcpdump_filter("greater 1500", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("frame_len_min: 1501"));

        let (config2, _) = import_tcpdump_filter("less 64", "drop", "test").unwrap();
        let yaml2 = config_to_yaml(&config2).unwrap();
        assert!(yaml2.contains("frame_len_max: 63"));
    }

    #[test]
    fn test_import_default_action_pass() {
        let (config, _) = import_tcpdump_filter("tcp", "pass", "test").unwrap();
        assert_eq!(config.pacgate.defaults.action, Action::Pass);
        // matched rule should be drop (opposite of default)
        assert_eq!(config.pacgate.rules[0].action(), Action::Drop);
    }

    #[test]
    fn test_import_validates() {
        // Import and then verify YAML is valid
        let (config, _) = import_tcpdump_filter("tcp port 80", "drop", "test").unwrap();
        let yaml = config_to_yaml(&config).unwrap();
        // Parse back
        let _: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    }

    #[test]
    fn test_import_ip_proto() {
        let (config, _) = import_tcpdump_filter("ip proto gre", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("ip_protocol: 47"));
    }

    #[test]
    fn test_import_json_summary() {
        let summary = import_tcpdump_summary("tcp port 80", "drop", "test");
        assert_eq!(summary["status"], "ok");
        assert!(summary["rule_count"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_import_json_error() {
        let summary = import_tcpdump_summary("", "drop", "test");
        assert_eq!(summary["status"], "error");
    }

    #[test]
    fn test_import_empty_filter() {
        assert!(import_tcpdump_filter("", "drop", "test").is_err());
    }

    #[test]
    fn test_import_invalid_default_action() {
        assert!(import_tcpdump_filter("tcp", "invalid", "test").is_err());
    }

    #[test]
    fn test_import_bare_protocols() {
        // Each protocol keyword should work standalone
        for proto in &["tcp", "udp", "icmp", "arp", "ip", "ip6", "igmp", "gre"] {
            let (config, _) = import_tcpdump_filter(proto, "drop", "test").unwrap();
            assert!(!config.pacgate.rules.is_empty(), "Failed for {}", proto);
        }
    }

    #[test]
    fn test_import_icmpv6_type() {
        let (config, _) = import_tcpdump_filter("icmp6[icmp6type] == 128", "drop", "test").unwrap();
        assert_eq!(config.pacgate.rules.len(), 1);
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("icmpv6_type: 128"));
    }

    #[test]
    fn test_import_tcp_named_flags() {
        let (config, _) = import_tcpdump_filter("tcp[tcpflags] & tcp-syn != 0", "drop", "test").unwrap();
        let yaml = config_to_yaml(&config).unwrap();
        assert!(yaml.contains("tcp_flags: 0"));
        assert!(yaml.contains("tcp_flags_mask: 2"));
    }
}
