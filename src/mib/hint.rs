//! Value rendering for DISPLAY-HINT (RFC 2579 section 3.1) and the explicit
//! formats in [`crate::mib::ValueFormat`].

impl crate::mib::ValueFormat {
    /// Render an OCTET STRING in this format. Returns `None` when the octets
    /// do not fit it (e.g. a 5 octet InetAddress).
    pub fn render(self, octets: &[u8]) -> Option<String> {
        match self {
            crate::mib::ValueFormat::DisplayString => {
                Some(String::from_utf8_lossy(octets).into_owned())
            }
            crate::mib::ValueFormat::OctetString => Some(hex::encode(octets)),
            crate::mib::ValueFormat::PhysAddress48 => Some(
                octets
                    .iter()
                    .map(|o| format!("{o:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            ),
            crate::mib::ValueFormat::InetAddress => match octets.len() {
                4 => Some(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(octets).ok()?).to_string()),
                16 => {
                    Some(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(octets).ok()?).to_string())
                }
                _ => None,
            },
            crate::mib::ValueFormat::DateAndTime => render_date_and_time(octets),
        }
    }
}

/// SNMPv2-TC DateAndTime: 8 octets local time, or 11 with a UTC offset.
fn render_date_and_time(o: &[u8]) -> Option<String> {
    if o.len() != 8 && o.len() != 11 {
        return None;
    }
    let year = u16::from_be_bytes([o[0], o[1]]);
    let (month, day, hour, min, sec, deci) = (o[2], o[3], o[4], o[5], o[6], o[7]);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || min > 59
        || sec > 60
        || deci > 9
    {
        return None;
    }
    let mut s = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{deci}");
    if o.len() == 11 {
        let sign = match o[8] {
            b'+' | b'-' => o[8] as char,
            _ => return None,
        };
        if o[9] > 13 || o[10] > 59 {
            return None;
        }
        s.push_str(&format!("{sign}{:02}:{:02}", o[9], o[10]));
    }
    Some(s)
}

/// Render an OCTET STRING with an RFC 2579 octet-format DISPLAY-HINT such as
/// `255a`, `1x:` or `1d.1d.1d.1d`. Returns `None` for a malformed hint.
pub fn render_octets(hint: &str, octets: &[u8]) -> Option<String> {
    let specs = OctetSpec::parse_all(hint)?;
    let mut out = String::new();
    let mut rest = octets;
    let mut idx = 0;
    while !rest.is_empty() {
        let spec = &specs[idx.min(specs.len() - 1)];
        idx += 1;
        let repeat = if spec.star {
            let n = rest[0] as usize;
            rest = &rest[1..];
            n
        } else {
            1
        };
        for i in 0..repeat {
            if rest.is_empty() {
                break;
            }
            let take = spec.len.min(rest.len());
            let (chunk, tail) = rest.split_at(take);
            rest = tail;
            spec.render_chunk(chunk, &mut out);
            let last_in_repeat = i + 1 == repeat;
            if !rest.is_empty() {
                match (spec.terminator, last_in_repeat) {
                    (Some(t), true) => out.push(t),
                    _ => {
                        if let Some(sep) = spec.separator {
                            out.push(sep);
                        }
                    }
                }
            }
        }
    }
    Some(out)
}

#[derive(Debug)]
struct OctetSpec {
    star: bool,
    len: usize,
    format: char,
    separator: Option<char>,
    terminator: Option<char>,
}

impl OctetSpec {
    fn parse_all(hint: &str) -> Option<Vec<OctetSpec>> {
        let chars: Vec<char> = hint.chars().collect();
        let mut specs = vec![];
        let mut i = 0;
        while i < chars.len() {
            let star = chars[i] == '*';
            if star {
                i += 1;
            }
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let len: usize = chars[start..i].iter().collect::<String>().parse().ok()?;
            let format = *chars.get(i)?;
            if !matches!(format, 'a' | 't' | 'x' | 'd' | 'o') {
                return None;
            }
            i += 1;
            let separator = Self::take_delimiter(&chars, &mut i);
            let terminator = if star && separator.is_some() {
                Self::take_delimiter(&chars, &mut i)
            } else {
                None
            };
            specs.push(OctetSpec {
                star,
                len,
                format,
                separator,
                terminator,
            });
        }
        if specs.is_empty() { None } else { Some(specs) }
    }

    fn take_delimiter(chars: &[char], i: &mut usize) -> Option<char> {
        match chars.get(*i) {
            Some(c) if !c.is_ascii_digit() && *c != '*' => {
                *i += 1;
                Some(*c)
            }
            _ => None,
        }
    }

    fn render_chunk(&self, chunk: &[u8], out: &mut String) {
        match self.format {
            'a' | 't' => out.push_str(&String::from_utf8_lossy(chunk)),
            'x' => {
                for b in chunk {
                    out.push_str(&format!("{b:02x}"));
                }
            }
            'd' | 'o' => {
                let n = chunk
                    .iter()
                    .fold(0u128, |acc, b| (acc << 8) | u128::from(*b));
                if self.format == 'd' {
                    out.push_str(&n.to_string());
                } else {
                    out.push_str(&format!("{n:o}"));
                }
            }
            _ => unreachable!("validated in parse_all"),
        }
    }
}

/// Render an INTEGER with an RFC 2579 integer-format DISPLAY-HINT (`d`,
/// `d-2`, `x`, `o`, `b`). Returns `None` for a malformed hint.
pub fn render_integer(hint: &str, value: i64) -> Option<String> {
    let mut chars = hint.chars();
    match chars.next()? {
        'd' => {
            let rest = chars.as_str();
            if rest.is_empty() {
                return Some(value.to_string());
            }
            let places: usize = rest.strip_prefix('-')?.parse().ok()?;
            let digits = value.unsigned_abs().to_string();
            let padded = format!("{digits:0>width$}", width = places + 1);
            let (int, frac) = padded.split_at(padded.len() - places);
            let sign = if value < 0 { "-" } else { "" };
            Some(format!("{sign}{int}.{frac}"))
        }
        'x' if chars.as_str().is_empty() => Some(format!("{value:x}")),
        'o' if chars.as_str().is_empty() => Some(format!("{value:o}")),
        'b' if chars.as_str().is_empty() => Some(format!("{value:b}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn octets_mac_address() {
        assert_eq!(
            crate::mib::hint::render_octets("1x:", &[0, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]).unwrap(),
            "00:1b:21:aa:bb:cc"
        );
    }

    #[test]
    fn octets_display_string() {
        assert_eq!(
            crate::mib::hint::render_octets("255a", b"eth0").unwrap(),
            "eth0"
        );
    }

    #[test]
    fn octets_dotted_ipv4() {
        assert_eq!(
            crate::mib::hint::render_octets("1d.1d.1d.1d", &[192, 0, 2, 1]).unwrap(),
            "192.0.2.1"
        );
    }

    #[test]
    fn octets_date_and_time_hint() {
        let octets = [0x07, 0xea, 10, 18, 13, 5, 9, 3, b'+', 9, 0];
        assert_eq!(
            crate::mib::hint::render_octets("2d-1d-1d,1d:1d:1d.1d,1a1d:1d", &octets).unwrap(),
            "2026-10-18,13:5:9.3,+9:0"
        );
    }

    #[test]
    fn octets_star_repeat_with_terminator() {
        assert_eq!(
            crate::mib::hint::render_octets("*1x:/1a", &[2, 0xab, 0xcd, b'z']).unwrap(),
            "ab:cd/z"
        );
    }

    #[test]
    fn octets_rejects_malformed_hint() {
        assert!(crate::mib::hint::render_octets("1q", &[1]).is_none());
        assert!(crate::mib::hint::render_octets("", &[1]).is_none());
    }

    #[test]
    fn integer_decimal_places() {
        assert_eq!(
            crate::mib::hint::render_integer("d-2", 1234).unwrap(),
            "12.34"
        );
        assert_eq!(
            crate::mib::hint::render_integer("d-2", -5).unwrap(),
            "-0.05"
        );
        assert_eq!(crate::mib::hint::render_integer("x", 255).unwrap(), "ff");
        assert!(crate::mib::hint::render_integer("z", 1).is_none());
    }

    #[test]
    fn format_date_and_time() {
        let octets = [0x07, 0xea, 10, 18, 13, 5, 9, 3, b'+', 9, 0];
        assert_eq!(
            crate::mib::ValueFormat::DateAndTime
                .render(&octets)
                .unwrap(),
            "2026-10-18T13:05:09.3+09:00"
        );
        assert!(
            crate::mib::ValueFormat::DateAndTime
                .render(&[1, 2])
                .is_none()
        );
    }

    #[test]
    fn format_inet_address() {
        assert_eq!(
            crate::mib::ValueFormat::InetAddress
                .render(&[192, 0, 2, 1])
                .unwrap(),
            "192.0.2.1"
        );
        assert!(
            crate::mib::ValueFormat::InetAddress
                .render(&[1, 2, 3])
                .is_none()
        );
    }
}
