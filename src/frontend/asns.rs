use flate2::read::GzDecoder;
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

/// ASN information from ip2asn database
#[derive(Debug, Clone)]
struct ASNEntry {
    first_ip: IpAddr,
    last_ip: IpAddr,
    number: u32,
}

impl PartialEq for ASNEntry {
    fn eq(&self, other: &ASNEntry) -> bool {
        self.first_ip == other.first_ip
    }
}

impl Eq for ASNEntry {}

impl Ord for ASNEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.first_ip.cmp(&other.first_ip)
    }
}

impl PartialOrd for ASNEntry {
    fn partial_cmp(&self, other: &ASNEntry) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Location information from ip2region database
#[derive(Debug, Clone)]
struct LocationEntry {
    start_ip: IpAddr,
    end_ip: IpAddr,
    country: String,
    province: String,
    city: String,
    isp: String,
    country_code: String,
}

impl PartialEq for LocationEntry {
    fn eq(&self, other: &LocationEntry) -> bool {
        self.start_ip == other.start_ip
    }
}

impl Eq for LocationEntry {}

impl Ord for LocationEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start_ip.cmp(&other.start_ip)
    }
}

impl PartialOrd for LocationEntry {
    fn partial_cmp(&self, other: &LocationEntry) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Combined result returned to callers
#[derive(Debug)]
pub struct ASN {
    pub number: u32,
    pub country: String,
    pub description: String,
}

pub struct ASNs {
    // ASN data from ip2asn-combined.tsv.gz
    asn_entries: BTreeSet<ASNEntry>,
    // Location data from ip2region
    ipv4_locations: BTreeSet<LocationEntry>,
    ipv6_locations: BTreeSet<LocationEntry>,
}

/// Check if ip is within the range [start, end]
fn ip_in_range(ip: IpAddr, start: IpAddr, end: IpAddr) -> bool {
    match (ip, start, end) {
        (IpAddr::V4(ip), IpAddr::V4(start), IpAddr::V4(end)) => {
            let ip_u32 = u32::from(ip);
            let start_u32 = u32::from(start);
            let end_u32 = u32::from(end);
            ip_u32 >= start_u32 && ip_u32 <= end_u32
        }
        (IpAddr::V6(ip), IpAddr::V6(start), IpAddr::V6(end)) => {
            let ip_u128 = u128::from(ip);
            let start_u128 = u128::from(start);
            let end_u128 = u128::from(end);
            ip_u128 >= start_u128 && ip_u128 <= end_u128
        }
        _ => false,
    }
}

impl ASNs {
    pub fn new(asn_file_path: &str, ip2region_dir: &str) -> Result<ASNs, &'static str> {
        let mut asn_entries = BTreeSet::new();
        let mut ipv4_locations = BTreeSet::new();
        let mut ipv6_locations = BTreeSet::new();

        // Load ASN database (ip2asn-combined.tsv.gz)
        info!("Loading ASN database from: {}", asn_file_path);
        Self::load_asn_database(asn_file_path, &mut asn_entries)?;
        info!("Loaded {} ASN entries", asn_entries.len());

        // Load ip2region location database
        let dir = Path::new(ip2region_dir);
        let ipv4_file_path = dir.join("ipv4_source.txt");
        let ipv6_file_path = dir.join("ipv6_source.txt");

        if ipv4_file_path.exists() {
            info!("Loading IPv4 location database from: {:?}", ipv4_file_path);
            Self::load_ipv4_locations(&ipv4_file_path, &mut ipv4_locations)?;
            info!("Loaded {} IPv4 location entries", ipv4_locations.len());
        } else {
            warn!("IPv4 location database not found: {:?}", ipv4_file_path);
        }

        if ipv6_file_path.exists() {
            info!("Loading IPv6 location database from: {:?}", ipv6_file_path);
            Self::load_ipv6_locations(&ipv6_file_path, &mut ipv6_locations)?;
            info!("Loaded {} IPv6 location entries", ipv6_locations.len());
        } else {
            warn!("IPv6 location database not found: {:?}", ipv6_file_path);
        }

        let total = asn_entries.len() + ipv4_locations.len() + ipv6_locations.len();
        info!("Database loaded with {} total entries", total);

        Ok(ASNs {
            asn_entries,
            ipv4_locations,
            ipv6_locations,
        })
    }

    /// Load ASN data from ip2asn-combined.tsv.gz
    /// Format: first_ip\tlast_ip\tnumber\tcountry\tdescription
    fn load_asn_database(
        file_path: &str,
        entries: &mut BTreeSet<ASNEntry>,
    ) -> Result<(), &'static str> {
        let f = File::open(file_path).map_err(|_| "Failed to open ASN database file")?;
        let mut data = String::new();
        GzDecoder::new(f)
            .read_to_string(&mut data)
            .map_err(|_| "Failed to decompress ASN database")?;

        for line in data.split_terminator('\n') {
            let mut parts = line.split('\t');

            let first_ip = match parts.next().and_then(|s| IpAddr::from_str(s).ok()) {
                Some(ip) => ip,
                None => continue,
            };

            let last_ip = match parts.next().and_then(|s| IpAddr::from_str(s).ok()) {
                Some(ip) => ip,
                None => continue,
            };

            let number = match parts.next().and_then(|s| u32::from_str(s).ok()) {
                Some(n) => n,
                None => continue,
            };

            // Skip country and description fields (we use ip2region for location)
            let _ = parts.next();
            let _ = parts.next();

            let entry = ASNEntry {
                first_ip,
                last_ip,
                number,
            };
            entries.insert(entry);
        }

        Ok(())
    }

    /// Load IPv4 location entries from ip2region format file
    /// Format: start_ip|end_ip|country|province|city|isp|country_code
    fn load_ipv4_locations(
        file_path: &Path,
        entries: &mut BTreeSet<LocationEntry>,
    ) -> Result<(), &'static str> {
        let file = File::open(file_path).map_err(|_| "Failed to open IPv4 location file")?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() < 7 {
                continue;
            }

            let start_ip = match Ipv4Addr::from_str(parts[0]) {
                Ok(ip) => IpAddr::V4(ip),
                Err(_) => continue,
            };

            let end_ip = match Ipv4Addr::from_str(parts[1]) {
                Ok(ip) => IpAddr::V4(ip),
                Err(_) => continue,
            };

            let entry = LocationEntry {
                start_ip,
                end_ip,
                country: parts[2].to_owned(),
                province: parts[3].to_owned(),
                city: parts[4].to_owned(),
                isp: parts[5].to_owned(),
                country_code: parts[6].to_owned(),
            };
            entries.insert(entry);
        }

        Ok(())
    }

    /// Load IPv6 location entries from ip2region format file
    /// Format: start_ip|end_ip|country|province|city|isp|country_code
    fn load_ipv6_locations(
        file_path: &Path,
        entries: &mut BTreeSet<LocationEntry>,
    ) -> Result<(), &'static str> {
        let file = File::open(file_path).map_err(|_| "Failed to open IPv6 location file")?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() < 7 {
                continue;
            }

            let start_ip = match Ipv6Addr::from_str(parts[0]) {
                Ok(ip) => IpAddr::V6(ip),
                Err(_) => continue,
            };

            let end_ip = match Ipv6Addr::from_str(parts[1]) {
                Ok(ip) => IpAddr::V6(ip),
                Err(_) => continue,
            };

            let entry = LocationEntry {
                start_ip,
                end_ip,
                country: parts[2].to_owned(),
                province: parts[3].to_owned(),
                city: parts[4].to_owned(),
                isp: parts[5].to_owned(),
                country_code: parts[6].to_owned(),
            };
            entries.insert(entry);
        }

        Ok(())
    }

    /// Lookup ASN entry by IP
    fn lookup_asn(&self, ip: IpAddr) -> Option<&ASNEntry> {
        let search_key = ASNEntry {
            first_ip: ip,
            last_ip: ip,
            number: 0,
        };

        for found in self.asn_entries.range(..=&search_key).rev() {
            if ip <= found.last_ip {
                if found.number > 0 {
                    return Some(found);
                }
                // IP is in a "not routed" range (ASN 0), no need to check further
                return None;
            }
            // first_ip <= ip but last_ip < ip, no earlier entry can contain ip
            break;
        }
        None
    }

    /// Lookup location entry by IP
    fn lookup_location(&self, ip: IpAddr) -> Option<&LocationEntry> {
        let locations = match ip {
            IpAddr::V4(_) => &self.ipv4_locations,
            IpAddr::V6(_) => &self.ipv6_locations,
        };

        let search_key = LocationEntry {
            start_ip: ip,
            end_ip: ip,
            country: String::new(),
            province: String::new(),
            city: String::new(),
            isp: String::new(),
            country_code: String::new(),
        };

        for found in locations.range(..=&search_key).rev() {
            if ip_in_range(ip, found.start_ip, found.end_ip) {
                // Skip reserved entries
                if found.country_code != "0" && !found.country_code.is_empty() {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Build location description string from location components
    fn build_location_description(loc: &LocationEntry) -> String {
        let mut parts = Vec::new();

        if !loc.country.is_empty() && loc.country != "0" && loc.country != "Reserved" {
            parts.push(loc.country.as_str());
        }
        if !loc.province.is_empty()
            && loc.province != "0"
            && loc.province != "Reserved"
            && loc.province != loc.country
        {
            parts.push(loc.province.as_str());
        }
        if !loc.city.is_empty()
            && loc.city != "0"
            && loc.city != "Reserved"
            && loc.city != loc.province
        {
            parts.push(loc.city.as_str());
        }
        if !loc.isp.is_empty() && loc.isp != "0" && loc.isp != "Reserved" {
            parts.push(loc.isp.as_str());
        }

        parts.join(" ")
    }

    /// Lookup by IP and return combined ASN + location information
    /// - ASN number: from ip2asn-combined.tsv.gz
    /// - Location info (country, description): from ip2region
    pub fn lookup_by_ip(&self, ip: IpAddr) -> Option<ASN> {
        let asn_entry = self.lookup_asn(ip);
        let location_entry = self.lookup_location(ip);

        // If we have neither ASN nor location info, return None
        if asn_entry.is_none() && location_entry.is_none() {
            return None;
        }

        // Get ASN number from ip2asn database
        let number = asn_entry.map(|e| e.number).unwrap_or(0);

        // Get country code from ip2region
        let country = location_entry
            .map(|e| e.country_code.clone())
            .unwrap_or_default();

        // Get description from ip2region
        let description = location_entry
            .map(|e| Self::build_location_description(e))
            .unwrap_or_default();

        Some(ASN {
            number,
            country,
            description,
        })
    }
}
