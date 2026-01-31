use csv::ReaderBuilder;
use ipnetwork::IpNetwork;
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::prelude::*;
use std::net::IpAddr;
use std::ops::Bound::{Included, Unbounded};
use std::str::FromStr;
use zip::ZipArchive;

#[derive(Debug)]
pub struct ASN {
    pub network: IpNetwork,
    pub number: u32,
    pub country: String,
    pub description: String,
}

impl PartialEq for ASN {
    fn eq(&self, other: &ASN) -> bool {
        self.network == other.network
    }
}

impl Eq for ASN {}

impl Ord for ASN {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare by the network address for ordering
        let self_ip = self.network.network();
        let other_ip = other.network.network();
        self_ip.cmp(&other_ip)
    }
}

impl PartialOrd for ASN {
    fn partial_cmp(&self, other: &ASN) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ASN {
    fn from_single_ip(ip: IpAddr) -> ASN {
        let network = match ip {
            IpAddr::V4(v4) => IpNetwork::V4(ipnetwork::Ipv4Network::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNetwork::V6(ipnetwork::Ipv6Network::new(v6, 128).unwrap()),
        };
        ASN {
            network,
            number: 0,
            country: String::new(),
            description: String::new(),
        }
    }
}

pub struct ASNs {
    asns: BTreeSet<ASN>,
}

impl ASNs {
    pub fn new(file_path: &str) -> Result<ASNs, &'static str> {
        info!("Loading the database");
        let f = File::open(file_path).expect("wrong asn db file path");
        let mut archive = ZipArchive::new(f).expect("failed to open zip archive");

        // Assuming the CSV file is the first file in the archive or has a known name
        let mut csv_file = if archive.len() > 0 {
            archive.by_index(0).expect("failed to read file from archive")
        } else {
            return Err("empty zip archive");
        };

        let mut csv_data = String::new();
        csv_file.read_to_string(&mut csv_data).expect("failed to read CSV data");

        let mut asns = BTreeSet::new();
        let mut rdr = ReaderBuilder::new()
            .has_headers(true)
            .from_reader(csv_data.as_bytes());

        for result in rdr.records() {
            let record = result.expect("failed to parse CSV record");

            // CSV format: network, asn, country_code, name, org, domain
            let network_str = record.get(0).unwrap_or("");
            let asn_str = record.get(1).unwrap_or("0");
            let country = record.get(2).unwrap_or("").to_owned();
            let name = record.get(3).unwrap_or("");
            let org = record.get(4).unwrap_or("");

            // Parse the network in CIDR notation
            if let Ok(network) = IpNetwork::from_str(network_str) {
                if let Ok(number) = u32::from_str(asn_str) {
                    // Combine name and org for description
                    let description = if !org.is_empty() {
                        org.to_owned()
                    } else {
                        name.to_owned()
                    };

                    let asn = ASN {
                        network,
                        number,
                        country,
                        description,
                    };
                    asns.insert(asn);
                }
            }
        }

        info!("Database loaded with {} entries", asns.len());
        Ok(ASNs { asns })
    }

    pub fn lookup_by_ip(&self, ip: IpAddr) -> Option<&ASN> {
        let fasn = ASN::from_single_ip(ip);

        // Find the largest network address that is <= the search IP
        match self.asns.range((Unbounded, Included(&fasn))).next_back() {
            Some(found) if found.network.contains(ip) && found.number > 0 => Some(found),
            _ => None,
        }
    }
}
