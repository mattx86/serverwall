use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use maxminddb::geoip2;

use crate::acl::AclDecision;
use crate::config::schema::GeoConfig;

/// Geo-IP based access control.
///
/// Uses a MaxMind GeoIP2 `.mmdb` database to look up the country for each
/// connecting IP and then applies block/allow country lists.
pub struct GeoEngine {
    reader: maxminddb::Reader<Vec<u8>>,
    block_countries: HashSet<String>,
    allow_countries: HashSet<String>,
}

impl GeoEngine {
    /// Load a `GeoEngine` from the configuration.
    ///
    /// Returns `None` if geo checking is disabled or no database path is set.
    pub fn from_config(config: &GeoConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let db_path = config.database_path.as_deref()?;
        match Self::load(db_path, &config.block_countries, &config.allow_countries) {
            Ok(engine) => Some(engine),
            Err(e) => {
                tracing::warn!(
                    db = %db_path.display(),
                    error = %e,
                    "failed to load GeoIP database; geo blocking disabled",
                );
                None
            }
        }
    }

    fn load(
        db_path: &Path,
        block: &[String],
        allow: &[String],
    ) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = maxminddb::Reader::open_readfile(db_path)?;
        Ok(Self {
            reader,
            block_countries: block.iter().map(|s| s.to_uppercase()).collect(),
            allow_countries: allow.iter().map(|s| s.to_uppercase()).collect(),
        })
    }

    /// Evaluate whether `ip` should be allowed based on geo country.
    ///
    /// Decision logic:
    /// 1. If `allow_countries` is non-empty, the IP's country MUST be in it.
    /// 2. If `block_countries` is non-empty, the IP's country must NOT be in it.
    /// 3. If the country cannot be determined, `Allow` is returned.
    pub fn check(&self, ip: IpAddr) -> AclDecision {
        let country_code = self.lookup_country(ip);

        if !self.allow_countries.is_empty() {
            return match &country_code {
                Some(cc) if self.allow_countries.contains(cc) => AclDecision::Allow,
                _ => AclDecision::Deny,
            };
        }

        if !self.block_countries.is_empty() {
            if let Some(ref cc) = country_code {
                if self.block_countries.contains(cc.as_str()) {
                    return AclDecision::Deny;
                }
            }
        }

        AclDecision::Allow
    }

    fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let record: Result<geoip2::Country, _> = self.reader.lookup(ip);
        record
            .ok()
            .and_then(|c| c.country)
            .and_then(|c| c.iso_code)
            .map(|s| s.to_uppercase())
    }
}
