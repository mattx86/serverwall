use anyhow::{Context, Result};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

/// A resolved MX host with its priority.
#[derive(Debug, Clone)]
pub struct MxHost {
    pub hostname: String,
    pub priority: u16,
    pub addresses: Vec<std::net::IpAddr>,
}

/// Resolves MX records for outbound delivery.
pub struct MxResolver {
    resolver: TokioAsyncResolver,
}

impl MxResolver {
    /// Create a new resolver using the system DNS configuration.
    pub fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        Ok(Self { resolver })
    }

    /// Resolve MX records for `domain`, returning hosts sorted by priority
    /// (lowest first). Falls back to an A/AAAA lookup on the domain itself
    /// if no MX records exist.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<MxHost>> {
        // Try MX lookup
        match self.resolver.mx_lookup(domain).await {
            Ok(mx_response) => {
                let mut hosts: Vec<(u16, String)> = mx_response
                    .iter()
                    .map(|mx| (mx.preference(), mx.exchange().to_string().trim_end_matches('.').to_string()))
                    .collect();

                // Sort by priority (lowest first)
                hosts.sort_by_key(|(prio, _)| *prio);

                let mut result = Vec::new();
                for (priority, hostname) in hosts {
                    let addresses = self.resolve_host(&hostname).await.unwrap_or_default();
                    if !addresses.is_empty() {
                        result.push(MxHost {
                            hostname,
                            priority,
                            addresses,
                        });
                    }
                }

                if result.is_empty() {
                    // MX records found but none resolvable — fall back to A record
                    return self.fallback_a_record(domain).await;
                }

                Ok(result)
            }
            Err(_) => {
                // No MX records — fall back to A/AAAA on the domain itself
                self.fallback_a_record(domain).await
            }
        }
    }

    /// Look up A and AAAA records for a hostname.
    async fn resolve_host(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>> {
        let lookup = self
            .resolver
            .lookup_ip(hostname)
            .await
            .with_context(|| format!("failed to resolve {hostname}"))?;
        Ok(lookup.iter().collect())
    }

    /// Fall back to treating the domain itself as the mail host.
    async fn fallback_a_record(&self, domain: &str) -> Result<Vec<MxHost>> {
        let addresses = self.resolve_host(domain).await?;
        if addresses.is_empty() {
            anyhow::bail!("no MX or A/AAAA records found for {domain}");
        }
        Ok(vec![MxHost {
            hostname: domain.to_string(),
            priority: 0,
            addresses,
        }])
    }
}
