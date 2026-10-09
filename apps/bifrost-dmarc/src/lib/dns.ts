import type { DomainSummary } from "../types";

export function detectedDnsProvider(domain: DomainSummary) {
  return domain.dns_provider?.trim() || domain.nameservers?.find(Boolean)?.trim() || "";
}

export function nameserverSummary(domain: DomainSummary) {
  return domain.nameservers?.length ? domain.nameservers.join(", ") : "No authoritative nameservers were returned.";
}

export function dnsProviderEvidence(domain: DomainSummary) {
  switch (domain.dns_provider_source) {
    case "cloudflare_integration": return "Confirmed by the connected Cloudflare inventory.";
    case "domain_connect": return "Confirmed by the DNS provider through Domain Connect.";
    case "ns_fingerprint": return "Detected from authoritative nameservers.";
    case "soa_fingerprint": return "Detected from the zone's SOA nameserver.";
    case "nameserver": return "The provider was not recognized; the authoritative nameserver is shown instead.";
    default: return domain.dns_provider ? "Detected from authoritative nameservers." : "The DNS provider was not identified.";
  }
}
