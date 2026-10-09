import type { DomainSummary } from "../types";

export function domainHasNoEmail(domain: DomainSummary) {
  if (domain.email_usage_override === "no_email") return true;
  if (domain.email_usage_override === "uses_email") return false;
  const normalizedSpf = domain.spf_record.toLowerCase().trim().replace(/\s+/g, " ");
  return ["null_mx", "no_route"].includes(domain.mx_status ?? "") && normalizedSpf === "v=spf1 -all";
}

export function mailRouteLabel(domain: DomainSummary) {
  if (domain.mx_status === "present") return domain.mx_provider || "Mail Routed";
  if (domain.mx_status === "null_mx") return "Null MX";
  if (domain.mx_status === "implicit") return "Implicit Route";
  if (domain.mx_status === "no_route") return "No Mail Route";
  if (domain.mx_status === "invalid") return "Invalid MX";
  if (domain.mx_status === "lookup_failed") return "Lookup Failed";
  return "Not Checked";
}

export function mailRouteDetail(domain: DomainSummary) {
  if (domain.mx_status === "present") return domain.mx_provider
    ? `Inbound mail is routed through ${domain.mx_provider}.`
    : "Public MX records accept inbound mail for this domain.";
  if (domain.mx_status === "null_mx") return "Public DNS explicitly declares that this domain does not accept inbound email.";
  if (domain.mx_status === "implicit") return "No MX record exists, but mail servers may fall back to the domain's public address.";
  if (domain.mx_status === "no_route") return "No MX record or public address route was found for inbound email.";
  if (domain.mx_status === "invalid") return "Null MX and ordinary MX records are published together. Correct the conflicting records.";
  if (domain.mx_status === "lookup_failed") return "The public MX lookup failed. Bifrost will retry during the next scan.";
  return "Public MX records have not been checked yet.";
}
