import type { DomainSummary } from "../types";
import { domainHasNoEmail } from "./mail";

export type ReportingStage = "missing_record" | "needs_reporting" | "awaiting_reports" | "reporting_stale" | "reporting_current";
export type PolicyStage = "missing" | "monitor_coverage" | "monitoring" | "ready_for_enforcement" | "staged_enforcement" | "enforced" | "strict";
export type PolicyBucket = "missing" | "monitor" | "quarantine" | "reject" | "strict";
export type DomainAction = "resolve_issue" | "verify_dns" | "review_mail_use" | "publish_reject" | "setup_dns" | "move_reporting" | "await_reports" | "review_evidence" | "enforce" | "tighten_policy" | "complete";
export type BulkMigrationOperation = "reporting" | "monitor" | "reject_no_mail" | "quarantine" | "strict";

export interface DomainMigrationState {
  reportingStage: ReportingStage;
  policyStage: PolicyStage;
  policyBucket: PolicyBucket;
  action: DomainAction;
  actionLabel: string;
  actionDetail: string;
  reportingEligible: boolean;
  monitorEligible: boolean;
  rejectNoMailEligible: boolean;
  rejectNoMailCandidate: boolean;
  quarantineEligible: boolean;
  strictEligible: boolean;
}

export interface MissingDmarcReadiness {
  total: number;
  ready: number;
  reviewEmailUse: number;
  directReject: number;
  manualDns: number;
  blocked: number;
}

function dmarcTag(record: string | undefined, tag: string) {
  const segment = record
    ?.split(";")
    .map((part) => part.trim())
    .find((part) => part.toLowerCase().startsWith(`${tag.toLowerCase()}=`));
  return segment?.split("=", 2)[1]?.trim().toLowerCase() ?? "";
}

function result(
  base: Omit<DomainMigrationState, "action" | "actionLabel" | "actionDetail">,
  action: DomainAction,
  actionDetail: string,
): DomainMigrationState {
  return { ...base, action, actionLabel: ACTION_LABELS[action], actionDetail };
}

export function classifyDomainMigration(domain: DomainSummary): DomainMigrationState {
  const active = domain.lifecycle_status !== "archived";
  const mapped = domain.mapping_status === "mapped";
  const cloudflare = Boolean(domain.cloudflare_zone_id);
  const hasDmarc = Boolean(domain.has_dmarc);
  const noEmail = domainHasNoEmail(domain);
  const emailUseConfirmed = domain.email_usage_override === "uses_email";
  const mailUseNeedsReview = !emailUseConfirmed && ["null_mx", "no_route", "implicit"].includes(domain.mx_status ?? "");
  const verification = domain.dmarc_verification_status ?? "not_checked";
  const verifiedPresent = verification === "verified_present";
  const verifiedAbsent = verification === "verified_absent";
  const reportsToBifrost = Boolean(domain.reports_to_bifrost);
  const reportingStage: ReportingStage = !hasDmarc
    ? "missing_record"
    : !reportsToBifrost
      ? "needs_reporting"
      : domain.reporting_status === "current"
        ? "reporting_current"
        : domain.reporting_status === "stale"
          ? "reporting_stale"
          : "awaiting_reports";

  const policy = domain.dmarc_policy || "missing";
  const pct = domain.dmarc_pct ?? 100;
  const strictAlignment = dmarcTag(domain.dmarc_record, "adkim") === "s" && dmarcTag(domain.dmarc_record, "aspf") === "s";
  const currentEvidence = reportingStage === "reporting_current" && (domain.volume ?? 0) > 0;
  const evidenceReady = currentEvidence && (domain.compliance ?? 0) >= 98;
  let policyStage: PolicyStage;
  let policyBucket: PolicyBucket;
  if (!hasDmarc || ["missing", "not_checked", "lookup_failed", "unknown"].includes(policy)) {
    policyStage = "missing";
    policyBucket = "missing";
  } else if (policy === "none") {
    policyBucket = "monitor";
    if (pct < 100) policyStage = "monitor_coverage";
    else if (evidenceReady) policyStage = "ready_for_enforcement";
    else policyStage = "monitoring";
  } else if (policy === "quarantine") {
    policyBucket = "quarantine";
    policyStage = pct < 100 ? "staged_enforcement" : "enforced";
  } else if (policy === "reject" && strictAlignment && pct === 100) {
    policyBucket = "strict";
    policyStage = "strict";
  } else {
    policyBucket = "reject";
    policyStage = pct < 100 ? "staged_enforcement" : "enforced";
  }

  const base = {
    reportingStage,
    policyStage,
    policyBucket,
    reportingEligible: active && mapped && cloudflare && verifiedPresent && hasDmarc && !reportsToBifrost,
    monitorEligible: active && mapped && cloudflare && verifiedAbsent && !hasDmarc && !noEmail && !mailUseNeedsReview,
    rejectNoMailEligible: active && mapped && cloudflare && verifiedAbsent && !hasDmarc && noEmail,
    rejectNoMailCandidate: active && mapped && cloudflare && verifiedAbsent && !hasDmarc && (noEmail || mailUseNeedsReview),
    quarantineEligible: active && mapped && cloudflare && verifiedPresent && reportsToBifrost && policy === "none" && pct === 100 && evidenceReady,
    strictEligible: active && mapped && cloudflare && verifiedPresent && reportsToBifrost && ["quarantine", "reject"].includes(policy) && policyBucket !== "strict" && pct === 100 && evidenceReady,
  };

  if (!mapped) return result(base, "resolve_issue", "Map this domain to an organization before changing DNS.");
  if (verification === "mismatch") return result(base, "resolve_issue", "Cloudflare and receiver-visible public DNS disagree. Refresh and reconcile DNS before changing policy.");
  if (["not_checked", "", "lookup_failed"].includes(verification)) return result(base, "verify_dns", verification === "lookup_failed" ? "The independent public DNS check failed. Retry the domain scan." : "Run the domain scan to independently verify the current DMARC state.");
  if (reportingStage === "missing_record" && noEmail) return result(base, "publish_reject", cloudflare ? "This domain is confirmed unused for email; publish reject at 100% without a monitoring period." : "This domain is confirmed unused for email; copy the reject-at-100% record to its authoritative DNS provider without a monitoring period.");
  if (reportingStage === "missing_record" && mailUseNeedsReview) return result(base, "review_mail_use", domain.mx_status === "implicit" ? "No explicit MX record was found. Confirm whether this domain sends or receives email before choosing monitor-only or direct reject." : "No inbound route was found. Confirm whether the domain also sends no email before choosing direct reject.");
  if (reportingStage === "missing_record") return result(base, "setup_dns", cloudflare ? "Create a monitor-only policy at 100% and send reports to Bifrost." : "Copy a monitor-only policy at 100% to the authoritative DNS provider and send reports to Bifrost.");
  if (reportingStage === "needs_reporting") return result(base, "move_reporting", cloudflare ? "Preserve the current policy and replace its aggregate-report destination." : "Preserve the current policy and copy the Bifrost aggregate-report destination to the authoritative DNS provider.");
  if (reportingStage === "awaiting_reports") return result(base, "await_reports", "DNS points to Bifrost; aggregate reports normally arrive within 24–48 hours.");
  if (reportingStage === "reporting_stale") return result(base, "resolve_issue", "Bifrost is configured, but no recent aggregate report was received.");
  if (policyStage === "strict") return result(base, "complete", "Reject is at 100% with strict DKIM and SPF alignment.");
  if (policy === "none" && evidenceReady) return result(base, "enforce", "Recent reports are at least 98% compliant; review failures, then move to quarantine.");
  if (["quarantine", "reject"].includes(policy) && evidenceReady) return result(base, "tighten_policy", "Review remaining failures, then move to reject with strict alignment.");
  return result(base, "review_evidence", currentEvidence
    ? "Review authentication failures before increasing enforcement."
    : "Collect current report evidence before increasing enforcement.");
}

export function summarizeMissingDmarcReadiness(domains: DomainSummary[]): MissingDmarcReadiness {
  const summary: MissingDmarcReadiness = {
    total: 0,
    ready: 0,
    reviewEmailUse: 0,
    directReject: 0,
    manualDns: 0,
    blocked: 0,
  };
  domains.forEach((domain) => {
    if (domain.lifecycle_status === "archived") return;
    const state = classifyDomainMigration(domain);
    if (state.policyBucket !== "missing") return;
    summary.total += 1;
    if (state.monitorEligible) summary.ready += 1;
    else if (state.action === "review_mail_use") summary.reviewEmailUse += 1;
    else if (state.action === "publish_reject") summary.directReject += 1;
    else if (state.action === "setup_dns" && !domain.cloudflare_zone_id) summary.manualDns += 1;
    else summary.blocked += 1;
  });
  return summary;
}

export const ACTION_LABELS: Record<DomainAction, string> = {
  resolve_issue: "Resolve Issue",
  verify_dns: "Verify DNS",
  review_mail_use: "Review Email Use",
  publish_reject: "Publish Reject",
  setup_dns: "Set Up DNS",
  move_reporting: "Move Reporting",
  await_reports: "Await Reports",
  review_evidence: "Review Evidence",
  enforce: "Enforce",
  tighten_policy: "Tighten Policy",
  complete: "Complete",
};

export const ACTION_ORDER: DomainAction[] = ["resolve_issue", "verify_dns", "review_mail_use", "publish_reject", "setup_dns", "move_reporting", "await_reports", "review_evidence", "enforce", "tighten_policy", "complete"];

/** Actions that require an operator decision or intervention. Awaiting reports
 * is healthy propagation time, while complete domains need no attention. */
export function domainNeedsAttention(domain: DomainSummary) {
  const action = classifyDomainMigration(domain).action;
  return action !== "await_reports" && action !== "complete";
}

export const POLICY_BUCKET_LABELS: Record<PolicyBucket, string> = {
  missing: "No DMARC",
  monitor: "Monitor Only",
  quarantine: "Quarantine",
  reject: "Reject",
  strict: "Strict",
};

export const REPORTING_STAGE_LABELS: Record<ReportingStage, string> = {
  missing_record: "No Record",
  needs_reporting: "Needs Bifrost RUA",
  awaiting_reports: "Awaiting Reports",
  reporting_stale: "Reports Stale",
  reporting_current: "Reporting Current",
};

export const POLICY_STAGE_LABELS: Record<PolicyStage, string> = {
  missing: "No Policy",
  monitor_coverage: "Monitor Below 100%",
  monitoring: "Monitoring",
  ready_for_enforcement: "Ready for Enforcement",
  staged_enforcement: "Partial Enforcement",
  enforced: "Enforced",
  strict: "Strict",
};
