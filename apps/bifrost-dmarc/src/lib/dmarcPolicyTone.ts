export type DmarcPolicyTone = "success" | "warning" | "danger" | "info" | "neutral";

export function dmarcPolicyTone(value?: string): DmarcPolicyTone {
  if (value === "reject") return "success";
  if (value === "quarantine") return "info";
  if (value === "none") return "warning";
  if (["missing", "lookup_failed", "not_configured"].includes(value ?? "")) return "danger";
  if (["not_checked", "unknown"].includes(value ?? "")) return "warning";
  return "neutral";
}
