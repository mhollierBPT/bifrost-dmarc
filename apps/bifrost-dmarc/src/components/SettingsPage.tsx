import { Check, FileSearch, FileUp, Send } from "lucide-react";
import { useMemo, useState } from "react";

import { fileToBase64, formatDate, formatNumber } from "../lib/format";
import type { DnsChange, Investigation } from "../types";
import { BfButton } from "./bifrost/BfButton";
import { BfCopyField } from "./bifrost/BfCopyField";
import { BfDataTable, type BfDataColumn } from "./bifrost/BfDataTable";
import { BfChip } from "./bifrost/BfChip";
import { LoadingRows } from "./LoadingState";

interface SettingsProps {
  loading?: boolean;
  setup?: {
    reporting_domain: string;
    inbound_address: string;
    authorization_record: string;
    signing_secret_configured?: boolean;
  };
  uploading: boolean;
  uploadResult?: { reports: number; records: number; messages: number };
  uploadError?: string;
  onUpload: (filename: string, contentBase64: string) => Promise<void>;
  investigations?: Investigation[];
  investigationsLoading?: boolean;
  investigationLoading?: boolean;
  emlLoading?: boolean;
  investigationError?: string;
  onCreateInvestigation?: () => Promise<Investigation>;
  onUploadEml?: (filename: string, contentBase64: string) => Promise<Investigation>;
  dnsChanges?: DnsChange[];
  secretImporting?: boolean;
  secretImportError?: string;
  onImportResendSecret?: () => Promise<{ configured: boolean; webhook_id: string; endpoint: string }>;
}

export function SettingsPage(props: SettingsProps) {
  const { setup, uploading, uploadResult, uploadError, onUpload } = props;
  const reportingDomain = setup?.reporting_domain ?? "dmarc.example.com";
  const inboundAddress = setup?.inbound_address ?? `rua@${reportingDomain}`;
  const authorizationRecord = setup?.authorization_record ?? `*._report._dmarc.${reportingDomain}`;
  const handleFile = async (file?: File) => {
    if (!file) return;
    await onUpload(file.name, await fileToBase64(file));
  };
  const [issued, setIssued] = useState<Investigation>();
  const [emlResult, setEmlResult] = useState<Investigation>();
  const localInvestigation = emlResult ?? issued;
  const liveLocalInvestigation = localInvestigation
    ? props.investigations?.find((investigation) => investigation.id === localInvestigation.id)
    : undefined;
  const activeInvestigation = liveLocalInvestigation ?? localInvestigation ?? props.investigations?.[0];
  const authenticationResults = activeInvestigation?.analysis?.results ?? {};
  const findings = activeInvestigation?.analysis?.findings ?? [];
  const handleEml = async (file?: File) => {
    if (!file || !props.onUploadEml) return;
    setEmlResult(await props.onUploadEml(file.name, await fileToBase64(file)));
  };
  const issueAddress = async () => {
    if (props.onCreateInvestigation) setIssued(await props.onCreateInvestigation());
  };
  const auditColumns = useMemo<BfDataColumn<DnsChange>[]>(() => [
    { id: "organization", header: "Organization", width: "22%", sortable: true, accessor: (change) => change.organization_name || "Unassigned" },
    { id: "domain", header: "Domain", width: "24%", sortable: true, accessor: (change) => <strong className="domain-name">{change.domain}</strong>, sortValue: (change) => change.domain },
    { id: "record", header: "Record", width: "10%", sortable: true, accessor: (change) => change.kind.toUpperCase() },
    { id: "action", header: "Action", width: "13%", sortable: true, accessor: "action" },
    { id: "status", header: "Status", width: "16%", sortable: true, sortValue: (change) => change.status, accessor: (change) => <span className="data-row-name"><BfChip tone={change.status === "completed" ? "success" : change.status === "failed" ? "danger" : "info"}>{change.status}</BfChip>{change.error ? <small>{change.error}</small> : null}</span> },
    { id: "date", header: "Date", width: "15%", sortable: true, sortValue: (change) => change.created_at ?? "", accessor: (change) => formatDate(change.created_at) },
  ], []);
  return (
    <div className="page settings-page page-enter" aria-busy={props.loading}>
      <header className="page-header"><div><h1>Settings &amp; Investigation</h1><p>Test mail authentication, verify inbound setup, and review delivery controls.</p></div></header>
      {props.loading && !setup ? <LoadingRows rows={6} label="Loading DMARC settings" /> : null}
      <section className="settings-section"><div className="section-number">1</div><div><h2>Resend Inbound</h2><p>Set the Solution configuration value <code>dmarc_reporting_domain</code>, configure that domain for inbound email in Resend, then subscribe Resend’s <code>email.received</code> webhook to the deployed <strong>DMARC Inbound</strong> callback URL.</p><BfCopyField label="Inbound Address" value={inboundAddress} /><div className="setup-state"><span className="status-dot" /><div><strong>Solution-Managed Webhook</strong><span>The generic Bifrost webhook starts the ingestion workflow; the workflow retrieves attachments through the Resend connection.</span></div></div></div></section>
      <section className="settings-section"><div className="section-number">2</div><div><h2>External Report Authorization</h2><p>This wildcard authorizes source domains to send aggregate reports to the external reporting destination <code>{reportingDomain}</code>. Add it in the DNS zone that contains the reporting domain.</p><BfCopyField label="Complete TXT Name" value={authorizationRecord} /><BfCopyField label="TXT Content" value="v=DMARC1;" /></div></section>
      <section className="settings-section"><div className="section-number">3</div><div><h2>Email Investigation</h2><p>Issue a private, 24-hour address and send a message to it from the system you want to test. Bifrost analyzes the authentication results recorded by the receiving system.</p><div className="investigation-actions"><BfButton icon={<Send aria-hidden="true" />} onClick={issueAddress} disabled={!props.onCreateInvestigation || props.investigationLoading}>{props.investigationLoading ? "Creating…" : "Create Test Address"}</BfButton><span className="live-update-status" role="status"><span className="status-dot" />{props.investigationsLoading ? "Connecting to live results…" : "Results update automatically"}</span></div>{issued?.address ? <BfCopyField label="Send Test Email To" value={issued.address} /> : null}<div className="or-divider"><span>or</span></div><label className={`upload-box compact ${props.emlLoading ? "is-loading" : ""}`}><FileSearch aria-hidden="true" /><strong>{props.emlLoading ? "Analyzing EML…" : "Upload an EML File"}</strong><span>Header analysis only; message content is not returned or displayed</span><input type="file" aria-label="Upload an EML File" accept=".eml,message/rfc822" disabled={props.emlLoading} onChange={(event) => handleEml(event.target.files?.[0])} /></label>{activeInvestigation ? <div className="investigation-result"><div><strong>{activeInvestigation.status === "completed" ? activeInvestigation.subject || "Authentication analysis" : activeInvestigation.status === "waiting" ? "Waiting for your email" : activeInvestigation.status}</strong><span>{activeInvestigation.address || "Uploaded EML"}</span></div>{activeInvestigation.analysis ? <div className="auth-grid">{(["dmarc", "dkim", "spf"] as const).map((method) => { const result = authenticationResults[method] ?? "not_recorded"; return <div key={method}><span>{method.toUpperCase()}</span><strong className={`auth-${result}`}>{result.replace("_", " ")}</strong></div>; })}</div> : null}{findings.map((finding, index) => <div className={`finding finding-${finding.severity}`} key={`${finding.title}-${index}`}><strong>{finding.title}</strong><span>{finding.detail}</span></div>)}{activeInvestigation.analysis?.limitations ? <small>{activeInvestigation.analysis.limitations}</small> : null}</div> : null}{props.investigationError ? <div className="error-banner" role="alert">{props.investigationError}</div> : null}</div></section>
      <section className="settings-section"><div className="section-number">4</div><div><h2>Per-Domain DNS Management</h2><p>Use the Domains page to configure DMARC or SPF. Bifrost automatically compares the managed value with live DNS, refuses duplicate records, writes approved changes through Cloudflare, and records an audit entry.</p><BfCopyField label="Managed RUA Tag" value={`rua=mailto:${inboundAddress}`} /></div></section>
      <section className="settings-section"><div className="section-number">5</div><div><h2>Test Aggregate Ingestion Without DNS</h2><p>Upload a DMARC XML, gzip, or zip report to exercise the same parser and tables without changing a production record.</p><label className={`upload-box ${uploading ? "is-loading" : ""}`}><FileUp aria-hidden="true" /><strong>{uploading ? "Ingesting report…" : "Choose a DMARC Report"}</strong><span>.xml, .xml.gz, .gz, or .zip</span><input type="file" aria-label="Choose a DMARC Report" accept=".xml,.gz,.gzip,.zip,application/xml,application/gzip,application/zip" disabled={uploading} onChange={(event) => handleFile(event.target.files?.[0])} /></label>{uploadResult ? <div className="success-banner" role="status"><Check aria-hidden="true" /><span>Ingested {uploadResult.reports} report, {uploadResult.records} aggregate rows, and {formatNumber(uploadResult.messages)} messages.</span></div> : null}{uploadError ? <div className="error-banner" role="alert">{uploadError}</div> : null}</div></section>
      <section className="settings-section"><div className="section-number">6</div><div><h2>Webhook Verification</h2><p>The Resend signing secret is {setup?.signing_secret_configured ? <strong>configured</strong> : <strong>not configured</strong>}. Importing reads the secret from Resend and stores it encrypted without displaying it.</p>{!setup?.signing_secret_configured ? <BfButton variant="secondary" onClick={props.onImportResendSecret} disabled={!props.onImportResendSecret || props.secretImporting}>{props.secretImporting ? "Importing…" : "Import Signing Secret from Resend"}</BfButton> : null}{props.secretImportError ? <div className="error-banner" role="alert">{props.secretImportError}</div> : null}<p>The workflow includes strict Standard Webhooks verification, timestamp validation, and replay-resistant event IDs. Verification activates when the event contract supplies the exact raw request body; the current generic adapter supplies the signature headers but only forwards parsed JSON. Until that raw-body handoff is available, Bifrost validates the email ID through the authenticated Resend API before processing, restricts recipients, validates attachments, rate-limits, and deduplicates deliveries.</p></div></section>
      <section className="settings-section"><div className="section-number">7</div><div><h2>DNS Change History</h2><p>The latest managed DMARC and SPF attempts, including failed changes. Previous and managed values remain in the audit table for the configured retention period.</p><BfDataTable className="audit-table" ariaLabel="DNS Change History" rows={props.dnsChanges ?? []} columns={auditColumns} getRowId={(change) => change.id} defaultSort={{ columnId: "date", direction: "descending" }} emptyState={{ title: "No managed DNS changes", description: "Automatic DNS comparisons are read-only; completed or failed writes will appear here." }} maxHeight="24rem" minWidth="42rem" /></div></section>
    </div>
  );
}
