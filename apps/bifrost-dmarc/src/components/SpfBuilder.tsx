import { Network, Plus, Server, ShieldCheck, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";

import { BfButton, BfIconButton } from "./bifrost/BfButton";
import { BfSelect, BfTextField } from "./bifrost/BfField";
import "./SpfBuilder.css";

interface SpfBuilderProps {
  terms: string[];
  onChange: (terms: string[]) => void;
}

type MechanismGroup = "include" | "ip4" | "ip6" | "a" | "mx" | "advanced";
type AdvancedMechanism = "exists" | "redirect";

const terminalPattern = /^[+\-~?]?all$/i;
const redirectPattern = /^redirect=/i;

const mechanismChoices: Array<{
  value: MechanismGroup;
  label: string;
  detail: string;
  icon: typeof Server;
}> = [
  { value: "include", label: "Include", detail: "Hosted service", icon: Server },
  { value: "ip4", label: "IPv4", detail: "Address or network", icon: Network },
  { value: "ip6", label: "IPv6", detail: "Address or network", icon: Network },
  { value: "a", label: "A", detail: "This domain", icon: Network },
  { value: "mx", label: "MX", detail: "This domain", icon: Server },
  { value: "advanced", label: "Advanced", detail: "Exists or redirect", icon: ShieldCheck },
];

function describeTerm(term: string) {
  const bare = term.replace(/^[+\-~?]/, "");
  const lower = bare.toLowerCase();

  if (lower.startsWith("include:")) return { title: "Include", detail: bare.slice(8), icon: Server };
  if (lower.startsWith("ip4:")) return { title: "IPv4", detail: bare.slice(4), icon: Network };
  if (lower.startsWith("ip6:")) return { title: "IPv6", detail: bare.slice(4), icon: Network };
  if (lower === "a" || lower.startsWith("a:")) return { title: "A", detail: bare.slice(2) || "This domain", icon: Network };
  if (lower === "mx" || lower.startsWith("mx:")) return { title: "MX", detail: bare.slice(3) || "This domain", icon: Server };
  if (lower.startsWith("exists:")) return { title: "Exists", detail: bare.slice(7), icon: ShieldCheck };
  if (lower.startsWith("redirect=")) return { title: "Redirect", detail: bare.slice(9), icon: ShieldCheck };
  return { title: "SPF Mechanism", detail: term, icon: ShieldCheck };
}

function buildMechanismLabel(mechanism: MechanismGroup | AdvancedMechanism): { label: string; placeholder: string; hint: string } {
  switch (mechanism) {
    case "include":
      return { label: "Include Domain or Host", placeholder: "spf.protection.outlook.com", hint: "Required for hosted sender services." };
    case "ip4":
      return { label: "IPv4 Address or Network", placeholder: "192.0.2.10/32", hint: "Enter the address or a CIDR range." };
    case "ip6":
      return { label: "IPv6 Address or Network", placeholder: "2001:db8::/32", hint: "Enter the address or a CIDR range." };
    case "a":
      return { label: "A Record Target", placeholder: "example.com", hint: "Optional. Uses the domain's A record when blank." };
    case "mx":
      return { label: "MX Host", placeholder: "example.com", hint: "Optional. Uses the domain's MX hosts when blank." };
    case "exists":
      return { label: "Exists Check Host", placeholder: "example.com", hint: "Resolve the host and only add it when it exists." };
    case "redirect":
      return { label: "Redirect Target", placeholder: "spf.example.com", hint: "Send the terminal decision to another policy." };
  }

  throw new Error(`Unsupported SPF mechanism: ${mechanism}`);
}

export function SpfBuilder({ terms, onChange }: SpfBuilderProps) {
  const [mechanismGroup, setMechanismGroup] = useState<MechanismGroup>("include");
  const [advancedMechanism, setAdvancedMechanism] = useState<AdvancedMechanism>("exists");
  const [value, setValue] = useState("");

  const terminal = terms.find((term) => terminalPattern.test(term)) ?? "~all";
  const redirect = terms.find((term) => redirectPattern.test(term));
  const sources = useMemo(() => terms.filter((term) => !terminalPattern.test(term)), [terms]);
  const activeMechanism = mechanismGroup === "advanced" ? advancedMechanism : mechanismGroup;
  const mechanismCopy = buildMechanismLabel(activeMechanism);
  const requiresValue = !["a", "mx"].includes(activeMechanism);

  const addSource = () => {
    const cleaned = value.trim();
    if (requiresValue && !cleaned) return;

    const nextTerm =
      activeMechanism === "redirect"
        ? `redirect=${cleaned}`
        : ["a", "mx"].includes(activeMechanism) && !cleaned
          ? activeMechanism
          : `${activeMechanism}:${cleaned}`;

    const withoutPolicy = terms.filter((term) => !terminalPattern.test(term) && !redirectPattern.test(term));
    if (activeMechanism === "redirect") {
      onChange([...withoutPolicy, nextTerm]);
    } else {
      onChange([...withoutPolicy, nextTerm, redirect ?? terminal]);
    }
    setValue("");
  };

  const removeSource = (index: number) => {
    const nextSources = sources.filter((_, itemIndex) => itemIndex !== index);
    const hasRedirect = nextSources.some((term) => redirectPattern.test(term));
    onChange(hasRedirect ? nextSources : [...nextSources, terminal]);
  };

  const setPolicy = (next: string) => {
    const withoutPolicy = terms.filter((term) => !terminalPattern.test(term) && !redirectPattern.test(term));
    onChange([...withoutPolicy, next]);
  };

  return (
    <section className="spf-workbench">
      <header className="spf-workbench__header">
        <div className="spf-workbench__title">
          <h3>Authorized Senders</h3>
          <p>Add each service, server, or redirect that can send mail for this domain.</p>
        </div>
        <span className="spf-workbench__count" aria-live="polite">
          {sources.length} sender{sources.length === 1 ? "" : "s"}
        </span>
      </header>

      <ul className="spf-workbench__list" aria-label="Current authorized senders">
        {sources.map((term, index) => {
          const item = describeTerm(term);
          const Icon = item.icon;

          return (
            <li className="spf-workbench__source" key={`${term}-${index}`}>
              <span className="spf-workbench__source-icon" aria-hidden="true">
                <Icon />
              </span>
              <div className="spf-workbench__source-copy">
                <strong>{item.title}</strong>
                <code>{item.detail}</code>
              </div>
              <BfIconButton
                label={`Remove ${item.title} ${item.detail}`}
                icon={<Trash2 />}
                variant="danger"
                size="compact"
                onClick={() => removeSource(index)}
              />
            </li>
          );
        })}
        {!sources.length ? (
          <li className="spf-workbench__empty">
            No authorized senders yet. Add the first source below.
          </li>
        ) : null}
      </ul>

      <section className="spf-workbench__composer" aria-labelledby="spf-workbench-composer-title">
        <div className="spf-workbench__composer-header">
          <div>
            <h4 id="spf-workbench-composer-title">Add Sender</h4>
            <p>Choose a mechanism, enter the target, then add it to the record.</p>
          </div>
        </div>

        <div className="spf-workbench__mechanisms" role="group" aria-label="Sender mechanism">
          {mechanismChoices.map((choice) => {
            const Icon = choice.icon;
            const selected = choice.value === mechanismGroup;
            return (
              <button
                key={choice.value}
                className={`spf-workbench__mechanism ${selected ? "is-selected" : ""}`}
                type="button"
                aria-pressed={selected}
                onClick={() => setMechanismGroup(choice.value)}
              >
                <span className="spf-workbench__mechanism-icon" aria-hidden="true"><Icon /></span>
                <span className="spf-workbench__mechanism-copy">
                  <strong>{choice.label}</strong>
                  <small>{choice.detail}</small>
                </span>
              </button>
            );
          })}
        </div>

        {mechanismGroup === "advanced" ? (
          <div className="spf-workbench__advanced">
            <BfSelect
              className="spf-workbench__field"
              label="Advanced Mechanism"
              value={advancedMechanism}
              onValueChange={(value) => setAdvancedMechanism(value as AdvancedMechanism)}
              options={[
                { value: "exists", label: "Exists" },
                { value: "redirect", label: "Redirect" },
              ]}
            />
          </div>
        ) : null}

        <BfTextField
          className="spf-workbench__field"
          label={mechanismCopy.label}
          hint={mechanismCopy.hint}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder={mechanismCopy.placeholder}
          autoComplete="off"
        />

        <div className="spf-workbench__composer-footer">
          <BfButton
            className="spf-workbench__submit"
            variant="secondary"
            icon={<Plus aria-hidden="true" />}
            onClick={addSource}
            type="button"
            disabled={requiresValue && !value.trim()}
          >
            Add Sender
          </BfButton>
        </div>
      </section>

      <section className="spf-workbench__policy" aria-labelledby="spf-workbench-policy-title">
        <div className="spf-workbench__policy-copy">
          <h4 id="spf-workbench-policy-title">Terminal Policy</h4>
          <p>Choose what happens after every approved sender has been checked.</p>
        </div>
        {redirect ? (
          <div className="spf-workbench__redirect-note" role="status">
            <ShieldCheck aria-hidden="true" />
            <span>
              This record delegates the final decision to <code>{redirect.slice(9)}</code>.
            </span>
          </div>
        ) : (
          <BfSelect
            className="spf-workbench__field"
            label="Terminal Policy"
            hideLabel
            value={terminal}
            onValueChange={setPolicy}
            options={[
              { value: "~all", label: "Mark as Suspicious (Recommended While Testing)" },
              { value: "-all", label: "Reject" },
              { value: "?all", label: "Make No Decision" },
              { value: "+all", label: "Allow (Not Recommended)" },
            ]}
          />
        )}
      </section>
    </section>
  );
}
