import { describe, expect, it } from "vitest";

import { dmarcPolicyTone } from "./dmarcPolicyTone";

describe("dmarcPolicyTone", () => {
  it("maps reject, quarantine, and none to the intended tones", () => {
    expect(dmarcPolicyTone("reject")).toBe("success");
    expect(dmarcPolicyTone("quarantine")).toBe("info");
    expect(dmarcPolicyTone("none")).toBe("warning");
  });

  it("keeps missing policies dangerous and unknown values warning", () => {
    expect(dmarcPolicyTone("missing")).toBe("danger");
    expect(dmarcPolicyTone("unknown")).toBe("warning");
    expect(dmarcPolicyTone(undefined)).toBe("neutral");
  });
});
