import { describe, expect, it } from "vitest";

import { formatNumber, formatPercent, relativeTime } from "./format";

describe("format helpers", () => {
  it("formats operational metrics consistently", () => {
    expect(formatNumber(200418)).toBe("200,418");
    expect(formatPercent(98.24)).toBe("98.2%");
  });

  it("formats relative ingest time", () => {
    const now = new Date("2026-08-13T12:10:00Z").getTime();
    expect(relativeTime("2026-08-13T12:02:00Z", now)).toBe("8m ago");
  });
});
