import { describe, expect, it } from "vitest";

import { inclusiveDateQueryValue } from "./date-query";

describe("inclusiveDateQueryValue", () => {
  it("expands a calendar end date to an inclusive UTC day bound", () => {
    expect(inclusiveDateQueryValue("date_to", "2026-08-31")).toBe("2026-08-31T23:59:59.999Z");
    expect(inclusiveDateQueryValue("date_from", "2026-08-01")).toBe("2026-08-01T00:00:00.000Z");
  });

  it("leaves non-date values unchanged", () => {
    expect(inclusiveDateQueryValue("query", "notes")).toBe("notes");
    expect(inclusiveDateQueryValue("date_to", "2026-08-31T12:00:00Z")).toBe("2026-08-31T12:00:00Z");
  });
});
