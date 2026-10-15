import { expect, it } from "vitest";
import { factJsonBytes } from "./FactTransfer.js";

it("measures actual JSON escapes and Unicode before serialization", () => {
  for (const value of [
    "é🚀",
    '\u0000\n\r\t\b\f"\\',
    "\ud800",
    "\udfff",
    { nested: [true, false, null, "é🚀"] },
  ])
    expect(factJsonBytes(value)).toBe(Buffer.byteLength(JSON.stringify(value)));
});
