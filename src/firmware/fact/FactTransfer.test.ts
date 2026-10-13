import { expect, it, vi } from "vitest";
import { FACT_LIMITS } from "./FactProtocol.js";
import { factJsonBytes, factUploadBody } from "./FactTransfer.js";

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
it("admits exact upload metadata max and rejects max plus one before base64 allocation", async () => {
  const fixed = factJsonBytes({ name: "", binary: "" });
  const prefix = "\u0000é🚀";
  const remaining = FACT_LIMITS.jsonBytes - fixed - (factJsonBytes(prefix) - 2);
  const name = prefix + "x".repeat(remaining);
  const bytes = Buffer.from("abc");
  const request = factUploadBody({ name }, bytes);
  const serialized = await new Response(request.body).text();
  expect(JSON.parse(serialized).binary).toBe("YWJj");
  expect(Buffer.byteLength(serialized)).toBe(request.wireBytes);
  let encoded = false;
  const original = bytes.toString.bind(bytes);
  bytes.toString = (...args) => {
    encoded = true;
    return original(...args);
  };
  let serializedOverflow = false;
  const stringify = JSON.stringify;
  const serialization = vi
    .spyOn(JSON, "stringify")
    .mockImplementation((value, replacer, space) => {
      if (
        value !== null &&
        typeof value === "object" &&
        "name" in value &&
        value.name === name + "x"
      )
        serializedOverflow = true;
      return stringify(value, replacer, space);
    });
  try {
    expect(() => factUploadBody({ name: name + "x" }, bytes)).toThrow(
      "metadata",
    );
    expect(serializedOverflow).toBe(false);
  } finally {
    serialization.mockRestore();
  }
  expect(encoded).toBe(false);
});

it("admits the default raw maximum lazily and rejects max plus one without encoding it", async () => {
  const maximum = Buffer.allocUnsafeSlow(FACT_LIMITS.rawBytes);
  const request = factUploadBody({}, maximum);
  expect(request.wireBytes).toBe(
    factJsonBytes({ binary: "" }) + 4 * Math.ceil(FACT_LIMITS.rawBytes / 3),
  );
  await request.body.cancel();
  const overflow = Buffer.allocUnsafeSlow(FACT_LIMITS.rawBytes + 1);
  expect(() => factUploadBody({}, overflow)).toThrow("raw byte budget");
});
