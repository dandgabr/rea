import { expect, it } from "vitest";
import { knownSensitiveValueRedactor } from "./knownSensitiveValueRedaction.js";

it("uses the existing replacement convention when declared identities overlap the marker", () => {
  for (const secret of ["R", "]", "[REDACTED]"]) {
    const redactor = knownSensitiveValueRedactor(secret);
    expect(redactor.text(secret)).toBe("…");
    expect(
      redactor.value({ field: secret, ordinary: "untouched漢字" }),
    ).toEqual({
      field: "…",
      ordinary: "untouched漢字",
    });
  }
  expect(knownSensitiveValueRedactor("…").text("…")).toBe("[REDACTED]");
  // The uppercase Latin-1 byte identity ED overlaps the default marker.
  expect(knownSensitiveValueRedactor("í", "latin1").text("ED")).toBe("…");
});

it("redacts exact malformed UTF-16 literals without manufacturing replacement-byte identities", () => {
  const controls = "ordinary � efbfbd EFBFBD 77+9 %EF%BF%BD 漢字😀";
  for (const secret of [
    "\ud800",
    "\udfff",
    "\ud83d",
    "\ude00",
    "a\ud800b",
    "a\udfffb",
    "\udfff\ud800",
  ]) {
    const redactor = knownSensitiveValueRedactor(secret);
    expect(redactor.text(secret)).toBe("[REDACTED]");
    expect(redactor.text(JSON.stringify(secret).slice(1, -1))).toBe(
      "[REDACTED]",
    );
    expect(redactor.text(controls)).toBe(controls);
    expect(redactor.value({ [secret]: secret, finding: controls })).toEqual({
      "[REDACTED]": "[REDACTED]",
      finding: controls,
    });
  }
});
it("preserves the scalar secret and all its byte encodings, with no restriction on ordinary Unicode", () => {
  for (const secret of [
    "clé privée",
    "秘密🗝️",
    "\ud800\udc00",
    "\udbff\udfff",
  ]) {
    const redactor = knownSensitiveValueRedactor(secret);
    for (const encoded of [
      secret,
      JSON.stringify(secret).slice(1, -1),
      encodeURIComponent(secret),
      Buffer.from(secret).toString("base64"),
      Buffer.from(secret).toString("hex"),
    ])
      expect(redactor.text(encoded)).toBe("[REDACTED]");
    expect(redactor.text("ordinary � /firmware/漢字😀.bin")).toBe(
      "ordinary � /firmware/漢字😀.bin",
    );
  }
  for (const absent of [undefined, ""])
    expect(knownSensitiveValueRedactor(absent).text("ordinary漢字😀")).toBe(
      "ordinary漢字😀",
    );
});

it("runs bounded malformed-secret properties without equating repaired bytes with the selected literal", () => {
  let seed = 0xfac70303;
  for (let index = 0; index < 64; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const secret = `literal[${String.fromCharCode(0xd800 + (seed % 0x800))}]漢.*`;
    const redactor = knownSensitiveValueRedactor(secret);
    expect(redactor.text(secret)).toBe("[REDACTED]");
    expect(redactor.text(JSON.stringify(secret).slice(1, -1))).toBe(
      "[REDACTED]",
    );
    const repaired = Buffer.from(secret).toString();
    for (const control of [
      repaired,
      encodeURIComponent(repaired),
      Buffer.from(secret).toString("hex"),
      Buffer.from(secret).toString("base64"),
    ])
      expect(redactor.text(control)).toBe(control);
  }
});

it("adds explicitly selected lossless wire bytes without replacing native UTF-8 identities", () => {
  const secret = "clé privée";
  const redactor = knownSensitiveValueRedactor(secret, "latin1");
  const wire = Buffer.from(secret, "latin1");
  for (const encoded of [
    wire.toString("base64"),
    wire.toString("hex"),
    wire.toString("hex").toUpperCase(),
    [...wire].map((byte) => `%${byte.toString(16).padStart(2, "0")}`).join(""),
    secret.replaceAll("é", "%E9"),
    encodeURIComponent(secret),
    Buffer.from(secret).toString("hex"),
  ])
    expect(redactor.text(encoded)).toBe("[REDACTED]");
  expect(knownSensitiveValueRedactor(secret).text(wire.toString("hex"))).toBe(
    wire.toString("hex"),
  );
  const nonByteString = "秘密🗝️";
  const unsupported = knownSensitiveValueRedactor(nonByteString, "latin1");
  const truncated = Buffer.from(nonByteString, "latin1").toString("hex");
  expect(unsupported.text(truncated)).toBe(truncated);
  expect(unsupported.text(nonByteString)).toBe("[REDACTED]");
  expect(unsupported.text(encodeURIComponent(nonByteString))).toBe(
    "[REDACTED]",
  );
});
