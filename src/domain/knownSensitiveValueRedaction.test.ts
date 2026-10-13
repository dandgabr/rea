import { selectExplicitRedactionReplacement } from "./explicitSensitiveValues.js";
import type { Result } from "./result.js";
const unwrap = <T>(result: Result<T, Error>): T => {
  if (!result.ok) throw result.error;
  return result.value;
};
import { expect, it } from "vitest";
import { knownSensitiveValueRedactor } from "./knownSensitiveValueRedaction.js";

it("uses the existing replacement convention when declared identities overlap the marker", () => {
  for (const secret of ["R", "]", "[REDACTED]"]) {
    const redactor = knownSensitiveValueRedactor(secret);
    expect(unwrap(redactor.text(secret))).toBe("…");
    expect(
      unwrap(redactor.value({ field: secret, ordinary: "untouched漢字" })),
    ).toEqual({
      field: "…",
      ordinary: "untouched漢字",
    });
  }
  expect(unwrap(knownSensitiveValueRedactor("…").text("…"))).toBe("[REDACTED]");
  // The uppercase Latin-1 byte identity ED overlaps the default marker.
  expect(unwrap(knownSensitiveValueRedactor("í", "latin1").text("ED"))).toBe(
    "…",
  );
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
    expect(unwrap(redactor.text(secret))).toBe("[REDACTED]");
    expect(unwrap(redactor.text(JSON.stringify(secret).slice(1, -1)))).toBe(
      "[REDACTED]",
    );
    expect(unwrap(redactor.text(controls))).toBe(controls);
    expect(
      unwrap(redactor.value({ [secret]: secret, finding: controls })),
    ).toEqual({
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
      expect(unwrap(redactor.text(encoded))).toBe("[REDACTED]");
    expect(unwrap(redactor.text("ordinary � /firmware/漢字😀.bin"))).toBe(
      "ordinary � /firmware/漢字😀.bin",
    );
  }
  for (const absent of [undefined, ""])
    expect(
      unwrap(knownSensitiveValueRedactor(absent).text("ordinary漢字😀")),
    ).toBe("ordinary漢字😀");
});

it("runs bounded malformed-secret properties without equating repaired bytes with the selected literal", () => {
  let seed = 0xfac70303;
  for (let index = 0; index < 64; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const secret = `literal[${String.fromCharCode(0xd800 + (seed % 0x800))}]漢.*`;
    const redactor = knownSensitiveValueRedactor(secret);
    expect(unwrap(redactor.text(secret))).toBe("[REDACTED]");
    expect(unwrap(redactor.text(JSON.stringify(secret).slice(1, -1)))).toBe(
      "[REDACTED]",
    );
    const repaired = Buffer.from(secret).toString();
    for (const control of [
      repaired,
      encodeURIComponent(repaired),
      Buffer.from(secret).toString("hex"),
      Buffer.from(secret).toString("base64"),
    ])
      expect(unwrap(redactor.text(control))).toBe(control);
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
    expect(unwrap(redactor.text(encoded))).toBe("[REDACTED]");
  expect(
    unwrap(knownSensitiveValueRedactor(secret).text(wire.toString("hex"))),
  ).toBe(wire.toString("hex"));
  const nonByteString = "秘密🗝️";
  const unsupported = knownSensitiveValueRedactor(nonByteString, "latin1");
  const truncated = Buffer.from(nonByteString, "latin1").toString("hex");
  expect(unwrap(unsupported.text(truncated))).toBe(truncated);
  expect(unwrap(unsupported.text(nonByteString))).toBe("[REDACTED]");
  expect(unwrap(unsupported.text(encodeURIComponent(nonByteString)))).toBe(
    "[REDACTED]",
  );
});

it("matches the frozen short raw/percent alternation semantics over bounded seeded cases", () => {
  const legacy = (secret: string, input: string, latin1: boolean) => {
    const variants = [
      ...new Set([
        secret,
        encodeURIComponent(secret),
        Buffer.from(secret).toString("base64"),
        Buffer.from(secret).toString("hex"),
        Buffer.from(secret).toString("hex").toUpperCase(),
        JSON.stringify(secret).slice(1, -1),
        ...(latin1 && !/[^\u0000-\u00ff]/u.test(secret)
          ? [
              Buffer.from(secret, "latin1").toString("base64"),
              Buffer.from(secret, "latin1").toString("hex"),
              Buffer.from(secret, "latin1").toString("hex").toUpperCase(),
            ]
          : []),
      ]),
    ];
    const marker = selectExplicitRedactionReplacement(variants);
    const contexts: BufferEncoding[] =
      latin1 && !/[^\u0000-\u00ff]/u.test(secret)
        ? ["utf8", "latin1"]
        : ["utf8"];
    const pattern = [...secret]
      .map(
        (char) =>
          `(?:${char.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}|${contexts
            .map((context) =>
              [...Buffer.from(char, context)]
                .map(
                  (byte) =>
                    "%" +
                    byte
                      .toString(16)
                      .padStart(2, "0")
                      .replace(
                        /[a-f]/gu,
                        (hex) => `[${hex}${hex.toUpperCase()}]`,
                      ),
                )
                .join(""),
            )
            .join("|")})`,
      )
      .join("");
    let output = input;
    for (const variant of variants) output = output.split(variant).join(marker);
    return output.replace(new RegExp(pattern, "gu"), marker);
  };
  let seed = 0xfac70304;
  const alphabet = ["a", "b", "%", "2", "5", "é", "😀"];
  const fixed = ["%", "%25", "%2525", "a%25", "éa", "😀é"];
  for (let index = 0; index < 128; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const secret =
      index < fixed.length
        ? fixed[index]!
        : Array.from(
            { length: 1 + (seed % 4) },
            (_, at) => alphabet[(seed >>> (at * 3)) % alphabet.length]!,
          ).join("");
    const latin1 = index % 2 === 0;
    const encoded = [...secret]
      .map((char, at) => (at % 2 ? char : encodeURIComponent(char)))
      .join("");
    for (const text of [
      encoded,
      `prefix${encoded}suffix`,
      `😀${encoded}x${encoded}`,
      encoded.slice(0, -1) + "!",
      "%252525a%61%e9%C3%a9",
    ]) {
      expect(
        unwrap(
          knownSensitiveValueRedactor(
            secret,
            latin1 ? "latin1" : undefined,
          ).text(text),
        ),
        `${index}:${JSON.stringify(secret)}`,
      ).toBe(legacy(secret, text, latin1));
    }
  }
});

it("refuses exact replacement expansion before publication and preserves ordinary maximum fields", () => {
  const secret = "a";
  const exact = unwrap(knownSensitiveValueRedactor(secret).text("a"));
  expect(exact).toBe("[REDACTED]");
  const base = 2 + 2 * (1 + 1 + 1 + 4 + 4 + 1 + 2) + 1 + 8;
  const admitted = knownSensitiveValueRedactor(secret, undefined, {
    limits: { representationBytes: base + 2 + 20, workUnits: 100 },
  }).text("a");
  expect(admitted.ok).toBe(true);
  const refused = knownSensitiveValueRedactor(secret, undefined, {
    limits: { representationBytes: base + 2 + 19, workUnits: 100 },
  }).text("a");
  expect(refused).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisResourceConstraintError",
      resource: "memory",
      reportedLimits: { required_representation_bytes: 61 },
    },
  });
  if (!refused.ok)
    expect(refused.error.reportedLimits).not.toHaveProperty(
      "required_work_units",
    );
  const ordinary = "x".repeat(8 * 1024 * 1024 - 3) + "%20";
  expect(
    unwrap(
      knownSensitiveValueRedactor("a".repeat(30) + "b", "latin1").text(
        ordinary,
      ),
    ),
  ).toBe(ordinary);
  const realistic = "s" + "x".repeat(8 * 1024 * 1024 - 5) + "y%20";
  expect(
    unwrap(
      knownSensitiveValueRedactor("synthetic-key", "latin1").text(realistic),
    ),
  ).toBe(realistic);
});

it("admits useful candidate work and refuses larger required rows before allocating matrices", () => {
  const admitted = knownSensitiveValueRedactor(
    "a".repeat(500) + "b",
    "latin1",
  ).text("b" + "%61".repeat(4000) + "x");
  expect(admitted.ok).toBe(true);
  const refused = knownSensitiveValueRedactor(
    "a".repeat(300) + "b",
    "latin1",
  ).text("%61".repeat(9999) + "b");
  expect(refused).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisResourceConstraintError",
      resource: "cpu",
      reportedLimits: { work_units: 8_000_000 },
    },
  });
  if (!refused.ok) {
    expect(refused.error.reportedLimits).not.toHaveProperty(
      "required_representation_bytes",
    );
    expect(refused.error.reportedLimits?.required_work_units).toBeGreaterThan(
      8_000_000,
    );
    expect(JSON.stringify(refused.error)).not.toContain("%61");
  }
  const memory = knownSensitiveValueRedactor("ab", "latin1").text(
    "%61".repeat(2_300_000) + "b",
  );
  expect(memory).toMatchObject({ ok: false, error: { resource: "memory" } });
});
