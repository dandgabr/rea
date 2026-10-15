import { Worker } from "node:worker_threads";
import { fc, it } from "@fast-check/vitest";
import { expect, vi } from "vitest";
import { FactJsonParser } from "./FactJsonParser.js";
import { FACT_LIMITS, factHash } from "./FactProtocol.js";

it("separates actual binary expansion from metadata and preserves escaped Unicode", async () => {
  const parser = new FactJsonParser();
  const raw = Buffer.from(
    '{"status":0,"binary":"YWJj","file_name":"\\u00e9\\ud83d\\ude80","SHA256":"' +
      factHash(Buffer.from("abc")) +
      '"}',
  );
  const parsed = await parser.parse(raw, true, new AbortController().signal);
  expect(parsed.binary?.toString()).toBe("abc");
  expect(parsed.data).toMatchObject({ status: 0, file_name: "é🚀" });
  expect(parsed.metadataBytes).toBe(raw.length - 4);
  expect(parsed.binaryEncodedChars).toBe(4);
  await parser.close();
});
it("parses a REST status response without enabling binary transfer handling", async () => {
  const parser = new FactJsonParser();
  const parsed = await parser.parse(
    Buffer.from('{"status":500,"message":"backend unavailable"}'),
    false,
    new AbortController().signal,
  );
  expect(parsed.data).toEqual({
    status: 500,
    message: "backend unavailable",
  });
  expect(parsed.binary).toBeUndefined();
  expect(parsed.binaryDecodedBytes).toBe(0);
  await parser.close();
});
it("rejects duplicate binary fields, malformed encoding and malformed base64 before object assembly", async () => {
  const parser = new FactJsonParser();
  for (const value of [
    '{"binary":"YWJj","binary":"ZA=="}',
    '{"binary":[]}',
    '{"binary":"YWJj="}',
    '{"binary":"A==="}',
  ])
    await expect(
      parser.parse(Buffer.from(value), true, new AbortController().signal),
    ).rejects.toThrow(/binary|base64/u);
  await expect(
    parser.parse(
      Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
      false,
      new AbortController().signal,
    ),
  ).rejects.toThrow("UTF-8");
  expect(parser.pendingResources).toEqual([]);
  await parser.close();
});
it("enforces exact nonbinary wire max and max plus one before expanded metadata assembly", async () => {
  const parser = new FactJsonParser();
  const prefix = '{"binary":"YWJj","name":"';
  const suffix = '"}';
  const fixed = Buffer.byteLength(prefix + suffix) - 4;
  for (const extra of [0, 1]) {
    const bytes = Buffer.from(
      prefix + "x".repeat(FACT_LIMITS.jsonBytes - fixed + extra) + suffix,
    );
    const parsed = parser.parse(bytes, true, new AbortController().signal);
    if (extra) await expect(parsed).rejects.toThrow("metadata");
    else expect((await parsed).metadataBytes).toBe(FACT_LIMITS.jsonBytes);
  }
  await parser.close();
});
it("rejects compact malformed downloads before expanded metadata assembly and leaves the caller alive", async () => {
  const parser = new FactJsonParser();
  const bytes = Buffer.from(
    '{"status":0,"values":[' + "{},".repeat(999999) + "{}]}",
  );
  expect(bytes.length).toBeLessThan(FACT_LIMITS.jsonBytes);
  let outcome = "parsed";
  try {
    await parser.parse(bytes, true, new AbortController().signal);
  } catch (cause) {
    outcome = cause instanceof Error ? cause.message : String(cause);
  }
  expect(outcome).toMatch(/download structure before metadata assembly/u);
  expect(parser.pendingResources).toEqual([]);
  expect(
    (
      await parser.parse(
        Buffer.from('{"status":0,"analysis":{"result":true}}'),
        false,
        new AbortController().signal,
      )
    ).data,
  ).toMatchObject({ analysis: { result: true } });
  await parser.close();
});

it("terminates its owned worker on cancellation without consuming another envelope automatically", async () => {
  const parser = new FactJsonParser();
  const controller = new AbortController();
  const input = Buffer.from(
    '{"name":"' + "x".repeat(FACT_LIMITS.jsonBytes - 32) + '"}',
  );
  const pending = parser.parse(input, false, controller.signal);
  expect(parser.pendingResources).toHaveLength(1);
  controller.abort();
  await expect(pending).rejects.toThrow("canceled");
  expect(parser.pendingResources).toEqual([]);
  expect(
    (
      await parser.parse(
        Buffer.from('{"status":0}'),
        false,
        new AbortController().signal,
      )
    ).data,
  ).toEqual({ status: 0 });
  await parser.close();
});

it("enforces decoded max and max plus one independently of the base64 wire maximum", async () => {
  const parser = new FactJsonParser({ rawBytes: 3, jsonBytes: 1024 });
  const signal = new AbortController().signal;
  expect(
    (
      await parser.parse(Buffer.from('{"binary":"YWJj"}'), true, signal)
    ).binary?.toString(),
  ).toBe("abc");
  await expect(
    parser.parse(Buffer.from('{"binary":"YWJjZA=="}'), true, signal),
  ).rejects.toThrow(/encoded byte budget|raw byte budget/u);
  expect(parser.pendingResources).toEqual([]);
  await parser.close();
});
it("keeps a real worker owner after failed termination and retries cleanup explicitly", async () => {
  const parser = new FactJsonParser();
  const terminate = vi
    .spyOn(Worker.prototype, "terminate")
    .mockRejectedValueOnce(Error("synthetic worker termination failure"));
  try {
    const parsed = await parser.parse(
      Buffer.from('{"status":0}'),
      false,
      new AbortController().signal,
    );
    expect(parsed.data).toEqual({ status: 0 });
    expect(parsed.cleanupDiagnostic).toContain("owner retained");
    expect(parser.pendingResources).toHaveLength(1);
  } finally {
    terminate.mockRestore();
    await parser.close();
  }
  expect(parser.pendingResources).toEqual([]);
});
it("allows large metadata before the binary member without imposing JSON member order", async () => {
  const parser = new FactJsonParser();
  const raw = Buffer.from(
    '{"file_name":"' + "x".repeat(65536) + '","binary":"YWJj"}',
  );
  expect(
    (
      await parser.parse(raw, true, new AbortController().signal)
    ).binary?.toString(),
  ).toBe("abc");
  await parser.close();
});

it.prop([fc.uint8Array({ maxLength: 512 })])(
  "contains arbitrary response bytes to a bounded parse outcome without leaking workers",
  async (bytes) => {
    const parser = new FactJsonParser({ rawBytes: 1024, jsonBytes: 1024 });
    try {
      try {
        await parser.parse(
          Buffer.from(bytes),
          false,
          new AbortController().signal,
        );
      } catch (cause) {
        expect(cause).toBeInstanceOf(Error);
      }
      expect(parser.pendingResources).toEqual([]);
    } finally {
      await parser.close();
    }
  },
);
