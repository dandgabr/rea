import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { Ajv } from "ajv";
import { expect, it } from "vitest";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createServer } from "../../../src/server/createServer.js";
import { firmwareCorpusInputs } from "../../../src/domain/corpus/firmwareCorpus.js";
import { toolInputSchemaWithMetadata } from "../../../src/contracts/toolSchemaMetadata.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";

it("advertises native export through the actual SDK and preserves exact namespace admission", async () => {
  const session = createTestBinarySession(() => {
    throw Error("No binary engine is authorized");
  });
  const server = createServer({ kind: "session", session });
  const client = new Client({
    name: "fact-native-runtime-schema",
    version: "1",
  });
  try {
    const [c, s] = InMemoryTransport.createLinkedPair();
    await server.connect(s);
    await client.connect(c);
    const { tools } = await client.listTools();
    const ajv = new Ajv2020({
      strict: false,
      validateFormats: false,
      addUsedSchema: false,
    });
    for (const name of ["export_corpus_firmware"] as const) {
      const schema = tools.find((tool) => tool.name === name)!.inputSchema;
      expect(ajv.validateSchema(schema)).toBe(true);
      const validate = ajv.compile(schema);
      const advertised = toolInputSchemaWithMetadata(toolContract(name));
      const legacySchema = advertised["~standard"].jsonSchema.input({
        target: "draft-07",
      });
      const legacy = new Ajv({ strict: false, validateFormats: false });
      expect(legacy.validateSchema(legacySchema)).toBe(true);
      const validateLegacy = legacy.compile(legacySchema);
      const selected = {
        interpreter: "/usr/local/bin/python3",
        checkout: "/data/fact-source",
        profile: "source-54aed90b",
        uids: ["a".repeat(64) + "_1"],
        output_directory: "/host/output",
        runtime: {
          kind: "podman-existing",
          podman: "/usr/bin/podman",
          container_id: "b".repeat(64),
          image_id: "c".repeat(64),
          existing_store_profile: "/host/profile.json",
          staging_parent: "/data/staging",
        },
      };
      for (const input of [
        selected,
        { ...selected, runtime: { kind: "native" } },
        { ...selected, runtime: undefined },
        { ...selected, checkout: "/data/漢字😀" },
      ]) {
        expect(firmwareCorpusInputs[name].safeParse(input).success).toBe(true);
        expect(validate(input)).toBe(true);
        expect(validateLegacy(input)).toBe(true);
      }
      for (const invalid of [
        "/data/../caller",
        "/data//caller",
        "/data/./caller",
        "relative",
        "/data/\ud800",
        "/data/\0",
      ]) {
        for (const input of [
          { ...selected, interpreter: invalid },
          { ...selected, checkout: invalid },
          {
            ...selected,
            runtime: { ...selected.runtime, staging_parent: invalid },
          },
        ]) {
          expect(
            firmwareCorpusInputs[name].safeParse(input).success,
            JSON.stringify(input),
          ).toBe(false);
          expect(validate(input)).toBe(false);
          expect(validateLegacy(input)).toBe(false);
        }
      }
      ajv.removeSchema();
    }
  } finally {
    await client.close();
    await server.close();
    await session.close();
  }
});
