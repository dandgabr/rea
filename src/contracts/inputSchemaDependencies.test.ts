import { Ajv } from "ajv";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import { presentInputJsonSchema } from "./inputSchemaPresentation.js";

it("conjoins declared schema dependencies with inferred required partners", () => {
  const schema = presentInputJsonSchema(
    {
      $schema: "http://json-schema.org/draft-07/schema#",
      dependencies: {
        runtime: {
          properties: { provider_id: { const: "unblob" } },
          required: ["provider_id"],
        },
      },
      anyOf: [
        {
          type: "object",
          properties: {
            path: { type: "string" },
            provider_id: { const: "binwalk" },
          },
          required: ["path"],
          additionalProperties: false,
        },
        {
          type: "object",
          properties: {
            path: { type: "string" },
            provider_id: { const: "unblob" },
            profile: { type: "string" },
            runtime: { type: "object" },
          },
          required: ["path", "provider_id", "profile"],
          additionalProperties: false,
        },
      ],
    },
    () => undefined,
  );
  const ajv = new Ajv({ strict: false });
  expect(ajv.validateSchema(schema)).toBe(true);
  const validate = ajv.compile(schema);
  expect(
    validate({
      path: "/fw",
      runtime: {},
      provider_id: "binwalk",
      profile: "/store",
    }),
  ).toBe(false);
  expect(validate({ path: "/fw", runtime: {}, provider_id: "unblob" })).toBe(
    false,
  );
  expect(
    validate({
      path: "/fw",
      runtime: {},
      provider_id: "unblob",
      profile: "/store",
    }),
  ).toBe(true);
  expect(validate({ path: "/fw" })).toBe(true);
});

it.each([
  { target: "07", runtime: ["confirmation"] },
  { target: "07", runtime: false },
  { target: "07", runtime: true },
  { target: "2020", runtime: ["confirmation"] },
] as const)(
  "retains overlapping $target dependency $runtime and disjoint property dependencies",
  ({ target, runtime }) => {
    const keyword = target === "07" ? "dependencies" : "dependentRequired";
    const schema = presentInputJsonSchema(
      {
        $schema:
          target === "07"
            ? "http://json-schema.org/draft-07/schema#"
            : "https://json-schema.org/draft/2020-12/schema",
        [keyword]: { runtime, marker: ["confirmation"] },
        anyOf: [
          {
            type: "object",
            properties: {
              path: { type: "string" },
              confirmation: { type: "boolean" },
              marker: { type: "boolean" },
            },
            required: ["path"],
            additionalProperties: false,
          },
          {
            type: "object",
            properties: {
              path: { type: "string" },
              profile: { type: "string" },
              runtime: { type: "object" },
              confirmation: { type: "boolean" },
              marker: { type: "boolean" },
            },
            required: ["path", "profile"],
            additionalProperties: false,
          },
        ],
      },
      () => undefined,
    );
    const ajv =
      target === "07"
        ? new Ajv({ strict: false })
        : new Ajv2020({ strict: false });
    expect(ajv.validateSchema(schema)).toBe(true);
    const validate = ajv.compile(schema);
    expect(validate({ path: "/fw" })).toBe(true);
    expect(validate({ path: "/fw", marker: true })).toBe(false);
    expect(validate({ path: "/fw", marker: true, confirmation: true })).toBe(
      true,
    );
    expect(validate({ path: "/fw", runtime: {}, confirmation: true })).toBe(
      false,
    );
    expect(
      validate({
        path: "/fw",
        runtime: {},
        profile: "/store",
        confirmation: true,
      }),
    ).toBe(runtime !== false);
    expect(validate({ path: "/fw", runtime: {}, profile: "/store" })).toBe(
      runtime === true,
    );
  },
);
