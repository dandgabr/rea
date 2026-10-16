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
  ["draft-07", "dependencies", Ajv],
  ["draft-2020-12", "dependentSchemas", Ajv2020],
] as const)(
  "preserves schema-valued dependencies in the %s dialect while keeping property dependencies as guidance",
  (dialect, dependencyKeyword, AjvConstructor) => {
    const draft07 = dialect === "draft-07";
    const dependency = {
      properties: { provider_id: { const: "unblob" } },
      required: ["provider_id"],
    };
    const schema = presentInputJsonSchema(
      {
        $schema: draft07
          ? "http://json-schema.org/draft-07/schema#"
          : "https://json-schema.org/draft/2020-12/schema",
        type: "object",
        properties: {
          provider_id: { enum: ["binwalk", "unblob"] },
          runtime: { type: "object" },
          options: { type: "object" },
        },
        required: ["provider_id"],
        dependencies: {
          runtime: dependency,
          options: ["provider_id"],
        },
        dependentSchemas: { runtime: dependency },
      },
      () => undefined,
    );
    expect(schema).toHaveProperty(`${dependencyKeyword}.runtime`);
    expect(schema).not.toHaveProperty(
      draft07 ? "dependentSchemas" : "dependencies.runtime",
    );
    expect(schema.description).toContain(
      "When options is provided, also provide provider_id.",
    );

    const ajv = new AjvConstructor({ strict: false });
    expect(ajv.validateSchema(schema)).toBe(true);
    const validate = ajv.compile(schema);
    expect(validate({ provider_id: "binwalk" })).toBe(true);
    expect(validate({ provider_id: "binwalk", runtime: {} })).toBe(false);
    expect(validate({ provider_id: "unblob", runtime: {} })).toBe(true);
    // Property-list dependencies are rendered as caller guidance rather than
    // schema constraints in the compact input presentation.
    expect(validate({ provider_id: "binwalk", options: {} })).toBe(true);
  },
);

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
    expect(schema).not.toHaveProperty("dependencies.marker");
    expect(schema).not.toHaveProperty("dependentRequired.marker");
    expect(schema.description).toContain(
      "When marker is provided, also provide confirmation.",
    );
    expect(validate({ path: "/fw", marker: true })).toBe(true);
    expect(validate({ path: "/fw", marker: true, confirmation: true })).toBe(
      true,
    );
    expect(validate({ path: "/fw", runtime: {}, confirmation: true })).toBe(
      Array.isArray(runtime),
    );
    expect(
      validate({
        path: "/fw",
        runtime: {},
        profile: "/store",
        confirmation: true,
      }),
    ).toBe(Array.isArray(runtime) || runtime === true);
    expect(validate({ path: "/fw", runtime: {}, profile: "/store" })).toBe(
      Array.isArray(runtime) || runtime === true,
    );
  },
);
