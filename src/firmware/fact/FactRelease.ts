/** Catalog identities; REST profiles are declarations, never version attestation. */
export const FACT_REST_PROVIDER_IDENTITY = {
  id: "fact-core",
  name: "FACT Core",
  version: null,
} as const;
/** Planned native capability identity; no local producer is currently executed. */
export const FACT_NATIVE_PROVIDER_IDENTITY = {
  id: "fact-core-native",
  name: "FACT Core native interchange",
  version: null,
} as const;
