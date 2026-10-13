/** Select the existing marker convention without including a declared literal. */
export const selectExplicitRedactionReplacement = (
  literals: readonly string[],
): string =>
  ["[REDACTED]", "…", ""].find((candidate) =>
    literals.every((literal) => literal === "" || !candidate.includes(literal)),
  ) ?? "";

/** Replace caller-declared literal text values without guessing sensitivity from names. */
export const redactExplicitText = (
  value: string,
  sensitiveValues: readonly string[],
): string => {
  const literals = [...new Set(sensitiveValues)].filter(
    (literal) => literal !== "",
  );
  const replacement = selectExplicitRedactionReplacement(literals);
  let result = value;
  for (const literal of literals.sort(
    (left, right) => right.length - left.length,
  ))
    result = result.replaceAll(literal, replacement);
  // Replacement boundaries can form another declaration; exclude that text.
  return literals.some((literal) => result.includes(literal)) ? "" : result;
};
