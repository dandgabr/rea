import { selectExplicitRedactionReplacement } from "./explicitSensitiveValues.js";
import type { JsonValue } from "./jsonValue.js";

/**
 * Total on JavaScript strings: preserve exact raw/JSON-escaped identities.
 * URI and UTF-8 byte forms exist only for scalar text, never replacement bytes
 * manufactured from malformed UTF-16. An explicit additional Latin-1 wire
 * representation is used only when lossless. Native text keeps UTF-8 semantics;
 * undefined/empty declarations are inert. The caller owns the mutable JSON graph.
 */
export const knownSensitiveValueRedactor = (
  secret: string | undefined,
  additionalByteEncoding?: "latin1",
) => {
  const scalarText = secret !== undefined && !/[\uD800-\uDFFF]/u.test(secret);
  const wireBytes =
    secret !== undefined &&
    additionalByteEncoding === "latin1" &&
    !/[^\u0000-\u00ff]/u.test(secret)
      ? Buffer.from(secret, "latin1")
      : undefined;
  const byteEncodings: readonly ("utf8" | "latin1")[] =
    wireBytes === undefined ? ["utf8"] : ["utf8", "latin1"];
  const variants =
    secret === undefined || secret.length === 0
      ? []
      : scalarText
        ? [
            secret,
            encodeURIComponent(secret),
            Buffer.from(secret).toString("base64"),
            Buffer.from(secret).toString("hex"),
            Buffer.from(secret).toString("hex").toUpperCase(),
            JSON.stringify(secret).slice(1, -1),
            ...(wireBytes === undefined
              ? []
              : [
                  wireBytes.toString("base64"),
                  wireBytes.toString("hex"),
                  wireBytes.toString("hex").toUpperCase(),
                ]),
          ]
        : [secret, JSON.stringify(secret).slice(1, -1)];
  // Unicode matching avoids treating half of an ordinary scalar as an exact
  // occurrence of a lone-surrogate declaration.
  const malformedLiteral =
    secret !== undefined && !scalarText
      ? new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "gu")
      : undefined;
  const percent =
    secret === undefined || secret.length === 0 || !scalarText
      ? undefined
      : new RegExp(
          [...secret]
            .map((char) => {
              const escaped = char.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
              const encoded = byteEncodings.map((encoding) =>
                [...Buffer.from(char, encoding)]
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
              );
              return `(?:${escaped}|${encoded.join("|")})`;
            })
            .join(""),
          "gu",
        );
  const replacement = selectExplicitRedactionReplacement(variants);
  const redact = (text: string) => {
    for (const value of variants)
      if (value.length)
        text =
          value === secret && malformedLiteral !== undefined
            ? text.replace(malformedLiteral, replacement)
            : text.split(value).join(replacement);
    return percent === undefined ? text : text.replace(percent, replacement);
  };
  // The caller transfers exclusive ownership. Redact that representation once,
  // rather than allocating a second expanded producer graph.
  const value = (input: JsonValue): JsonValue => {
    if (secret === undefined) return input;
    if (typeof input === "string") return redact(input);
    const pending: JsonValue[] = [input];
    while (pending.length) {
      const item = pending.pop();
      if (Array.isArray(item)) {
        for (let at = 0; at < item.length; at++) {
          const child = item[at]!;
          if (typeof child === "string") item[at] = redact(child);
          else if (child !== null && typeof child === "object")
            pending.push(child);
        }
      } else if (item !== null && typeof item === "object") {
        for (const key of Object.keys(item)) {
          const child = item[key]!;
          const redacted = typeof child === "string" ? redact(child) : child;
          const replacement = redact(key);
          if (replacement !== key) {
            delete item[key];
            let selected = replacement;
            let suffix = 1;
            while (Object.hasOwn(item, selected))
              selected = `${replacement} (${suffix++})`;
            Object.defineProperty(item, selected, {
              value: redacted,
              enumerable: true,
              writable: true,
              configurable: true,
            });
          } else
            Object.defineProperty(item, key, {
              value: redacted,
              enumerable: true,
              writable: true,
              configurable: true,
            });
          if (child !== null && typeof child === "object") pending.push(child);
        }
      }
    }
    return input;
  };
  return { text: redact, value };
};
