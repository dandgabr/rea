import type { JsonValue } from "./jsonValue.js";

/** Redact one explicitly known sensitive value and its encodings in an exclusively owned JSON graph. */
export const knownSensitiveValueRedactor = (secret: string | undefined) => {
  const variants =
    secret === undefined
      ? []
      : [
          secret,
          encodeURIComponent(secret),
          Buffer.from(secret).toString("base64"),
          Buffer.from(secret).toString("hex"),
          Buffer.from(secret).toString("hex").toUpperCase(),
          JSON.stringify(secret).slice(1, -1),
        ];
  const percent =
    secret === undefined
      ? undefined
      : new RegExp(
          [...secret]
            .map((char) => {
              const escaped = char.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
              const encoded = [...Buffer.from(char)]
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
                .join("");
              return `(?:${escaped}|${encoded})`;
            })
            .join(""),
          "gu",
        );
  const redact = (text: string) => {
    for (const value of variants)
      if (value.length) text = text.split(value).join("[REDACTED]");
    return percent === undefined ? text : text.replace(percent, "[REDACTED]");
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
