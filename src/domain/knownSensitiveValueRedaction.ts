import { selectExplicitRedactionReplacement } from "./explicitSensitiveValues.js";
import type { JsonValue } from "./jsonValue.js";
import { AnalysisResourceConstraintError } from "./analysisErrorCore.js";
import { err, ok, type Result } from "./result.js";

/** Independent privacy-projection admission, including pre-provider parameters. */
export const KNOWN_VALUE_REDACTION_LIMITS = {
  representationBytes: 64 * 1024 * 1024,
  workUnits: 8_000_000,
} as const;

type Options = {
  operation?: string;
  limits?: { representationBytes: number; workUnits: number };
};

/**
 * Exact raw/JSON identities for every JS string; byte variants only for scalar
 * text, with optional lossless Latin-1 transport bytes. Expected resource refusal
 * is a Result, never unredacted success. Counters bound owned representations and
 * explicit matching work, not total V8 heap or wall-clock execution.
 */
export const knownSensitiveValueRedactor = (
  secret: string | undefined,
  additionalByteEncoding?: "latin1",
  options: Options = {},
) => {
  const limits = options.limits ?? KNOWN_VALUE_REDACTION_LIMITS;
  let usedWork = 0,
    retainedBytes = 0;
  const failure = (resource: "memory" | "cpu", required: number) =>
    new AnalysisResourceConstraintError(
      options.operation ?? "known-sensitive-value-redaction",
      resource,
      "Known-value privacy projection exceeds its independent resource admission",
      {
        representation_bytes: limits.representationBytes,
        work_units: limits.workUnits,
        consumed_work_units: usedWork,
        ...(resource === "memory"
          ? { required_representation_bytes: required }
          : { required_work_units: required }),
      },
    );
  const memory = (bytes: number) => {
    if (!Number.isSafeInteger(bytes) || bytes > limits.representationBytes)
      throw failure("memory", bytes);
  };
  const work = (units = 1) => {
    if (
      !Number.isSafeInteger(usedWork + units) ||
      usedWork + units > limits.workUnits
    )
      throw failure("cpu", usedWork + units);
    usedWork += units;
  };
  const guard = <T>(
    run: () => T,
  ): Result<T, AnalysisResourceConstraintError> => {
    try {
      return ok(run());
    } catch (cause) {
      if (cause instanceof AnalysisResourceConstraintError) return err(cause);
      throw cause;
    }
  };
  const scalar = secret !== undefined && !/[\uD800-\uDFFF]/u.test(secret);
  const latin1 =
    secret !== undefined &&
    additionalByteEncoding === "latin1" &&
    !/[^\u0000-\u00ff]/u.test(secret);
  let variants: string[] = [],
    table = new Uint32Array(0),
    replacement = "[REDACTED]";
  const setup = guard(() => {
    if (!secret) return;
    memory(2 * secret.length);
    work(secret.length);
    let jsonUnits = 0,
      uriUnits = 0,
      scalarCount = 0;
    for (let at = 0; at < secret.length; at++) {
      const unit = secret.charCodeAt(at);
      const pair =
        unit >= 0xd800 &&
        unit <= 0xdbff &&
        secret.charCodeAt(at + 1) >= 0xdc00 &&
        secret.charCodeAt(at + 1) <= 0xdfff;
      jsonUnits +=
        unit === 34 || unit === 92 || [8, 9, 10, 12, 13].includes(unit)
          ? 2
          : unit < 32 || (unit >= 0xd800 && unit <= 0xdfff && !pair)
            ? 6
            : pair
              ? 2
              : 1;
      if (scalar) {
        const cp = secret.codePointAt(at)!;
        const bytes = cp < 128 ? 1 : cp < 2048 ? 2 : cp < 65536 ? 3 : 4;
        uriUnits +=
          cp < 128 && /[A-Za-z0-9!~*'()._-]/u.test(secret[at]!) ? 1 : bytes * 3;
        scalarCount++;
      }
      if (pair) at++;
    }
    const utf8Bytes = scalar ? Buffer.byteLength(secret) : 0;
    const wireBytes = scalar && latin1 ? secret.length : 0;
    // Include transient candidate variants before dedup, JSON quotes/slice,
    // selected text, retained byte buffers and the compact two-word token table.
    const variantUnits =
      secret.length +
      jsonUnits +
      (scalar
        ? uriUnits +
          4 * Math.ceil(utf8Bytes / 3) +
          4 * utf8Bytes +
          (latin1 ? 4 * Math.ceil(wireBytes / 3) + 4 * wireBytes : 0)
        : 0);
    retainedBytes =
      2 * secret.length +
      2 * (variantUnits + jsonUnits + 2) +
      utf8Bytes +
      wireBytes +
      8 * scalarCount;
    memory(retainedBytes);
    const utf8 = scalar ? Buffer.from(secret) : undefined;
    const wire = scalar && latin1 ? Buffer.from(secret, "latin1") : undefined;
    const utf8Hex = utf8?.toString("hex");
    const wireHex = wire?.toString("hex");
    variants = [
      ...new Set([
        secret,
        ...(scalar
          ? [
              encodeURIComponent(secret),
              utf8!.toString("base64"),
              utf8Hex!,
              utf8Hex!.toUpperCase(),
            ]
          : []),
        JSON.stringify(secret).slice(1, -1),
        ...(wire
          ? [wire.toString("base64"), wireHex!, wireHex!.toUpperCase()]
          : []),
      ]),
    ];
    replacement = selectExplicitRedactionReplacement(variants);
    table = new Uint32Array(2 * scalarCount);
    let index = 0;
    if (scalar)
      for (const char of secret) {
        const cp = char.codePointAt(0)!;
        const count = cp < 128 ? 1 : cp < 2048 ? 2 : cp < 65536 ? 3 : 4;
        const packed =
          count === 1
            ? cp << 24
            : count === 2
              ? ((0xc0 | (cp >>> 6)) << 24) | ((0x80 | (cp & 63)) << 16)
              : count === 3
                ? ((0xe0 | (cp >>> 12)) << 24) |
                  ((0x80 | ((cp >>> 6) & 63)) << 16) |
                  ((0x80 | (cp & 63)) << 8)
                : ((0xf0 | (cp >>> 18)) << 24) |
                  ((0x80 | ((cp >>> 12) & 63)) << 16) |
                  ((0x80 | ((cp >>> 6) & 63)) << 8) |
                  (0x80 | (cp & 63));
        table[index++] = cp | (count << 24);
        table[index++] = packed >>> 0;
      }
  });
  const boundary = (text: string, at: number) =>
    !(
      at > 0 &&
      text.charCodeAt(at - 1) >= 0xd800 &&
      text.charCodeAt(at - 1) <= 0xdbff &&
      text.charCodeAt(at) >= 0xdc00 &&
      text.charCodeAt(at) <= 0xdfff
    );
  const find = (
    text: string,
    literal: string,
    from: number,
    unicode: boolean,
  ) => {
    let at = text.indexOf(literal, from);
    while (
      at >= 0 &&
      unicode &&
      (!boundary(text, at) || !boundary(text, at + literal.length))
    ) {
      work();
      at = text.indexOf(literal, at + 1);
    }
    return at;
  };
  const hex = (unit: number) =>
    unit >= 48 && unit <= 57
      ? unit - 48
      : unit >= 65 && unit <= 70
        ? unit - 55
        : unit >= 97 && unit <= 102
          ? unit - 87
          : -1;
  const encoded = (
    text: string,
    pos: number,
    packed: number,
    count: number,
  ) => {
    if (pos + 3 * count > text.length) return false;
    for (let at = 0; at < count; at++) {
      work(3);
      const byte = (packed >>> (24 - 8 * at)) & 255;
      if (
        text.charCodeAt(pos + 3 * at) !== 37 ||
        hex(text.charCodeAt(pos + 3 * at + 1)) !== byte >>> 4 ||
        hex(text.charCodeAt(pos + 3 * at + 2)) !== (byte & 15)
      )
        return false;
    }
    return true;
  };
  const hasToken = (text: string, row: number) => {
    const cp = table[2 * row]! & 0x1fffff,
      count = table[2 * row]! >>> 24,
      packed = table[2 * row + 1]!;
    if (text.includes(String.fromCodePoint(cp))) return true;
    for (let at = text.indexOf("%"); at >= 0; at = text.indexOf("%", at + 1)) {
      work();
      if (
        encoded(text, at, packed, count) ||
        (latin1 && cp > 127 && encoded(text, at, cp << 24, 1))
      )
        return true;
    }
    return false;
  };
  const apply = (input: string, reserved: number): string => {
    let text = input;
    for (const literal of variants) {
      const unicode = literal === secret && !scalar;
      let matches = 0;
      for (
        let at = find(text, literal, 0, unicode);
        at >= 0;
        at = find(text, literal, at + literal.length, unicode)
      ) {
        work();
        matches++;
      }
      if (!matches) continue;
      const units =
        text.length + matches * (replacement.length - literal.length);
      memory(reserved + (text === input ? 0 : 2 * text.length) + 2 * units);
      if (!unicode) text = text.replaceAll(literal, replacement);
      else {
        let result = "",
          from = 0;
        for (
          let at = find(text, literal, 0, true);
          at >= 0;
          at = find(text, literal, from, true)
        ) {
          result += text.slice(from, at) + replacement;
          from = at + literal.length;
        }
        text = result + text.slice(from);
      }
    }
    const rows = table.length / 2;
    // Literal replacement already covers every all-raw match. No percent or no
    // possible first/last token means no mixed candidate: no matrices/work product.
    if (
      !rows ||
      !text.includes("%") ||
      !hasToken(text, 0) ||
      !hasToken(text, rows - 1)
    )
      return text;
    // A mixed match requires at least one whole encoded scalar. Scan percent
    // positions once; token comparisons are charged before matrix admission.
    let encodedCandidate = false;
    for (
      let at = text.indexOf("%");
      at >= 0 && !encodedCandidate;
      at = text.indexOf("%", at + 1)
    ) {
      work();
      for (let row = 0; row < rows; row++) {
        work();
        const cp = table[2 * row]! & 0x1fffff,
          count = table[2 * row]! >>> 24,
          packed = table[2 * row + 1]!;
        if (
          encoded(text, at, packed, count) ||
          (latin1 && cp > 127 && encoded(text, at, cp << 24, 1))
        ) {
          encodedCandidate = true;
          break;
        }
      }
    }
    if (!encodedCandidate) return text;
    const length = text.length;
    if (length >= 0xffffffff) throw failure("memory", 8 * (length + 1));
    const matrices = 8 * (length + 1);
    const retained = reserved + (text === input ? 0 : 2 * length);
    memory(retained + matrices);
    const minimum = (rows + 1) * (length + 1);
    if (!Number.isSafeInteger(minimum) || usedWork + minimum > limits.workUnits)
      throw failure("cpu", usedWork + minimum);
    let next = new Uint32Array(length + 1),
      current = new Uint32Array(length + 1);
    work(length + 1);
    for (let pos = 0; pos <= length; pos++) next[pos] = pos + 1; // zero sentinel; endpoint + 1
    for (let row = rows - 1; row >= 0; row--) {
      const cp = table[2 * row]! & 0x1fffff,
        bytes = table[2 * row]! >>> 24,
        packed = table[2 * row + 1]!,
        rawUnits = cp > 65535 ? 2 : 1;
      for (let pos = 0; pos < length; pos++) {
        work();
        current[pos] = 0;
        if (pos + rawUnits <= length && next[pos + rawUnits]) {
          work(rawUnits);
          if (text.codePointAt(pos) === cp) {
            current[pos] = next[pos + rawUnits]!;
            continue;
          }
        }
        if (
          pos + 3 * bytes <= length &&
          next[pos + 3 * bytes] &&
          encoded(text, pos, packed, bytes)
        ) {
          current[pos] = next[pos + 3 * bytes]!;
          continue;
        }
        // ASCII UTF8/Latin1 alternatives are identical; retain only the first.
        if (
          latin1 &&
          cp > 127 &&
          pos + 3 <= length &&
          next[pos + 3] &&
          encoded(text, pos, cp << 24, 1)
        )
          current[pos] = next[pos + 3]!;
      }
      current[length] = 0;
      [next, current] = [current, next];
    }
    let matches = 0,
      removed = 0;
    for (let pos = 0; pos < length;) {
      work();
      const end = next[pos]!;
      if (end) {
        matches++;
        removed += end - 1 - pos;
        pos = end - 1;
      } else pos += text.codePointAt(pos)! > 65535 ? 2 : 1;
    }
    if (!matches) return text;
    const units = length - removed + matches * replacement.length;
    memory(retained + matrices + 2 * units);
    let result = "",
      from = 0;
    for (let pos = 0; pos < length;) {
      work();
      const end = next[pos]!;
      if (end) {
        result += text.slice(from, pos) + replacement;
        from = end - 1;
        pos = from;
      } else pos += text.codePointAt(pos)! > 65535 ? 2 : 1;
    }
    return result + text.slice(from);
  };
  const text = (input: string) =>
    guard(() => {
      if (!setup.ok) throw setup.error;
      if (!secret) return input;
      const reserved = retainedBytes + 2 * input.length;
      memory(reserved);
      const output = apply(input, reserved);
      retainedBytes = reserved + (output === input ? 0 : 2 * output.length);
      memory(retainedBytes);
      return output;
    });
  const value = (input: JsonValue) =>
    guard(() => {
      if (!setup.ok) throw setup.error;
      if (!secret) return input;
      const pending: JsonValue[] = [input];
      while (pending.length) {
        work();
        const item = pending.pop()!;
        if (typeof item === "string") {
          memory(retainedBytes + 2 * item.length);
          retainedBytes += 2 * item.length;
        } else if (Array.isArray(item))
          for (const child of item) pending.push(child);
        else if (item !== null && typeof item === "object")
          for (const key of Object.keys(item)) {
            memory(retainedBytes + 2 * key.length);
            retainedBytes += 2 * key.length;
            pending.push(item[key]!);
          }
      }
      const redact = (inputText: string) => {
        const output = apply(inputText, retainedBytes);
        if (output !== inputText) {
          memory(retainedBytes + 2 * output.length);
          retainedBytes += 2 * output.length;
        }
        return output;
      };
      if (typeof input === "string") return redact(input);
      pending.push(input);
      while (pending.length) {
        work();
        const item = pending.pop()!;
        if (Array.isArray(item))
          for (let at = 0; at < item.length; at++) {
            const child = item[at]!;
            if (typeof child === "string") item[at] = redact(child);
            else if (child !== null && typeof child === "object")
              pending.push(child);
          }
        else if (item !== null && typeof item === "object")
          for (const key of Object.keys(item)) {
            const child = item[key]!,
              result = typeof child === "string" ? redact(child) : child,
              replacementKey = redact(key);
            if (replacementKey !== key) {
              delete item[key];
              let selected = replacementKey,
                suffix = 1;
              while (Object.hasOwn(item, selected)) {
                work();
                const digits = String(suffix++);
                memory(
                  retainedBytes +
                    2 * (replacementKey.length + digits.length + 3),
                );
                selected = `${replacementKey} (${digits})`;
              }
              retainedBytes += 2 * selected.length;
              Object.defineProperty(item, selected, {
                value: result,
                enumerable: true,
                writable: true,
                configurable: true,
              });
            } else
              Object.defineProperty(item, key, {
                value: result,
                enumerable: true,
                writable: true,
                configurable: true,
              });
            if (child !== null && typeof child === "object")
              pending.push(child);
          }
      }
      return input;
    });
  return { text, value };
};
