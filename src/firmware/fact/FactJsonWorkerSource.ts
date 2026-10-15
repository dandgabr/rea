/** Owned worker program. Dependencies are resolved by the adapter, never caller input. */
export const FACT_JSON_WORKER_SOURCE = String.raw`
const { parentPort, workerData } = require("node:worker_threads");
const { Readable } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const { createHash } = require("node:crypto");
(async () => {
  const [{ default: parser }, { asStream, none }, { default: fun }] =
    await Promise.all(workerData.modules.map((url) => import(url)));
  const raw = Buffer.from(workerData.bytes);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const stack = [];
  let binary = false,
    binarySeen = false,
    producerStatus = undefined,
    binaryChars = 0,
    carry = "",
    decodedBytes = 0,
    block = null,
    used = 0;
  const binaryHash = createHash("sha256");
  const blocks = [];
  let text = "",
    parts = [],
    partBytes = 0,
    metadataNormalizedBytes = 0;
  const append = (part) => {
    metadataNormalizedBytes += Buffer.byteLength(part);
    if (metadataNormalizedBytes > workerData.jsonBytes)
      throw Error("FACT nonbinary JSON metadata exceeds its byte budget");
    parts.push(part);
    partBytes += part.length;
    if (partBytes >= 65536) {
      text += parts.join("");
      parts = [];
      partBytes = 0;
    }
  };
  const store = (bytes) => {
    if (decodedBytes + bytes.length > workerData.rawBytes)
      throw Error("FACT decoded binary exceeds its raw byte budget");
    decodedBytes += bytes.length;
    binaryHash.update(bytes);
    let at = 0;
    while (at < bytes.length) {
      if (block === null)
        block = Buffer.allocUnsafeSlow(Math.min(65536, workerData.rawBytes));
      const count = Math.min(block.length - used, bytes.length - at);
      bytes.copy(block, used, at, at + count);
      used += count;
      at += count;
      if (used === block.length) {
        blocks.push(block);
        block = null;
        used = 0;
      }
    }
  };
  const base64 = (part) => {
    binaryChars += part.length;
    if (binaryChars > 4 * Math.ceil(workerData.rawBytes / 3))
      throw Error("FACT base64 binary exceeds its encoded byte budget");
    if (!/^[A-Za-z0-9+/=]*$/.test(part))
      throw Error("FACT binary has malformed base64 characters");
    const joined = carry + part;
    const length = Math.max(0, Math.floor(joined.length / 4) * 4 - 4);
    const complete = joined.slice(0, length);
    if (complete.includes("="))
      throw Error("FACT binary has premature base64 padding");
    if (complete.length) store(Buffer.from(complete, "base64"));
    carry = joined.slice(length);
  };
  const value = () => {
    const frame = stack[stack.length - 1];
    if (frame && frame.type === "array") {
      if (!frame.first) append(",");
      frame.first = false;
    }
  };
  const consume = (token) => {
    const frame = stack[stack.length - 1];
    switch (token.name) {
      case "keyValue":
        if (frame.keys.has(token.value))
          throw Error(
            "FACT producer response has duplicate JSON member " + token.value,
          );
        frame.keys.add(token.value);
        frame.key = token.value;
        if (!frame.first) append(",");
        frame.first = false;
        append(JSON.stringify(token.value) + ":");
        break;
      case "startObject":
      case "startArray":
        if (
          workerData.binaryAllowed &&
          stack.length === 0 &&
          token.name !== "startObject"
        )
          throw Error("FACT producer response JSON root must be an object");
        if (
          workerData.binaryMode === "download" &&
          stack.length === 1 &&
          frame.key === "binary"
        )
          throw Error("FACT binary must be a base64 string");
        if (
          workerData.binaryMode === "download" &&
          ((stack.length === 1 &&
            (frame.key !== "request" || token.name !== "startObject")) ||
            stack.length >= 2)
        )
          throw Error(
            "FACT malformed download structure before metadata assembly",
          );
        value();
        append(token.name === "startObject" ? "{" : "[");
        stack.push({
          type: token.name === "startObject" ? "object" : "array",
          first: true,
          keys: new Set(),
          key: undefined,
        });
        if (stack.length > 1000)
          throw Error(
            "FACT producer response nesting exceeds the JSON contract",
          );
        break;
      case "endObject":
      case "endArray":
        append(token.name === "endObject" ? "}" : "]");
        stack.pop();
        break;
      case "startString":
        value();
        binary =
          workerData.binaryMode === "download" &&
          stack.length === 1 &&
          frame.key === "binary";
        if (binary) binarySeen = true;
        append(binary ? '""' : '"');
        break;
      case "stringChunk":
        if (binary) base64(token.value);
        else append(JSON.stringify(token.value).slice(1, -1));
        break;
      case "endString":
        if (binary) {
          if (
            carry.length &&
            !/^(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$/.test(
              carry,
            )
          )
            throw Error("FACT binary has malformed base64 length or padding");
          if (carry.length) {
            const tail = Buffer.from(carry, "base64");
            if (tail.toString("base64") !== carry)
              throw Error("FACT binary is not canonical base64");
            store(tail);
          }
          binary = false;
        } else append('"');
        break;
      case "numberValue":
      case "nullValue":
      case "trueValue":
      case "falseValue":
        if (workerData.binaryAllowed && stack.length === 0)
          throw Error("FACT producer response JSON root must be an object");
        if (
          token.name === "numberValue" &&
          !Number.isFinite(Number(token.value))
        )
          throw Error("FACT JSON numbers must be finite");
        if (
          workerData.binaryMode === "download" &&
          stack.length === 1 &&
          frame.key === "binary"
        )
          throw Error("FACT binary must be a base64 string");
        if (
          stack.length === 1 &&
          frame.key === "status" &&
          token.name === "numberValue"
        )
          producerStatus = Number(token.value);
        value();
        append(
          token.name === "numberValue"
            ? token.value
            : token.name === "nullValue"
              ? "null"
              : token.name === "trueValue"
                ? "true"
                : "false",
        );
        break;
    }
    return none;
  };
  async function* chunks() {
    try {
      for (let at = 0; at < raw.length; at += 65536)
        yield decoder.decode(raw.subarray(at, at + 65536), { stream: true });
      yield decoder.decode();
    } catch (cause) {
      if (cause.code === "ERR_ENCODING_INVALID_ENCODED_DATA")
        throw Error("FACT producer response is not valid UTF-8");
      throw cause;
    }
  }
  await pipeline(
    Readable.from(chunks()),
    asStream(
      fun(
        parser({
          jsonStreaming: false,
          streamKeys: false,
          packKeys: true,
          streamStrings: true,
          packStrings: false,
          streamNumbers: false,
          packNumbers: true,
        }),
        consume,
      ),
    ),
  );
  const metadataBytes = raw.length - binaryChars;
  if (metadataBytes > workerData.jsonBytes)
    throw Error("FACT nonbinary JSON metadata exceeds its wire byte budget");
  if (
    workerData.binaryMode === "download" &&
    producerStatus !== 1 &&
    !binarySeen
  )
    throw Error("FACT download missing binary before metadata assembly");
  text += parts.join("");
  parts = [];
  const data = JSON.parse(text);
  const decoded = Buffer.allocUnsafeSlow(decodedBytes);
  let at = 0;
  for (const part of blocks) {
    part.copy(decoded, at);
    at += part.length;
  }
  if (block !== null) block.copy(decoded, at, 0, used);
  parentPort.postMessage(
    {
      kind: "parsed",
      data,
      binary: decoded,
      binaryEncodedChars: binaryChars,
      metadataBytes,
      binaryDecodedBytes: decodedBytes,
      binarySha256: binaryHash.digest("hex"),
    },
    [decoded.buffer],
  );
})().catch((cause) =>
  parentPort.postMessage({
    kind: "failed",
    reason: cause instanceof Error ? cause.message : String(cause),
  }),
);
`;
