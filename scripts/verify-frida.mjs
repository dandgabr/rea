import { FridaInstrumentationService } from "../dist/application/frida/FridaInstrumentationService.js";
import { FridaInstrumentationManager } from "../dist/frida/FridaInstrumentationManager.js";

const options = parseArguments(process.argv.slice(2));
const manager = new FridaInstrumentationManager();
const service = new FridaInstrumentationService(manager);
const remote = {
  address: options.address,
  ...(options.token === undefined ? {} : { token: options.token }),
  ...(options.certificate === undefined
    ? {}
    : { certificate: options.certificate }),
  ...(options.origin === undefined ? {} : { origin: options.origin }),
  ...(options.keepaliveInterval === undefined
    ? {}
    : { keepaliveInterval: options.keepaliveInterval }),
};

try {
  const inventory = await service.listProcesses({ remote });
  if (!inventory.ok) throw new Error(inventory.error.message);
  const targetProcess = inventory.value.processes.find(
    ({ pid }) => pid === options.pid,
  );
  if (targetProcess === undefined)
    throw new Error(
      `Selected PID ${String(options.pid)} was not observed remotely`,
    );

  const result = await service.instrument({
    mode: "attach",
    remote,
    pid: options.pid,
    source: {
      sourceKind: "inline",
      source: "send({ rea_frida_verification: 'ok', pid: Process.id });",
    },
    durationMs: 500,
  });
  if (!result.ok) throw new Error(result.error.message);
  const observed = result.value.evidence.normalized_result;
  if (
    typeof observed !== "object" ||
    observed === null ||
    Array.isArray(observed) ||
    !Array.isArray(observed.messages)
  )
    throw new Error("Frida returned no message observation");
  const messageObserved = observed.messages.some(
    (message) =>
      typeof message === "object" &&
      message !== null &&
      !Array.isArray(message) &&
      message.type === "send" &&
      typeof message.payload === "object" &&
      message.payload !== null &&
      !Array.isArray(message.payload) &&
      message.payload.rea_frida_verification === "ok" &&
      message.payload.pid === options.pid,
  );
  if (!messageObserved)
    throw new Error("Selected remote target did not return the Frida marker");
  const report = {
    ok: result.value.cleanupError === null,
    provider: "frida",
    host_platform: process.platform,
    target_pid: options.pid,
    target_name: targetProcess.name,
    remote_target_observed: true,
    script_message_observed: true,
    cleanup_error: result.value.cleanupError,
  };
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (!report.ok) process.exitCode = 1;
} catch (cause) {
  process.stderr.write(
    `Frida real-provider verification failed: ${cause instanceof Error ? cause.message : String(cause)}\n`,
  );
  process.exitCode = 1;
} finally {
  await manager.closeAll().catch(() => undefined);
}

function parseArguments(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[index + 1];
    if (
      typeof flag !== "string" ||
      !flag.startsWith("--") ||
      value === undefined
    )
      throw new Error(
        "Expected --address HOST:PORT --pid PID and optional remote auth flags",
      );
    values.set(flag, value);
    index += 1;
  }
  const address = values.get("--address");
  const pid = Number(values.get("--pid"));
  if (address === undefined || /[?@#]/u.test(address))
    throw new Error(
      "--address is required and cannot contain credentials, query, or fragment data",
    );
  if (!Number.isSafeInteger(pid) || pid <= 0)
    throw new Error("--pid must be a positive process identifier");
  const keepalive = values.get("--keepalive-interval");
  const keepaliveInterval =
    keepalive === undefined ? undefined : Number(keepalive);
  if (
    keepaliveInterval !== undefined &&
    (!Number.isSafeInteger(keepaliveInterval) || keepaliveInterval <= 0)
  )
    throw new Error("--keepalive-interval must be a positive integer");
  return {
    address,
    pid,
    ...(values.has("--token") ? { token: values.get("--token") } : {}),
    ...(values.has("--certificate")
      ? { certificate: values.get("--certificate") }
      : {}),
    ...(values.has("--origin") ? { origin: values.get("--origin") } : {}),
    ...(keepaliveInterval === undefined ? {} : { keepaliveInterval }),
  };
}
