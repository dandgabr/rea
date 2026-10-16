import { rm } from "node:fs/promises";

// Client.close() itself closes this transport. Settle sequentially so two
// concurrent closes cannot race, while independently attempting each owner.
// Keep original failures and failed owners available privately; callers publish
// resource names only, never error messages or subprocess response bodies.
export async function settleLiveRestResources({
  client,
  transport,
  temporary,
  primaryError,
  operationFailed = false,
  processOwner,
}) {
  const attempted = [];
  const failures = [];
  let processSettlement;
  try {
    if (client !== undefined) {
      attempted.push("client");
      try {
        await client.close();
      } catch (error) {
        failures.push({ resource: "client", owner: client, error });
      }
    }
  } finally {
    try {
      if (transport !== undefined) {
        attempted.push("transport");
        try {
          await transport.close();
        } catch (error) {
          failures.push({ resource: "transport", owner: transport, error });
        }
      }
    } finally {
      try {
        if (processOwner !== undefined) {
          attempted.push("process");
          try {
            // Independent of the SDK's close implementation. The supervisor
            // signals only its retained original ChildProcess, never a pid.
            const stopped = await processOwner.stop({
              terminationGraceMs: 250,
              killGraceMs: 1000,
            });
            processSettlement = {
              status: stopped.status,
              exited: processOwner.observedExit() !== undefined,
            };
            if (stopped.status === "incomplete" || !processSettlement.exited)
              throw new Error("FACT live owned process cleanup incomplete", {
                cause: stopped,
              });
          } catch (error) {
            processSettlement ??= { status: "incomplete", exited: false };
            failures.push({ resource: "process", owner: processOwner, error });
          }
        }
      } finally {
        if (temporary !== undefined) {
          attempted.push("home");
          try {
            await rm(temporary, { recursive: true });
          } catch (error) {
            failures.push({ resource: "home", owner: temporary, error });
          }
        }
      }
    }
  }
  const error = failures.length
    ? new AggregateError(
        [
          ...(operationFailed ? [primaryError] : []),
          ...failures.map(({ error }) => error),
        ],
        "FACT live acceptance resource settlement failed",
        operationFailed ? { cause: primaryError } : undefined,
      )
    : primaryError;
  return { error, failures, attempted, process: processSettlement };
}
