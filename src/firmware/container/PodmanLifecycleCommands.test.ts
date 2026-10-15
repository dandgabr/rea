import { expect, it } from "vitest";
import { admitPodmanLifecycleCommand } from "./PodmanLifecycleCommands.js";
import { PreparedPodmanTransport } from "./PodmanTransport.js";

it("fails closed for every production container lifecycle or selection command", () => {
  const cid = "b".repeat(64);
  for (const command of [
    ["create", "--pull=never", "--", `sha256:${"a".repeat(64)}`],
    ["init", "--", cid],
    ["start", "--attach", "--", cid],
    ["stop", "--time=1", "--", cid],
    ["kill", "--signal=KILL", "--", cid],
    ["rm", "--force", "--", cid],
    ["container", "exists", "--", cid],
    [
      "ps",
      "--all",
      `--filter=label=rea.firmware.owner=${"c".repeat(32)}`,
      "--format={{.ID}}",
      "--no-trunc",
    ],
  ]) {
    expect(admitPodmanLifecycleCommand(command)).toBe(false);
  }
});

it("does not issue a lifecycle command owner through production transport", () => {
  expect(PreparedPodmanTransport.prototype).not.toHaveProperty(
    "acquireContainerCommands",
  );
});
