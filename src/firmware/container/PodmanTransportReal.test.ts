import { expect, it } from "vitest";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { PreparedPodmanTransport as SourceTransport } from "./PodmanTransport.js";
const PreparedPodmanTransport: typeof SourceTransport =
  process.env.REA_CONTAINER_TEST_MODULE === undefined
    ? SourceTransport
    : (await import(process.env.REA_CONTAINER_TEST_MODULE))
        .PreparedPodmanTransport;
import { readFile } from "node:fs/promises";
import { parseLinuxProcessStartTime } from "../../process/ProcessOwnershipObservation.js";

const profile = process.env.REA_CONTAINER_TEST_STORE_PROFILE;
const image = process.env.REA_CONTAINER_TEST_IMAGE;
it.skipIf(profile === undefined || image === undefined)(
  "observes the explicitly preinitialized real store/local immutable image through the same prepared transport without any producer launch",
  async () => {
    const scope = new ArtifactResourceScope();
    const signal = AbortSignal.timeout(30_000);
    const transport = await PreparedPodmanTransport.prepare({
      profile: profile!,
      command: "/usr/bin/podman",
      limiter: "/usr/bin/prlimit",
      signal,
      scope,
    });
    let unrelated: { pid: number; start: string | undefined } | undefined;
    try {
      const runtime = await transport.probe(signal);
      if (process.env.REA_CONTAINER_TEST_UNRELATED_CID !== undefined) {
        const observation = await transport.run(
          [
            "inspect",
            "--format=json",
            "--",
            process.env.REA_CONTAINER_TEST_UNRELATED_CID,
          ],
          signal,
        );
        const actual = JSON.parse(observation.stdout.text)[0] as {
          Id: string;
          State: { Pid: number; Running: boolean };
        };
        expect(actual.Id).toBe(process.env.REA_CONTAINER_TEST_UNRELATED_CID);
        expect(actual.State.Running).toBe(true);
        unrelated = {
          pid: actual.State.Pid,
          start: parseLinuxProcessStartTime(
            await readFile(`/proc/${actual.State.Pid}/stat`, "utf8"),
          ),
        };
      }
      const identity = await transport.image(image!, signal);
      expect(runtime.version.stdout.text.trim()).toBe("podman version 5.8.7");
      expect(runtime.info.stdout.utf8Valid).toBe(true);
      expect(identity.selected_reference).toBe(image);
      expect(identity.image_id).toMatch(/^[a-f0-9]{64}$/u);
      expect(runtime.store.shared_helper).toMatchObject({
        authority: "external_shared_infrastructure",
        pid: transport.store.selection.shared_helper.pid,
        start_ticks: transport.store.selection.shared_helper.start_ticks,
      });
    } finally {
      await transport.close();
      await scope.close();
    }
    if (unrelated !== undefined)
      expect(
        parseLinuxProcessStartTime(
          await readFile(`/proc/${unrelated.pid}/stat`, "utf8"),
        ),
      ).toBe(unrelated.start);
  },
  35_000,
);
