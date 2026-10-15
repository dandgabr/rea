import { expect, it } from "vitest";
import {
  admitPodmanContainerInspection,
  OwnedPodmanContainer,
} from "./OwnedPodmanContainer.js";

const cid = "b".repeat(64),
  image = "a".repeat(64),
  token = "c".repeat(32);
const expected = {
  id: cid,
  image_id: image,
  token,
  graph_root: "/store/graph",
};
const record = {
  Id: cid,
  Image: image,
  Created: "2026-10-13T00:00:00.000Z",
  StaticDir: `/store/graph/overlay-containers/${cid}/userdata`,
  OCIConfigPath: `/store/graph/overlay-containers/${cid}/userdata/config.json`,
  Config: { Labels: { "rea.firmware.owner": token } },
  State: { Status: "created", Pid: 0, Running: false, ExitCode: 0 },
  GraphDriver: { Name: "overlay", Data: { MergedDir: "" } },
};
it("binds full CID, image, owner label and exact store userdata before lifecycle authority", () => {
  expect(admitPodmanContainerInspection([record], expected)).toMatchObject({
    id: cid,
    image_id: image,
    created: record.Created,
    pid: 0,
  });
  for (const candidate of [
    { ...record, Id: "d".repeat(64) },
    { ...record, Image: "d".repeat(64) },
    { ...record, Config: { Labels: {} } },
    { ...record, StaticDir: "/unrelated/userdata" },
    { ...record, OCIConfigPath: "/unrelated/config.json" },
    { ...record, State: { ...record.State, Pid: -1 } },
    { ...record, GraphDriver: { Name: "fuse", Data: { MergedDir: "" } } },
  ])
    expect(() =>
      admitPodmanContainerInspection([candidate], expected),
    ).toThrow();
});
it("preserves immutable container generation and refuses ambiguous or changed creation identity", () => {
  const generation = admitPodmanContainerInspection([record], expected);
  expect(() =>
    admitPodmanContainerInspection(
      [{ ...record, Created: "2026-10-14T00:00:00Z" }],
      { ...expected, generation },
    ),
  ).toThrow();
  expect(() =>
    admitPodmanContainerInspection([record, record], expected),
  ).toThrow();
  expect(() =>
    admitPodmanContainerInspection(
      [{ ...record, Created: "unknown" }],
      expected,
    ),
  ).toThrow();
});

it("refuses REA-managed container acquisition before inspecting or changing Podman state", async () => {
  await expect(OwnedPodmanContainer.acquire({} as never)).rejects.toThrow(
    "REA-managed container creation and lifecycle are disabled",
  );
});
