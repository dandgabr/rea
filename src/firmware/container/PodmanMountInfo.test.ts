import { expect, it } from "vitest";
import { parsePodmanMountInfo } from "./PodmanMountInfo.js";

it("retains escaped paths, source fields and stacked duplicate mount destinations", () => {
  const entries = parsePodmanMountInfo(
    "10 1 0:30 / / ro,nodev - overlay overlay rw\n11 10 0:31 /source\\040path /rea-input ro,nodev - ext4 /dev/sda1 rw\n12 10 0:32 /empty /sys/devices/virtual/powercap ro - tmpfs tmpfs rw\n13 12 0:32 /empty /sys/devices/virtual/powercap ro - tmpfs tmpfs rw\n",
  );
  expect(entries[1]!.root).toBe("/source path");
  expect(
    entries
      .filter((entry) => entry.destination === "/sys/devices/virtual/powercap")
      .map((entry) => [entry.id, entry.parent]),
  ).toEqual([
    [12, 10],
    [13, 12],
  ]);
});
it("refuses ambiguous escapes, duplicate mount IDs, malformed fields and bounded expansion", () => {
  const base = "10 1 0:30 / / ro,nodev - overlay overlay rw\n";
  for (const text of [
    base + base,
    base.replace("/ /", "/bad\\041 /"),
    base.replace(" ro,nodev", ""),
    base.replace("10 1", "-1 1"),
    base.replace(" - ", " "),
    base.replace("0:30", "device"),
    base.repeat(10001),
  ])
    expect(() => parsePodmanMountInfo(text)).toThrow();
});
it("retains exact escaped names and refuses invalid identities with seed0x4d4e5431 across256cases", () => {
  let seed = 0x4d4e5431;
  for (let index = 0; index < 256; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const name = `/private/${seed} space\\name`;
    const encoded = name.replaceAll("\\", "\\134").replaceAll(" ", "\\040");
    const record = `${index + 2} 1 0:30 ${encoded} /rea-input ro - ext4 /dev/sda1 rw\n`;
    expect(parsePodmanMountInfo(record)[0]!.root).toBe(name);
    expect(() =>
      parsePodmanMountInfo(record.replace(`${index + 2} 1`, `-${index + 2} 1`)),
    ).toThrow();
  }
});
