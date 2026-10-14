import { describe, expect, it } from "vitest";

import { createDocumentSvgAncestry, domSvgLink } from "./CdpCaptureDomSvg.js";

const snapshot = (attributes: readonly unknown[]) => ({
  nodeTypes: [9, 1],
  nodeNames: [0, 1],
  parents: [-1, 0],
  strings: ["#document", "svg", "xmlns", "http://www.w3.org/2000/svg", "id"],
  attributes: [[], attributes],
});

describe("DOMSnapshot absent attribute values", () => {
  it("keeps the document's XML identity when a value-less attribute is reported as -1", () => {
    const ancestry = createDocumentSvgAncestry(snapshot([2, 3, 4, -1]));

    expect(ancestry.xml).toBe(true);
    expect(domSvgLink(ancestry, 1)).toMatchObject({
      svgElement: true,
      xmlDocument: true,
    });
  });

  it.each([
    ["an out-of-range value index", [2, 3, 4, 99]],
    ["a negative index other than the absent marker", [2, 3, 4, -2]],
    ["an absent attribute name", [-1, 3]],
  ])("treats %s as unknown rather than as a document fact", (_name, pairs) => {
    const ancestry = createDocumentSvgAncestry(snapshot(pairs));

    expect(ancestry.xml).toBeUndefined();
  });
});
