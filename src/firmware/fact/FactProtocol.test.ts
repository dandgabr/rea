import { expect, it, vi } from "vitest";
import { FactResponseResources, readFactResponse } from "./FactProtocol.js";

it("retains a rejected body reader when cancellation fails and retries only cleanup on close", async () => {
  let cancellations = 0;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(Buffer.from("{"));
    },
    cancel() {
      cancellations++;
      throw Error("injected transport cancellation failure");
    },
  });
  const response = new Response(body, { headers: { "content-length": "4" } });
  const resources = new FactResponseResources();
  await expect(
    readFactResponse(response, 3, new AbortController().signal, resources),
  ).rejects.toThrow("wire byte budget");
  expect(cancellations).toBe(1);
  expect(body.locked).toBe(true);
  expect(resources.pendingResources).toEqual(["FACT HTTP response body"]);
  // The native stream closed even though its first cancellation rejected. The
  // retained reader can now acknowledge cancellation and release its lock.
  await resources.close();
  expect(resources.pendingResources).toEqual([]);
  expect(body.locked).toBe(false);
  expect(cancellations).toBe(1);
});

it("preserves admitted bytes while retaining failed cancellation ownership across close failures", async () => {
  class FailingCancellation extends FactResponseResources {
    override acquire(response: Response) {
      const reader = super.acquire(response);
      if (reader)
        vi.spyOn(reader, "cancel")
          .mockRejectedValueOnce(Error("injected observation cleanup failure"))
          .mockRejectedValueOnce(Error("injected first close failure"));
      return reader;
    }
  }
  const resources = new FailingCancellation();
  const response = new Response("abc");
  const bytes = await readFactResponse(
    response,
    3,
    new AbortController().signal,
    resources,
  );
  expect(bytes.toString()).toBe("abc");
  expect(resources.pendingResources).toHaveLength(1);
  await expect(resources.close()).rejects.toThrow("cleanup remains unresolved");
  expect(resources.pendingResources).toHaveLength(1);
  await resources.close();
  expect(resources.pendingResources).toEqual([]);
  expect(response.body!.locked).toBe(false);
});

it("cancels an admitted header response when streaming bytes exceed the budget", async () => {
  let cancellations = 0;
  const response = new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(Buffer.from("abcd"));
      },
      cancel() {
        cancellations++;
      },
    }),
  );
  const resources = new FactResponseResources();
  await expect(
    readFactResponse(response, 3, new AbortController().signal, resources),
  ).rejects.toThrow("wire byte budget");
  expect(cancellations).toBe(1);
  expect(resources.pendingResources).toEqual([]);
  expect(response.body!.locked).toBe(false);
});
