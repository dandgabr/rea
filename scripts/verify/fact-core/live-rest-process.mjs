import { ChildProcess } from "node:child_process";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { ProviderProcessSupervisor } from "../../../dist/process/ProviderProcess.js";

// SDK 2.3.1's public pid cannot prove process ownership. Its pinned stdio
// implementation stores the original spawned ChildProcess in _process. Capture
// that exact object during start, before a close can clear the SDK field. This
// harness-only bridge is guarded by the SDK binding/real-child regression.
export class OwnedLiveRestTransport extends StdioClientTransport {
  #processOwner;

  get processOwner() {
    return this.#processOwner;
  }

  async start() {
    try {
      await super.start();
    } finally {
      const child = this._process;
      if (child !== undefined && child.pid !== undefined) {
        if (!(child instanceof ChildProcess) || child.pid !== this.pid)
          throw new Error("FACT live stdio child ownership unavailable");
        this.#processOwner = new ProviderProcessSupervisor(
          { process: child, ownsProcessLifetime: true },
          // MCP stdout remains protocol-owned; no diagnostic bytes or secrets
          // are retained by the independent process lifecycle owner.
          { captureStdout: false, maxDiagnosticBytes: 0 },
        );
      }
    }
  }
}
