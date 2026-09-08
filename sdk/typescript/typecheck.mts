// SPDX-License-Identifier: GPL-3.0-or-later

import { Session, type ApiResponse } from "./dist/index.js";

function check(session: Session) {
  session.launch({ program: "/workspace/app", argv: ["a b"], stop: "main" });
  session.control({ action: "until", location: "main", wait: { until: "stopped" } });
  session.control({ action: "continue", input: { text: "1\n" },
    wait: { until: "snapshot" }, inspect: [{ view: "threads", stack_depth: 8 }] });
  session.control({ action: "interrupt", wait: { until: "settled" },
    inspect: [{ view: "crash", profile: "brief" }] });
  const stack: Promise<ApiResponse<{ frames: unknown[] }>> = session.inspect({
    view: "stack", stop_id: "stop_1", limit: 8,
  });
  session.inspect({ view: "registers", accept_current_stop: true, roles: ["pc", "sp"] });
  session.call("inspection.get", { view: "symbols", query: "main" });

  // @ts-expect-error Launch requires the executable.
  session.launch({ argv: ["/workspace/app"] });
  // @ts-expect-error Unknown wait policy.
  session.control({ action: "continue", wait: { until: "stop" } });
  // @ts-expect-error Run-until requires a location.
  session.control({ action: "until" });
  // @ts-expect-error Inspection must pin or explicitly accept the current stop.
  session.inspect({ view: "stack", limit: 8 });
  // @ts-expect-error View names are checked.
  session.inspect({ view: "stacks", accept_current_stop: true });
  // @ts-expect-error A running acknowledgement cannot support stop inspection.
  session.control({ action: "continue", wait: { until: "running" }, inspect: [{ view: "stack" }] });
  // @ts-expect-error Inspection needs an explicit stop-producing wait.
  session.control({ action: "continue", inspect: [{ view: "stack" }] });
  // @ts-expect-error Interrupt cannot feed input.
  session.control({ action: "interrupt", input: { text: "1\n" } });
  // @ts-expect-error Input has exactly one encoding.
  session.control({ action: "continue", input: { text: "1", data_base64: "MQ==" } });
  return stack;
}
