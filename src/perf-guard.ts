/**
 * React 19.2 dev builds instrument every component render for the Chrome
 * DevTools "Component Renders" track: changed props are diffed and their raw
 * values are passed as `performance.measure(..., { detail })`, which the
 * browser must structured-clone. When a prop carries large payloads (parsed
 * PCAP sessions/evidence, full report JSON), cloning fails with
 * `DataCloneError: Data cannot be cloned, out of memory` — and because the
 * call happens inside a passive effect, the uncaught error crashes the whole
 * app.
 *
 * A dropped DevTools trace entry is observability, never correctness, so this
 * guard swallows exactly that failure and lets every other measure through.
 * It must be imported before react-dom so the wrapper is installed first.
 */

let warned = false;

const nativeMeasure = performance.measure.bind(performance);

performance.measure = ((...args: Parameters<typeof performance.measure>) => {
  try {
    return nativeMeasure(...args);
  } catch (error) {
    const isCloneFailure =
      error instanceof DOMException &&
      (error.name === "DataCloneError" ||
        error.message.includes("out of memory"));
    if (!isCloneFailure) throw error;
    if (!warned) {
      warned = true;
      console.warn(
        "[perf-guard] Dropped a performance.measure entry whose payload could not " +
          "be structured-cloned (React dev component-renders trace). Dev-tooling " +
          "telemetry only — the app is unaffected.",
      );
    }
    return undefined as unknown as PerformanceMeasure;
  }
}) as typeof performance.measure;
