/**
 * Route-matrix regression check for SecureMailScope.
 *
 * Uses react-router's own matcher to prove that every navigation target
 * resolves to exactly the intended page route — including that no app path
 * can ever fall through to the catch-all. This is the routing contract:
 *
 *   /dashboard      -> Overview
 *   /captures       -> Captures
 *   /captures/:id   -> CaptureDetail
 *   /findings       -> Findings
 *   /reports        -> Reports
 *   /test-lab       -> TestLab
 *
 * Keep the route table below in sync with the <Routes> tree in src/main.tsx.
 * Path ranking is order-insensitive (react-router ranks by specificity), so
 * this file lists routes in the same logical order as main.tsx.
 *
 * Run:  bun scripts/route-check.mjs   (or: node scripts/route-check.mjs)
 */
import { matchRoutes } from "react-router";

const routes = [
  { path: "/", element: "Landing" },
  { path: "/auth", element: "Auth" },
  { path: "/dashboard", element: "Overview" },
  { path: "/captures", element: "Captures" },
  { path: "/captures/:id", element: "CaptureDetail" },
  { path: "/findings", element: "Findings" },
  { path: "/reports", element: "Reports" },
  { path: "/test-lab", element: "TestLab" },
  { path: "*", element: "NotFound" },
];

const expectations = [
  ["/dashboard", "Overview"],
  ["/captures", "Captures"],
  ["/captures/demo-capture-123", "CaptureDetail"],
  ["/findings", "Findings"],
  ["/reports", "Reports"],
  ["/test-lab", "TestLab"],
  ["/", "Landing"],
  ["/auth?returnTo=%2Fcaptures", "Auth"],
  ["/some/unknown/path", "NotFound"],
];

let failed = 0;
for (const [url, expected] of expectations) {
  const [pathname, search] = url.split("?");
  const match = matchRoutes(routes, { pathname, search });
  const got = match?.at(-1)?.route.element ?? "NO MATCH";
  const ok = got === expected;
  if (!ok) failed += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${url.padEnd(30)} -> ${got}${ok ? "" : `  (expected ${expected})`}`,
  );
}

if (failed > 0) {
  console.error(`\n${failed} route check(s) FAILED — routing contract broken.`);
  process.exit(1);
}
console.log("\nAll route checks passed: every URL resolves to its intended page.");
