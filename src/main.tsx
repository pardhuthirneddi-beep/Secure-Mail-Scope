// Must be the first import: installs the performance.measure guard before
// react-dom is evaluated. See src/perf-guard.ts — prevents the React 19.2 dev
// component-renders trace from crashing the app on oversized props.
import "./perf-guard";
import '@vly-ai/integrations';
import { Toaster } from "@/components/ui/sonner";
import { Button } from "@/components/ui/button";
import { RequireAuth } from "@/components/RequireAuth";
import { VlyToolbar } from "../vly-toolbar-readonly.tsx";
import { ConvexAuthProvider } from "@convex-dev/auth/react";
import { ConvexReactClient } from "convex/react";
import React, { StrictMode, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes, useLocation } from "react-router";
import "./index.css";

// All route modules are imported statically (no lazy chunks). The preview
// environment has HMR disabled, so stale bundles previously failed to fetch
// renamed lazy chunks after a redeploy and navigation hung silently. With
// static imports every page is already in the bundle: navigation is pure
// client-side routing and can never fail on a chunk request.
import Landing from "./pages/Landing.tsx";
import AuthPage from "./pages/Auth.tsx";
import Dashboard from "./pages/Dashboard.tsx";
import Captures from "./pages/Captures.tsx";
import CaptureDetail from "./pages/CaptureDetail.tsx";
import Findings from "./pages/Findings.tsx";
import Reports from "./pages/Reports.tsx";
import TestLab from "./pages/TestLab.tsx";
import NotFound from "./pages/NotFound.tsx";

/** Route changes start at the top — long capture pages never land mid-scroll. */
function ScrollToTop() {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" as ScrollBehavior });
  }, [pathname]);
  return null;
}

/** Silent error boundary — if VlyToolbar crashes it renders nothing instead of
 *  crashing the whole app (e.g. hook errors in WebContainer environment). */
class ToolbarErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean }
> {
  state = { hasError: false };
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  componentDidCatch(err: Error) {
    console.warn("[VlyToolbar] Caught error, toolbar disabled:", err.message);
  }
  render() {
    return this.state.hasError ? null : this.props.children;
  }
}

/** Hard guard so runtime errors never leave the preview as a blank page. */
class RootErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; message: string; stack: string }
> {
  state = { hasError: false, message: "", stack: "" };
  static getDerivedStateFromError(error: Error) {
    return {
      hasError: true,
      message: error.message || "Unknown runtime error",
      stack: error.stack || "",
    };
  }
  componentDidCatch(err: Error) {
    console.error("[WebContainer preview] Root crash:", err);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background text-foreground p-6">
          <div className="max-w-lg text-center">
            <p className="text-sm font-semibold">Preview runtime error</p>
            <p className="mt-2 text-xs text-muted-foreground break-words">
              {this.state.message}
            </p>
            {this.state.stack && (
              <pre className="mt-3 text-left text-[10px] leading-4 text-muted-foreground/80 max-h-40 overflow-auto rounded border border-border/60 p-2">
                {this.state.stack}
              </pre>
            )}
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const convex = new ConvexReactClient(import.meta.env.VITE_CONVEX_URL as string);



function RouteSyncer() {
  const location = useLocation();
  useEffect(() => {
    window.parent.postMessage(
      { type: "iframe-route-change", path: location.pathname },
      "*",
    );
  }, [location.pathname]);

  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (event.data?.type === "navigate") {
        if (event.data.direction === "back") window.history.back();
        if (event.data.direction === "forward") window.history.forward();
      }
    }
    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, []);

  return null;
}


/**
 * Per-route error boundary: if a page crashes while rendering, show a
 * branded, recoverable panel instead of a blank screen. Resets automatically
 * when the user navigates elsewhere (path prop changes).
 */
class RouteErrorBoundary extends React.Component<
  { path: string; children: React.ReactNode },
  { hasError: boolean }
> {
  state = { hasError: false };
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  componentDidCatch(err: Error) {
    console.error("[route] render failure:", err);
  }
  componentDidUpdate(prev: { path: string }) {
    if (prev.path !== this.props.path && this.state.hasError) {
      this.setState({ hasError: false });
    }
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-background px-4">
          <div className="border-border/80 bg-card/40 w-full max-w-sm rounded-sm border p-6 text-center">
            <p className="text-sm font-semibold">This section hit an error</p>
            <p className="text-muted-foreground mt-1.5 text-xs leading-relaxed">
              The page failed while rendering. Reloading the workstation usually
              resolves it.
            </p>
            <Button size="sm" className="mt-4" onClick={() => window.location.reload()}>
              Reload workstation
            </Button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

/** Reads the location so the boundary resets on every navigation. */
function RouteArea() {
  const location = useLocation();
  return (
    <RouteErrorBoundary path={location.pathname}>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route
          path="/auth"
          element={<AuthPage redirectAfterAuth="/dashboard" />}
        />
        <Route
          path="/dashboard"
          element={
            <RequireAuth>
              <Dashboard />
            </RequireAuth>
          }
        />
        <Route
          path="/captures"
          element={
            <RequireAuth>
              <Captures />
            </RequireAuth>
          }
        />
        <Route
          path="/captures/:id"
          element={
            <RequireAuth>
              <CaptureDetail />
            </RequireAuth>
          }
        />
        <Route
          path="/findings"
          element={
            <RequireAuth>
              <Findings />
            </RequireAuth>
          }
        />
        <Route
          path="/reports"
          element={
            <RequireAuth>
              <Reports />
            </RequireAuth>
          }
        />
        <Route
          path="/test-lab"
          element={
            <RequireAuth>
              <TestLab />
            </RequireAuth>
          }
        />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </RouteErrorBoundary>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RootErrorBoundary>
      <ToolbarErrorBoundary>
        <VlyToolbar />
      </ToolbarErrorBoundary>
      <ConvexAuthProvider client={convex}>
        <BrowserRouter>
          <RouteSyncer />
          <ScrollToTop />
          <RouteArea />
        </BrowserRouter>
        <Toaster />
      </ConvexAuthProvider>
    </RootErrorBoundary>
  </StrictMode>,
);
