import '@vly-ai/integrations';
import { Toaster } from "@/components/ui/sonner";
import { Button } from "@/components/ui/button";
import { RequireAuth } from "@/components/RequireAuth";
import { VlyToolbar } from "../vly-toolbar-readonly.tsx";
import { ConvexAuthProvider } from "@convex-dev/auth/react";
import { ConvexReactClient } from "convex/react";
import React, { StrictMode, useEffect, lazy, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes, useLocation } from "react-router";
import "./index.css";

// Lazy load route components for better code splitting. Each import is
// wrapped in a one-shot retry: after a redeploy, a stale page can reference a
// renamed chunk that 404s once — retrying after the new build settles loads
// the route instead of leaving navigation stuck on the fallback.
function lazyRetry<T extends React.ComponentType<any>>(
  factory: () => Promise<{ default: T }>,
) {
  return lazy(async () => {
    try {
      return await factory();
    } catch (firstError) {
      console.warn("[route] chunk load failed, retrying once", firstError);
      await new Promise((r) => setTimeout(r, 300));
      return await factory();
    }
  });
}
const Landing = lazyRetry(() => import("./pages/Landing.tsx"));
const AuthPage = lazyRetry(() => import("./pages/Auth.tsx"));
const Dashboard = lazyRetry(() => import("./pages/Dashboard.tsx"));
const Captures = lazyRetry(() => import("./pages/Captures.tsx"));
const CaptureDetail = lazyRetry(() => import("./pages/CaptureDetail.tsx"));
const Findings = lazyRetry(() => import("./pages/Findings.tsx"));
const Reports = lazyRetry(() => import("./pages/Reports.tsx"));
const TestLab = lazyRetry(() => import("./pages/TestLab.tsx"));
const NotFound = lazyRetry(() => import("./pages/NotFound.tsx"));

// Simple loading fallback for route transitions — brand voice, amber pulse
function RouteLoading() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="flex items-center gap-2.5">
        <span className="bg-primary size-1.5 animate-pulse rounded-full" />
        <span className="sms-mono text-muted-foreground text-xs tracking-[0.08em] uppercase">
          Loading workstation
        </span>
      </div>
    </div>
  );}

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
 * Per-route error boundary. If a route module fails to load or render, show a
 * branded, recoverable panel instead of a silent hang. Resets automatically
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
    console.error("[route] render/load failure:", err);
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
            <p className="text-sm font-semibold">This section failed to load</p>
            <p className="text-muted-foreground mt-1.5 text-xs leading-relaxed">
              The route module could not be loaded — this can happen right after an
              update while the preview is still serving an old bundle. Reloading the
              workstation resolves it.
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
      <Suspense fallback={<RouteLoading />}>
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
      </Suspense>
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
