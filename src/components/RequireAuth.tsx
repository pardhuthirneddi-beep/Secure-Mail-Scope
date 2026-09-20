import { useAuth } from "@/hooks/use-auth";
import { Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router";

/**
 * Route guard: gates only on the auth handshake (`useConvexAuth`), never on
 * the `currentUser` profile query. If the Convex WebSocket stalls in the
 * preview iframe, a pending profile subscription used to hold every route on
 * an infinite spinner ("page not responding"). Auth identity is what protects
 * these routes; the profile is display-only and the shell already falls back
 * to a placeholder when it is absent.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  // Gate ONLY on the auth handshake. The `currentUser` profile subscription is
  // display-only (the shell falls back to "Analyst") and can stall forever if
  // the Convex socket idles out in the preview iframe — blocking on it held
  // every protected route on the loader while the URL had already changed.
  const { isAuthLoading, isAuthenticated } = useAuth();
  const location = useLocation();

  if (isAuthLoading) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-background">
        <Loader2 className="size-6 animate-spin text-muted-foreground" />
      </main>
    );
  }

  if (!isAuthenticated) {
    const returnTo = `${location.pathname}${location.search}`;
    return (
      <Navigate
        to={`/auth?returnTo=${encodeURIComponent(returnTo)}`}
        replace
      />
    );
  }

  return children;
}
