import { api } from "@/convex/_generated/api";
import { useAuthActions } from "@convex-dev/auth/react";
import { useConvexAuth, useQuery } from "convex/react";

export function useAuth() {
  const { isLoading: isAuthLoading, isAuthenticated } = useConvexAuth();
  const user = useQuery(api.users.currentUser);
  const { signIn, signOut } = useAuthActions();

  return {
    /** True only while the auth handshake is in flight. */
    isAuthLoading,
    /** Aliased to the handshake flag on purpose: route guards must never block
     *  on the `currentUser` profile subscription, which can stall forever if
     *  the Convex socket idles out in the preview iframe. Callers that need
     *  the profile can check `user` directly. */
    isLoading: isAuthLoading,
    isAuthenticated,
    user,
    signIn,
    signOut,
  };
}
