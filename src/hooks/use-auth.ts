import { api } from "@/convex/_generated/api";
import { useAuthActions } from "@convex-dev/auth/react";
import { useConvexAuth, useQuery } from "convex/react";

export function useAuth() {
  const { isLoading: isAuthLoading, isAuthenticated } = useConvexAuth();
  const user = useQuery(api.users.currentUser);
  const { signIn, signOut } = useAuthActions();

  return {
    /** True only while the auth handshake is in flight — never blocks on the
     *  profile subscription, which can stall if the Convex socket idles out. */
    isAuthLoading,
    /** Convenience flag for callers that need a profile before rendering. */
    isLoading: isAuthLoading || user === undefined,
    isAuthenticated,
    user,
    signIn,
    signOut,
  };
}
