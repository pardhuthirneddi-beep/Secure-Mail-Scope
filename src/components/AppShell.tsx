import { useAuth } from "@/hooks/use-auth";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  FlaskConical,
  LayoutDashboard,
  LogOut,
  ScanSearch,
  ShieldCheck,
  FileWarning,
  FileText,
} from "lucide-react";
import type { ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router";

const NAV = [
  { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { to: "/captures", label: "Captures", icon: ScanSearch },
  { to: "/findings", label: "Findings", icon: FileWarning },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/test-lab", label: "Test Lab", icon: FlaskConical },
];

/**
 * Persistent workstation shell for all authenticated routes: fixed sidebar
 * navigation, top bar with product identity, and the user menu.
 */
export function AppShell({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  return (
    <div className="bg-background text-foreground flex min-h-screen">
      <aside className="bg-sidebar/60 border-border/70 hidden w-56 shrink-0 flex-col border-r md:flex">
        <Link to="/" className="flex h-14 items-center gap-2.5 border-b border-border/70 px-4">
          <div className="bg-primary/15 flex size-7 items-center justify-center rounded-sm">
            <ShieldCheck className="text-primary size-4" />
          </div>
          <div className="leading-tight">
            <div className="text-[13px] font-semibold tracking-tight">Secure Mail Analysis</div>
            <div className="text-muted-foreground text-[10px]">Security posture workstation</div>
          </div>
        </Link>
        <nav className="flex flex-1 flex-col gap-0.5 p-2">
          {NAV.map((item) => {
            const active =
              location.pathname === item.to || location.pathname.startsWith(item.to + "/");
            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "flex items-center gap-2.5 rounded-sm px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-primary/10 text-primary font-medium"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )}
              >
                <item.icon className="size-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-border/70 border-t p-3">
          <div className="text-muted-foreground mb-1 text-[11px]">Signed in as</div>
          <div className="truncate text-xs font-medium">
            {user?.email ?? user?.name ?? "analyst"}
          </div>
          <Button
            variant="outline"
            size="sm"
            className="mt-2 w-full gap-2 text-xs"
            onClick={handleSignOut}
          >
            <LogOut className="size-3.5" />
            Sign out
          </Button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="border-border/70 bg-background/80 sticky top-0 z-10 border-b backdrop-blur">
          <div className="flex h-14 items-center justify-between gap-4 px-4 md:px-6">
            <div className="flex min-w-0 items-center gap-3">
              <Link to="/dashboard" className="md:hidden">
                <ShieldCheck className="text-primary size-5" />
              </Link>
              <div className="min-w-0">
                <h1 className="truncate text-sm font-semibold tracking-tight">{title}</h1>
                {subtitle && (
                  <p className="text-muted-foreground truncate text-xs">{subtitle}</p>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2">{actions}</div>
          </div>
        </header>
        <main className="flex-1 px-4 py-6 md:px-6">{children}</main>
        {/* Mobile navigation */}
        <nav className="border-border/70 sticky bottom-0 z-10 flex border-t md:hidden">
          {NAV.map((item) => {
            const active =
              location.pathname === item.to || location.pathname.startsWith(item.to + "/");
            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "flex flex-1 flex-col items-center gap-0.5 py-2 text-[10px]",
                  active ? "text-primary" : "text-muted-foreground",
                )}
              >
                <item.icon className="size-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>
      </div>
    </div>
  );
}
