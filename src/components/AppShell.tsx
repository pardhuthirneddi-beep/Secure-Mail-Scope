import { useAuth } from "@/hooks/use-auth";
import { cn } from "@/lib/utils";
import { BrandMark, BrandWordmark, ForensicWaves } from "@/components/sms-brand";
import { Button } from "@/components/ui/button";
import {
  FlaskConical,
  LayoutDashboard,
  LogOut,
  ScanSearch,
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
 * Persistent workstation shell for all authenticated routes: graphite sidebar
 * with amber active rule and mono route codes, compact top bar, and the
 * operator block over the forensic wave signature. Navigation and routes are
 * unchanged from the original shell.
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
    <div
      data-testid={`page-${title.toLowerCase().replace(/\s+/g, "-")}`}
      className="bg-background text-foreground flex min-h-screen"
    >
      <aside className="bg-sidebar border-border/70 hidden w-56 shrink-0 flex-col border-r md:flex">
        <Link
          to="/"
          className="border-border/70 hover:bg-accent/40 flex h-14 items-center gap-2.5 border-b px-4 transition-colors"
        >
          <BrandMark size={26} />
          <BrandWordmark compact />
        </Link>
        <div className="sms-label text-muted-foreground/60 px-4 pt-4 pb-2">Workstation</div>
        <nav className="flex flex-1 flex-col gap-px px-2">
          {NAV.map((item) => {
            const active =
              location.pathname === item.to || location.pathname.startsWith(item.to + "/");
            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "group relative flex items-center gap-2.5 rounded-sm px-2.5 py-2 text-[13px] transition-colors",
                  active
                    ? "bg-primary/10 text-foreground font-medium"
                    : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
                )}
              >
                {/* amber active rule */}
                <span
                  className={cn(
                    "bg-primary absolute top-1.5 bottom-1.5 left-0 w-0.5 rounded-full transition-opacity duration-200",
                    active ? "opacity-100" : "opacity-0",
                  )}
                />
                <item.icon
                  className={cn(
                    "size-3.5 shrink-0 transition-colors",
                    active ? "text-primary" : "text-muted-foreground/70 group-hover:text-foreground/80",
                  )}
                />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Forensic wave signature at the sidebar base — ambient, non-interactive */}
        <div className="border-border/70 relative border-t">
          <ForensicWaves height={64} tone="soft" />
          <div className="absolute inset-x-0 bottom-0 p-3">
            <div className="sms-label text-muted-foreground">Operator</div>
            <div
              className="sms-mono mt-1 truncate text-xs"
              title={user?.email ?? user?.name ?? ""}
            >
              {user?.email ?? user?.name ?? "Analyst"}
            </div>
            <Button
              variant="outline"
              size="sm"
              className="mt-2.5 w-full gap-2 bg-background/80 text-xs"
              onClick={handleSignOut}
            >
              <LogOut className="size-3.5" />
              Sign out
            </Button>
            {/* Diagnostic build tag + live route: if the route shown here does
                not match the page content on screen, the tab is running stale
                code and must be reloaded. */}
            <div className="sms-mono text-muted-foreground/40 mt-2 text-center text-[9px]">
              build r6 · {location.pathname}
            </div>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="border-border/70 bg-background/95 sticky top-0 z-20 border-b">
          <div className="flex h-14 items-center justify-between gap-4 px-4 md:px-8">
            <div className="flex min-w-0 items-baseline gap-3">
              <Link to="/dashboard" className="md:hidden">
                <BrandMark size={26} />
              </Link>
              <h1 className="truncate text-sm font-semibold tracking-tight">{title}</h1>
              {subtitle && (
                <p className="text-muted-foreground hidden truncate text-xs lg:block">{subtitle}</p>
              )}
            </div>
            <div className="flex items-center gap-2">{actions}</div>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 md:px-8 md:py-8">{children}</main>
        {/* Mobile navigation */}
        <nav className="border-border/70 bg-background sticky bottom-0 z-20 flex border-t md:hidden">
          {NAV.map((item) => {
            const active =
              location.pathname === item.to || location.pathname.startsWith(item.to + "/");
            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "relative flex flex-1 flex-col items-center gap-0.5 py-2 text-[10px] transition-colors",
                  active ? "text-primary" : "text-muted-foreground",
                )}
              >
                {active && <span className="bg-primary absolute top-0 h-0.5 w-6 rounded-full" />}
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
