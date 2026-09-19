import { motion } from "framer-motion";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="bg-background text-foreground flex min-h-screen flex-col items-center justify-center px-4"
    >
      <div className="w-full max-w-sm">
        <div className="sms-mono text-muted-foreground/70 flex items-center justify-between text-[10px] tracking-[0.14em] uppercase">
          <span>securemailscope</span>
          <span>err 404</span>
        </div>
        <div className="border-border/80 bg-card/40 mt-2 rounded-sm border p-8 text-center">
          <p className="sms-mono text-2xl font-semibold tracking-tight">404</p>
          <p className="text-muted-foreground mt-2 text-sm">
            This route does not exist in the workstation.
          </p>
          <Button asChild size="sm" className="mt-6">
            <Link to="/dashboard">Back to Overview</Link>
          </Button>
        </div>
      </div>
    </motion.div>
  );
}
