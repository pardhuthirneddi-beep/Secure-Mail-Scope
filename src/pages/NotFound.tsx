import { motion } from "framer-motion";
import { ShieldOff } from "lucide-react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="bg-background text-foreground flex min-h-screen flex-col items-center justify-center px-4"
    >
      <div className="border-border/70 bg-card/40 rounded-md border px-8 py-10 text-center">
        <ShieldOff className="text-muted-foreground mx-auto mb-4 size-8" />
        <h1 className="sms-mono text-3xl font-bold tracking-tight">404</h1>
        <p className="text-muted-foreground mt-2 text-sm">
          This route does not exist in the workstation.
        </p>
        <Button asChild size="sm" className="mt-6">
          <Link to="/dashboard">Back to Overview</Link>
        </Button>
      </div>
    </motion.div>
  );
}
