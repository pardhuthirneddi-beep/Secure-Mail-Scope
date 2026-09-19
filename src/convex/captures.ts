import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { getCurrentUser } from "./users";

/**
 * Capture analyses belong to the signed-in user. The analysis itself runs
 * entirely in the browser; Convex persists the resulting evidence-linked
 * report so analysts can revisit and export it later.
 */

export const createCapture = mutation({
  args: {
    name: v.string(),
    sizeBytes: v.number(),
    packetCount: v.number(),
    durationSec: v.number(),
    sessionCount: v.number(),
    findingCount: v.number(),
    highRiskCount: v.number(),
    criticalCount: v.number(),
    maxRisk: v.string(),
    isDemo: v.boolean(),
    demoScenarioId: v.optional(v.string()),
    reportJson: v.string(),
    sessionsJson: v.string(),
  },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (!user) {
      throw new Error("Not authenticated");
    }
    const id = await ctx.db.insert("captures", {
      ...args,
      userId: user._id,
      uploadedAt: Date.now(),
    });
    return id;
  },
});

export const listCaptures = query({
  args: {},
  handler: async (ctx) => {
    const user = await getCurrentUser(ctx);
    if (!user) return [];
    return await ctx.db
      .query("captures")
      .withIndex("by_user_time", (q) => q.eq("userId", user._id))
      .order("desc")
      .collect();
  },
});

export const getCapture = query({
  args: { id: v.id("captures") },
  handler: async (ctx, { id }) => {
    const user = await getCurrentUser(ctx);
    if (!user) return null;
    const doc = await ctx.db.get(id);
    if (!doc || doc.userId !== user._id) return null;
    return doc;
  },
});

export const deleteCapture = mutation({
  args: { id: v.id("captures") },
  handler: async (ctx, { id }) => {
    const user = await getCurrentUser(ctx);
    if (!user) {
      throw new Error("Not authenticated");
    }
    const doc = await ctx.db.get(id);
    if (!doc || doc.userId !== user._id) {
      throw new Error("Capture not found");
    }
    await ctx.db.delete(id);
  },
});
