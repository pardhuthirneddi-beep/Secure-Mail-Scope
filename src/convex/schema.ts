import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { Infer, v } from "convex/values";

// default user roles. can add / remove based on the project as needed
export const ROLES = {
  ADMIN: "admin",
  USER: "user",
  MEMBER: "member",
} as const;

export const roleValidator = v.union(
  v.literal(ROLES.ADMIN),
  v.literal(ROLES.USER),
  v.literal(ROLES.MEMBER),
);
export type Role = Infer<typeof roleValidator>;

const schema = defineSchema(
  {
    // default auth tables using convex auth.
    ...authTables, // do not remove or modify

    // the users table is the default users table that is brought in by the authTables
    users: defineTable({
      name: v.optional(v.string()), // name of the user. do not remove
      image: v.optional(v.string()), // image of the user. do not remove
      email: v.optional(v.string()), // email of the user. do not remove
      emailVerificationTime: v.optional(v.number()), // email verification time. do not remove
      isAnonymous: v.optional(v.boolean()), // is the user anonymous. do not remove

      role: v.optional(roleValidator), // role of the user. do not remove
    }).index("email", ["email"]), // index for the email. do not remove or modify

    // add other tables here

    // Stored capture analyses. The heavy analysis payloads (report, sessions,
    // evidence) are serialized JSON produced by the browser-side pipeline.
    captures: defineTable({
      userId: v.id("users"),
      name: v.string(),
      sizeBytes: v.number(),
      packetCount: v.number(),
      durationSec: v.number(),
      sessionCount: v.number(),
      findingCount: v.number(),
      highRiskCount: v.number(),
      criticalCount: v.number(),
      maxRisk: v.string(), // RiskLevel of the worst session
      isDemo: v.boolean(),
      demoScenarioId: v.optional(v.string()),
      reportJson: v.string(), // AnalysisReport
      sessionsJson: v.string(), // { sessions: Session[]; evidence: Evidence[] }
      uploadedAt: v.number(),
    })
      .index("by_user", ["userId"])
      .index("by_user_time", ["userId", "uploadedAt"]),

    // tableName: defineTable({
    //   ...
    //   // table fields
    // }).index("by_field", ["field"])
  },
  {
    schemaValidation: false,
  },
);

export default schema;
