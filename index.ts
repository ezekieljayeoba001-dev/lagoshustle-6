import { Hono } from "hono";
import { GetSearch } from "./endpoints/search";
import {
  authenticateUser,
  AuthLogin,
  AuthRegister,
} from "./foundation/auth";
import { Env } from "./types";

const app = new Hono<{ Bindings: Env }>();

// Check that the Worker is running
app.get("/api/health", (c) => {
  return c.json({
    success: true,
    message: "Lagos Hustle Worker is running",
  });
});

// Public authentication routes
app.post("/api/auth/register", AuthRegister);
app.post("/api/auth/login", AuthLogin);

// Protect the remaining API routes
app.use("/api/*", authenticateUser);

// Authenticated endpoint
app.get("/api/search", GetSearch);

// Return a clear response for unknown API routes
app.all("/api/*", (c) => {
  return c.json(
    {
      success: false,
      error: "API route not found",
      path: new URL(c.req.url).pathname,
    },
    404
  );
});

// Other unknown routes
app.notFound((c) => {
  return c.text("Not Found", 404);
});

export default app;
