import {
  ApiException,
  Bool,
  contentJson,
  Email,
  Int,
  Obj,
  OpenAPIRoute,
  Str,
} from "chanfana";
import { D1QB } from "workers-qb";
import { AppContext, User, UserSession } from "../types";
import { Next } from "hono";
import z from "zod";

/**
 * Hash a password using the existing project method.
 * Keeps compatibility with passwords created by the existing code.
 */
async function hashPassword(
  password: string,
  salt: string
): Promise<string> {
  const utf8 = new TextEncoder().encode(`${salt}:${password}`);
  const hashBuffer = await crypto.subtle.digest("SHA-256", utf8);

  return Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Register a new user.
 */
export class AuthRegister extends OpenAPIRoute {
  schema = {
    tags: ["Auth"],
    summary: "Register user",
    request: {
      body: contentJson(
        z.object({
          name: z.string().trim().min(1).max(60),
          email: Email(),
          password: Str().min(8).max(16),
        })
      ),
    },
    responses: {
      "200": {
        description: "Successful response",
        content: {
          "application/json": {
            schema: Obj({
              success: Bool(),
              result: Obj({
                user: Obj({
                  email: Str(),
                  name: Str(),
                }),
              }),
            }),
          },
        },
      },
      "400": {
        description: "Registration error",
        content: {
          "application/json": {
            schema: Obj({
              success: Bool(),
              error: Str(),
            }),
          },
        },
      },
    },
  };

  async handle(c: AppContext) {
    const data = await this.getValidatedData<typeof this.schema>();
    const body = data.body;
    const qb = new D1QB(c.env.AUTH_DB);

    try {
      await qb
        .insert({
          tableName: "users",
          data: {
            email: body.email,
            name: body.name,
            password: await hashPassword(
              body.password,
              c.env.SALT_TOKEN
            ),
          },
        })
        .execute();

      return {
        success: true,
        result: {
          user: {
            email: body.email,
            name: body.name,
          },
        },
      };
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);

      if (message.includes("UNIQUE constraint failed")) {
        return Response.json(
          {
            success: false,
            error: "An account with that email already exists.",
          },
          { status: 400 }
        );
      }

      console.error("Registration failed:", error);

      return Response.json(
        {
          success: false,
          error: "Registration failed. Please check the Worker logs.",
        },
        { status: 500 }
      );
    }
  }
}

/**
 * Log in an existing user and create a session.
 */
export class AuthLogin extends OpenAPIRoute {
  schema = {
    tags: ["Auth"],
    summary: "Log in user",
    request: {
      body: contentJson(
        z.object({
          email: Email(),
          password: Str().min(8).max(16),
        })
      ),
    },
    responses: {
      "200": {
        description: "Successful response",
        content: {
          "application/json": {
            schema: Obj({
              success: Bool(),
              result: Obj({
                session: Obj({
                  token: Str(),
                  expires_at: Int(),
                }),
              }),
            }),
          },
        },
      },
      "400": {
        description: "Login error",
        content: {
          "application/json": {
            schema: Obj({
              success: Bool(),
              error: Str(),
            }),
          },
        },
      },
    },
  };

  async handle(c: AppContext) {
    const data = await this.getValidatedData<typeof this.schema>();
    const body = data.body;

    // Use the database binding configured in wrangler.json.
    const qb = new D1QB(c.env.AUTH_DB);

    const user = await qb
      .fetchOne<User>({
        tableName: "users",
        fields: "*",
        where: {
          conditions: ["email = ?1", "password = ?2"],
          params: [
            body.email,
            await hashPassword(body.password, c.env.SALT_TOKEN),
          ],
        },
      })
      .execute();

    if (!user.results) {
      return Response.json(
        {
          success: false,
          error: "Invalid email or password.",
        },
        { status: 400 }
      );
    }

    const expiration = new Date();
    expiration.setDate(expiration.getDate() + 7);

    const session = await qb
      .insert<UserSession>({
        tableName: "users_sessions",
        data: {
          user_id: user.results.id,
          token: await hashPassword(
            crypto.randomUUID(),
            c.env.SALT_TOKEN
          ),
          expires_at: expiration.getTime(),
        },
        returning: "*",
      })
      .execute();

    if (!session.results) {
      throw new ApiException("Unable to create user session");
    }

    return {
      success: true,
      result: {
        session: {
          token: session.results.token,
          expires_at: session.results.expires_at,
        },
      },
    };
  }
}

/**
 * Read the bearer token from a request.
 */
export function getBearer(request: Request): string | null {
  const authHeader = request.headers.get("Authorization");

  if (!authHeader || !/^Bearer\s+/i.test(authHeader)) {
    return null;
  }

  return authHeader.replace(/^Bearer\s+/i, "").trim();
}

/**
 * Require a valid session for protected API routes.
 */
export async function authenticateUser(
  c: AppContext,
  next: Next
) {
  const token = getBearer(c.req.raw);

  if (!token) {
    return Response.json(
      {
        success: false,
        error: "Authorization token is missing.",
      },
      { status: 401 }
    );
  }

  const qb = new D1QB(c.env.AUTH_DB);

  const session = await qb
    .fetchOne<UserSession>({
      tableName: "users_sessions",
      fields: "*",
      where: {
        conditions: ["token = ?1", "expires_at > ?2"],
        params: [token, Date.now()],
      },
    })
    .execute();

  if (!session.results) {
    return Response.json(
      {
        success: false,
        error: "Your session is invalid or has expired.",
      },
      { status: 401 }
    );
  }

  c.set("user_id", session.results.user_id);
  await next();
  }
