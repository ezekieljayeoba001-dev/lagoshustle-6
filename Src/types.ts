
import { D1Database } from "@cloudflare/workers-types";
import { Context } from "hono";

export type Env = {
    AUTH_DB: D1Database;
    SALT_TOKEN: string;
};

export type Vars = {
    user_id?: string;
};

export type AppContext = Context<{
    Bindings: Env;
    Variables: Vars;
}>;

export type User = {
    id: string;
    email: string;
    password: string;
    name: string;
};

export type UserSession = {
    id: string;
    user_id: string;
    token: string;
    expires_at: number;
};
