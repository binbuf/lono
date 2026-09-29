import { Api } from "./api";

const STORAGE_KEY = "lono.key";

type Status = "unknown" | "checking" | "valid" | "invalid";

export const auth = $state({
  key: (typeof localStorage !== "undefined" ? localStorage.getItem(STORAGE_KEY) : "") || "",
  status: "unknown" as Status,
  error: "",
});

export function saveKey(key: string): void {
  auth.key = key.trim();
  if (typeof localStorage !== "undefined") localStorage.setItem(STORAGE_KEY, auth.key);
  auth.status = "unknown";
  auth.error = "";
}

export function clearKey(): void {
  auth.key = "";
  if (typeof localStorage !== "undefined") localStorage.removeItem(STORAGE_KEY);
  auth.status = "invalid";
}

export async function validateKey(): Promise<boolean> {
  if (!auth.key) {
    auth.status = "invalid";
    return false;
  }
  auth.status = "checking";
  try {
    await new Api(auth.key).get("/audit/stats");
    auth.status = "valid";
    auth.error = "";
    return true;
  } catch (error) {
    auth.status = "invalid";
    auth.error = (error as Error).message;
    return false;
  }
}