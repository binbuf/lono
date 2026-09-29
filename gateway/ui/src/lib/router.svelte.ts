function parse(): string {
  if (typeof window === "undefined") return "overview";
  const raw = window.location.hash.replace(/^#\/?/, "");
  return raw || "overview";
}

export const router = $state({ path: parse() });

if (typeof window !== "undefined") {
  window.addEventListener("hashchange", () => {
    router.path = parse();
  });
}

export function go(path: string): void {
  if (typeof window === "undefined") return;
  if (window.location.hash === `#/${path}`) {
    router.path = path;
    return;
  }
  window.location.hash = `#/${path}`;
}

export function queryParam(name: string): string | null {
  const [, search] = router.path.split("?");
  if (!search) return null;
  return new URLSearchParams(search).get(name);
}

export function goQuery(path: string, params: Record<string, string>): void {
  const search = new URLSearchParams(params).toString();
  go(search ? `${path}?${search}` : path);
}