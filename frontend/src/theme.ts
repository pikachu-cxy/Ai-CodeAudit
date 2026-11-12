export type ThemeMode = "system" | "light" | "dark";

const STORAGE_KEY = "audit-theme-mode";

export function getStoredThemeMode(): ThemeMode {
  const value = localStorage.getItem(STORAGE_KEY);
  if (value === "light" || value === "dark" || value === "system") {
    return value;
  }
  return "system";
}

export function getSystemTheme(): "light" | "dark" {
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function resolveTheme(mode: ThemeMode): "light" | "dark" {
  if (mode === "light") return "light";
  if (mode === "dark") return "dark";
  return getSystemTheme();
}

export function applyTheme(mode: ThemeMode): "light" | "dark" {
  const resolved = resolveTheme(mode);
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themeMode = mode;
  document.documentElement.style.colorScheme = resolved;
  return resolved;
}

export function persistThemeMode(mode: ThemeMode): void {
  localStorage.setItem(STORAGE_KEY, mode);
}

export function cycleThemeMode(current: ThemeMode): ThemeMode {
  const order: ThemeMode[] = ["system", "light", "dark"];
  const index = order.indexOf(current);
  return order[(index + 1) % order.length];
}

export function themeModeLabel(mode: ThemeMode, resolved: "light" | "dark"): string {
  if (mode === "system") {
    return `跟随系统（当前${resolved === "light" ? "浅色" : "深色"}）`;
  }
  return mode === "light" ? "浅色模式" : "深色模式";
}

/** Apply saved theme before React mounts to reduce flash. */
export function initTheme(): ThemeMode {
  const mode = getStoredThemeMode();
  applyTheme(mode);
  return mode;
}
