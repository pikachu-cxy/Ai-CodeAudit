import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  applyTheme,
  cycleThemeMode,
  getStoredThemeMode,
  persistThemeMode,
  resolveTheme,
  themeModeLabel,
  type ThemeMode,
} from "./theme";

interface ThemeContextValue {
  mode: ThemeMode;
  resolved: "light" | "dark";
  label: string;
  cycle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<ThemeMode>(() => getStoredThemeMode());
  const [resolved, setResolved] = useState<"light" | "dark">(() => resolveTheme(getStoredThemeMode()));

  const sync = useCallback((next: ThemeMode) => {
    const effective = applyTheme(next);
    setResolved(effective);
    persistThemeMode(next);
  }, []);

  useEffect(() => {
    sync(mode);
  }, [mode, sync]);

  useEffect(() => {
    if (mode !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => sync("system");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [mode, sync]);

  const cycle = useCallback(() => {
    setMode((current) => cycleThemeMode(current));
  }, []);

  const value = useMemo(
    () => ({
      mode,
      resolved,
      label: themeModeLabel(mode, resolved),
      cycle,
    }),
    [mode, resolved, cycle],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used within ThemeProvider");
  }
  return ctx;
}
