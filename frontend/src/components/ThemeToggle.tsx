import { Moon, Sun } from "lucide-react";
import { useTheme } from "../ThemeContext";

interface Props {
  className?: string;
}

export function ThemeToggle({ className = "" }: Props) {
  const { mode, resolved, label, cycle } = useTheme();

  return (
    <button
      type="button"
      className={`theme-toggle ${className}`}
      onClick={cycle}
      title={label}
      aria-label={label}
    >
      {mode === "system" ? (
        <span className="theme-toggle-dual" aria-hidden>
          <Sun className={`w-4 h-4 ${resolved === "light" ? "opacity-100" : "opacity-35"}`} />
          <Moon className={`w-4 h-4 ${resolved === "dark" ? "opacity-100" : "opacity-35"}`} />
        </span>
      ) : resolved === "light" ? (
        <Sun className="w-4 h-4" />
      ) : (
        <Moon className="w-4 h-4" />
      )}
    </button>
  );
}
