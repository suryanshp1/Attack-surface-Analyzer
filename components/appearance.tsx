"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { Monitor, Moon, Sun } from "lucide-react";

type Appearance = "light" | "dark" | "system";
const storageKey = "surfacer.appearance";
const valid = (value: unknown): Appearance =>
  value === "light" || value === "dark" ? value : "system";
const AppearanceContext = createContext<{
  mode: Appearance;
  setMode: (mode: Appearance) => void;
  notice: string;
}>({ mode: "system", setMode: () => {}, notice: "" });

function apply(mode: Appearance) {
  const root = document.documentElement;
  root.dataset.appearance = mode;
  root.dataset.theme =
    mode === "system"
      ? window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
      : mode;
}
export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<Appearance>("system");
  const [notice, setNotice] = useState("");
  useEffect(() => {
    const initial = valid(document.documentElement.dataset.appearance);
    setModeState(initial);
    apply(initial);
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const systemChanged = () => {
      if (document.documentElement.dataset.appearance === "system")
        apply("system");
    };
    const stored = (event: StorageEvent) => {
      if (event.key === storageKey || event.key === null) {
        const value = valid(event.newValue);
        setModeState(value);
        apply(value);
        setNotice("");
      }
    };
    media.addEventListener("change", systemChanged);
    window.addEventListener("storage", stored);
    return () => {
      media.removeEventListener("change", systemChanged);
      window.removeEventListener("storage", stored);
    };
  }, []);
  function setMode(next: Appearance) {
    setModeState(next);
    apply(next);
    setNotice("");
    try {
      localStorage.setItem(storageKey, next);
    } catch {
      setNotice(
        "Applied for this tab. Your browser could not save the preference.",
      );
    }
  }
  return (
    <AppearanceContext.Provider value={{ mode, setMode, notice }}>
      {children}
    </AppearanceContext.Provider>
  );
}
export function AppearanceControl({ compact = false }: { compact?: boolean }) {
  const { mode, setMode, notice } = useContext(AppearanceContext);
  const Icon = mode === "system" ? Monitor : mode === "dark" ? Moon : Sun;
  return (
    <div className={`appearance ${compact ? "appearance-compact" : ""}`}>
      <label className="appearance-control">
        <Icon size={16} aria-hidden="true" />
        <span className={compact ? "sr-only" : ""}>Appearance</span>
        <select
          aria-label={compact ? "Appearance" : "Appearance preference"}
          value={mode}
          onChange={(event) => setMode(valid(event.target.value))}
        >
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </label>
      {notice && (
        <p className="appearance-notice" role="status">
          {notice}
        </p>
      )}
    </div>
  );
}
