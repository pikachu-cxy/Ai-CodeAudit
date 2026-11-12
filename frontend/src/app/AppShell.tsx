import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { Sidebar } from "./Sidebar";
import { GlobalHeader } from "./GlobalHeader";
import { InspectorDrawer, type InspectorConfig } from "./InspectorDrawer";
import { usePersistentState } from "../shared/hooks/usePersistentState";
import { navigate, type Route } from "./router";

/* ------------------------------------------------------------------ *
 * Optional inspector registration. Pages opt in; nothing is global.
 * ------------------------------------------------------------------ */
const InspectorContext = createContext<((config: InspectorConfig | null) => void) | null>(null);

/** `config` must be memoized by the caller (useMemo) to avoid render loops. */
export function useInspector(config: InspectorConfig | null): void {
  const register = useContext(InspectorContext);
  useEffect(() => {
    if (!register) return;
    register(config);
    return () => register(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [register, config]);
}

interface Props {
  route: Route;
  username: string;
  isAdmin: boolean;
  onLogout: () => void;
  /** Legacy ScanDetailView owns its own scroll container. */
  contentScroll?: boolean;
  onRefresh: () => void;
  children: ReactNode;
}

export function AppShell({
  route,
  username,
  isAdmin,
  onLogout,
  contentScroll = true,
  onRefresh,
  children,
}: Props) {
  const [collapsed, setCollapsed] = usePersistentState<boolean>(
    "ai-audit.sidebar.collapsed",
    false,
  );
  const [inspector, setInspector] = useState<InspectorConfig | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(true);

  useEffect(() => {
    if (inspector) setInspectorOpen(true);
  }, [inspector]);

  return (
    <InspectorContext.Provider value={setInspector}>
      <div className="app-shell grid-bg flex h-screen overflow-hidden">
        <Sidebar
          currentPath={window.location.pathname}
          collapsed={collapsed}
          onToggleCollapsed={() => setCollapsed((value) => !value)}
          username={username}
          isAdmin={isAdmin}
          onLogout={onLogout}
          onNavigate={(path) => navigate(path)}
        />

        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          <GlobalHeader
            route={route}
            hasInspector={Boolean(inspector)}
            inspectorOpen={inspectorOpen}
            onToggleInspector={() => setInspectorOpen((value) => !value)}
            onRefresh={onRefresh}
          />
          <div className="flex min-h-0 min-w-0 flex-1">
            <main
              className={`min-h-0 min-w-0 flex-1 ${
                contentScroll ? "overflow-y-auto app-main-scroll" : "overflow-hidden"
              }`}
            >
              {children}
            </main>
            {inspector && (
              <InspectorDrawer
                config={inspector}
                open={inspectorOpen}
                onClose={() => setInspectorOpen(false)}
              />
            )}
          </div>
        </div>
      </div>
    </InspectorContext.Provider>
  );
}
