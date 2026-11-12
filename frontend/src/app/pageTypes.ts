export interface PageContext {
  /** Bumped after mutations so list pages reload real backend data. */
  refreshKey: number;
  onDataChanged: () => void;
  username: string;
  isAdmin: boolean;
  onLogout: () => void;
}
