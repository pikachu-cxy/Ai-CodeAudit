import {
  Bot,
  Cpu,
  FolderOpen,
  LayoutDashboard,
  ListTodo,
  MessageSquare,
  Plug,
  Puzzle,
  Settings,
  Users,
  type LucideIcon,
} from "lucide-react";

/**
 * Single source of truth for global navigation.
 *
 * Adding a future module (vulnerability center, asset inventory, audit policy,
 * runtime security) should only require registering a new item + route here.
 */
export type NavGroupId = "workspace" | "platform";

export interface NavGroup {
  id: NavGroupId;
  label: string;
  order: number;
}

export interface NavItem {
  key: string;
  label: string;
  icon: LucideIcon;
  route: string;
  group: NavGroupId;
  order: number;
  /** Optional feature flag. A flag only hides the entry, it never grants access. */
  featureFlag?: string;
  /** Reserved for future RBAC. Backend must still authorize every API call. */
  requiredPermission?: string;
  /** `skeleton` = UI only, `config-only` = real CRUD but no executor wired. */
  maturity: "ready" | "config-only" | "skeleton";
  description: string;
}

export const NAV_GROUPS: NavGroup[] = [
  { id: "workspace", label: "工作空间", order: 1 },
  { id: "platform", label: "平台配置", order: 2 },
];

export const NAV_ITEMS: NavItem[] = [
  {
    key: "dashboard",
    label: "仪表盘",
    icon: LayoutDashboard,
    route: "/dashboard",
    group: "workspace",
    order: 1,
    maturity: "ready",
    description: "全局审计态势与快捷入口",
  },
  {
    key: "chat",
    label: "对话",
    icon: MessageSquare,
    route: "/chat",
    group: "workspace",
    order: 2,
    maturity: "ready",
    description: "基于扫描上下文的审计对话工作台",
  },
  {
    key: "projects",
    label: "项目",
    icon: FolderOpen,
    route: "/projects",
    group: "workspace",
    order: 3,
    maturity: "ready",
    description: "审计项目、扫描版本与报告",
  },
  {
    key: "tasks",
    label: "任务",
    icon: ListTodo,
    route: "/tasks",
    group: "workspace",
    order: 4,
    maturity: "ready",
    description: "扫描任务执行状态与详情",
  },
  {
    key: "agents",
    label: "Agent 配置",
    icon: Bot,
    route: "/agents",
    group: "platform",
    order: 1,
    featureFlag: "agents",
    requiredPermission: "settings:read",
    maturity: "config-only",
    description: "Agent 角色定义、模型绑定与执行预算（仅配置，未接调度器）",
  },
  {
    key: "skills",
    label: "Skill 管理",
    icon: Puzzle,
    route: "/skills",
    group: "platform",
    order: 2,
    featureFlag: "skills",
    requiredPermission: "settings:read",
    maturity: "ready",
    description: "审计技能包与来源管理",
  },
  {
    key: "mcp",
    label: "MCP 管理",
    icon: Plug,
    route: "/mcp",
    group: "platform",
    order: 3,
    featureFlag: "mcp",
    requiredPermission: "settings:read",
    maturity: "config-only",
    description: "MCP Server 注册与真实连接测试（未开放工具执行）",
  },
  {
    key: "llm",
    label: "LLM 设置",
    icon: Cpu,
    route: "/llm",
    group: "platform",
    order: 4,
    requiredPermission: "settings:read",
    maturity: "ready",
    description: "模型、API 连接与审计参数",
  },
  {
    key: "system",
    label: "系统管理",
    icon: Settings,
    route: "/system",
    group: "platform",
    order: 5,
    requiredPermission: "settings:read",
    maturity: "ready",
    description: "扫描器、集成、存储与评分规则",
  },
  {
    key: "accounts",
    label: "账户管理",
    icon: Users,
    route: "/accounts",
    group: "platform",
    order: 6,
    requiredPermission: "admin",
    maturity: "config-only",
    description: "认证状态、刷新会话、管理员密码与操作留痕",
  },
];

export interface NavVisibilityOptions {
  /** Undefined flag = visible. Only an explicit `false` hides an entry. */
  flags?: Record<string, boolean>;
  /** Reserved for UI presentation only. Never a substitute for backend authz. */
  permissions?: readonly string[];
}

export function visibleNavItems(options: NavVisibilityOptions = {}): NavItem[] {
  const { flags, permissions } = options;
  return NAV_ITEMS.filter((item) => {
    if (item.featureFlag && flags?.[item.featureFlag] === false) return false;
    if (
      item.requiredPermission &&
      permissions &&
      !permissions.includes(item.requiredPermission) &&
      !permissions.includes("admin")
    ) {
      return false;
    }
    return true;
  }).sort((a, b) => a.order - b.order);
}

/** Match a pathname to a nav item, including nested detail routes. */
export function navItemForPath(pathname: string): NavItem | undefined {
  const segments = pathname.split("/").filter(Boolean);
  const root = segments[0] || "dashboard";
  return NAV_ITEMS.find((item) => item.route === `/${root}`);
}
