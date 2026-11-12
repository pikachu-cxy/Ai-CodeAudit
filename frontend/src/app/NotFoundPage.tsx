import { ArrowLeft } from "lucide-react";
import { navigate } from "./router";
import { EmptyState, MonoMeta } from "../shared/ui";

export function NotFoundPage({ path }: { path: string }) {
  return (
    <div className="page-container space-y-4">
      <EmptyState
        title="页面不存在"
        description={`没有与 ${path} 对应的模块。可以从侧边栏重新选择功能，或返回仪表盘。`}
        action={
          <button type="button" className="btn-action inline-flex items-center gap-1.5" onClick={() => navigate("/dashboard")}>
            <ArrowLeft className="h-3.5 w-3.5" /> 返回仪表盘
          </button>
        }
      />
      <p className="text-center"><MonoMeta>旧版 ?view= 链接会自动跳转到对应的新路由</MonoMeta></p>
    </div>
  );
}
