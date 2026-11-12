import { ArrowLeft } from "lucide-react";
import { api } from "../../api";
import { navigate } from "../../app/router";
import type { PageContext } from "../../app/pageTypes";
import { NewScanPanel } from "../../components/NewScanPanel";
import { PageHeader } from "../../shared/ui";

interface Props extends PageContext {
  appendProjectId: number | null;
}

export function NewProjectPage({ appendProjectId, onDataChanged }: Props) {
  const handleCreated = async (scanId: number) => {
    // NewScanPanel only returns the scan id; resolve the owning project from
    // the real scan record instead of guessing.
    let projectId = appendProjectId;
    if (!projectId) {
      try {
        const scan = await api.getScan(scanId);
        projectId = scan.project_id ?? null;
      } catch {
        projectId = null;
      }
    }
    onDataChanged();
    navigate(projectId ? `/projects/${projectId}?scan=${scanId}` : `/tasks/${scanId}`);
  };

  return (
    <div className="page-container space-y-4">
      <button
        type="button"
        className="btn-ghost text-sm inline-flex items-center gap-1.5 -ml-2"
        onClick={() => navigate("/projects")}
      >
        <ArrowLeft className="h-4 w-4" /> 返回项目列表
      </button>
      <PageHeader
        eyebrow="Workspace / Projects"
        title={appendProjectId ? "追加扫描版本" : "新建审计项目"}
        description={
          appendProjectId
            ? `在项目 #${appendProjectId} 下创建新一轮扫描（上传新包或拉取 GitLab）。`
            : "上传 ZIP 代码包或接入 GitLab 仓库，创建后自动进入扫描详情。"
        }
      />
      <div className="max-w-3xl">
        <NewScanPanel projectId={appendProjectId} onCreated={(id) => void handleCreated(id)} />
      </div>
    </div>
  );
}
