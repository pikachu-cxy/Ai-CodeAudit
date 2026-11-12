# SQL 版本化迁移

本地开发与生产使用**不同数据库**（如 `ai_audit_dev` / `ai_audit_prod`），schema 变更通过本目录下的编号 SQL 同步到生产。

## 目录结构

```text
migrations/
  mysql/     # 生产 MySQL 语法
  sqlite/    # 本地 SQLite 语法（有差异时单独维护）
```

文件命名：`NNN_简短描述.sql`（如 `003_add_foo_index.sql`）。**已发布的 SQL 文件禁止修改**，只能追加新编号。

## 当前版本

| 版本 | 说明 |
|------|------|
| `001_baseline` | 基线标记；表结构由 SQLAlchemy `create_all` 从 `app/models.py` 创建 |
| `002_normalize_source_url` | GitLab `source_url` 索引；历史 URL 归一化由 Python hook 执行 |
| `003_unique_project_name` | 项目名全局唯一；重复名改为 `原名 (id)` 后加唯一索引 |
| `004_notify_emails_suppressions` | 扫描报告收件人 `notify_emails_json`；项目级误报抑制库 `project_suppressions` |

查看已应用版本：

```sql
SELECT version, applied_at FROM schema_migrations ORDER BY version;
```

## 开发流程

1. 改模型或需要 DDL/DML → 新增 `migrations/mysql/00N_xxx.sql`（SQLite 若语法不同则同步写 `sqlite/`）
2. 本地启动 backend 或运行 `python -m app.migrate` 验证
3. PR / 发版说明写明：**本次 migrations: 00N**
4. 生产：先执行 migrate，再滚动发布镜像

## 生产发版 Checklist

1. 合并代码（含新 SQL 文件）
2. 确认生产库名（如 `ai_audit_prod`），**勿用本地 dev 库**
3. 执行迁移（二选一）：
   - 发布 Job / 运维：`python -m app.migrate`（读取 K8s Secret / `.env` 中的 MySQL 配置）
   - 或手动：`mysql -h ... -u ... ai_audit_prod < migrations/mysql/00N_xxx.sql`（仅当未走 runner 时）
4. 滚动更新 backend Pod
5. 验收：`/api/health`、项目列表、Jenkins webhook 同 URL 合并

## 环境变量示例

**本地**（`.env`）：

```env
DATABASE_BACKEND=sqlite
# 或联调 MySQL：
# DATABASE_BACKEND=mysql
# MYSQL_HOST=127.0.0.1
# MYSQL_DATABASE=ai_audit_dev
```

**生产**（K8s Secret，库名示例 `ai_audit_prod`）：

```env
DATABASE_BACKEND=mysql
MYSQL_HOST=db.example.com
MYSQL_PORT=3306
MYSQL_USER=ai_audit
MYSQL_PASSWORD=***
MYSQL_DATABASE=ai_audit_prod
```

修改数据库连接后需**重启 backend** 生效；`repos/`、`uploads/` 仍建议使用 PVC，不存入 MySQL。
