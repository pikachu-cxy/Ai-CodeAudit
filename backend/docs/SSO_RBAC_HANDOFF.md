> **公开示例文档**：本文中的域名、姓名、邮箱与响应样例均为占位符，
> 不代表任何真实系统、员工或客户信息。

# SSO 角色对接说明（审计平台 RBAC）

**读者**：SSO 后端 / 运维  
**目的**：让审计平台能从 SSO 识别管理员与普通用户  
**结论**：当前 `/oauth/userinfo` **未返回角色**，审计平台只能把所有 SSO 用户当作普通用户。请 SSO 侧按本文改造后，双方重新登录验收即可。

---

## 1. 背景与现状

### 1.1 审计平台如何取角色

登录链路不变：

```text
/oauth/authorize → /oauth/token → /oauth/userinfo → 审计平台签发本地 JWT（含 role）
```

- 角色**只**从 `GET /oauth/userinfo` 读取，不会用「用户名是否叫 admin」判断。
- 本地密码登录（应急账号）在审计平台侧恒为管理员，与 SSO 无关。
- 管理员可访问审计平台「系统设置」及全部 `/api/settings*`；项目/扫描等业务接口管理员与普通用户均可访问。

### 1.2 联调实测（问题所在）

对 `https://sso.example.com` 使用 OAuth access_token 调用 userinfo，**实际响应**为：

```json
{
  "sub": "16",
  "name": "示例用户",
  "email": "user@example.com",
  "avatar": "https://...",
  "feishu_id": "ou_..."
}
```

管理员测试账号同理，例如：

```json
{
  "sub": "1",
  "name": null,
  "email": "admin@example.com",
  "avatar": null,
  "feishu_id": null
}
```

以上均**无** `role` / `roles`。因此审计平台落库/签发的角色一律为 `user`。

### 1.3 SSO 侧已有能力（未打通到 OAuth）

SSO 管理端用户列表已有「角色」列（`admin` / `user`），管理 API 为：

- `GET/PUT /api/v1/admin/users`（字段含 `role`）

个人中心等页面通过 **SSO 会话 JWT** 调用 `/api/v1/auth/me` 可读到 `role`。

但 **OAuth 颁发给第三方应用的 opaque access_token**：

- 可以调用 `/oauth/userinfo`（当前无角色）
- **不能**调用 `/api/v1/auth/me`、`/api/v1/admin/users`（返回 `Invalid token`）

因此审计平台作为 OAuth Client，**唯一可靠的角色来源就是把用户表中的 `role` 写入 `/oauth/userinfo`**。

---

## 2. SSO 必须修改什么

### 2.1 改哪个接口

`GET {SSO_BASE_URL}/oauth/userinfo`  
`Authorization: Bearer <oauth_access_token>`

在现有字段基础上，**增加角色信息**。推荐字段：

```json
"roles": ["user", "admin"]
```

或单角色用户：

```json
"roles": ["user"]
```

也可用单字段 `"role": "admin"`（审计平台同样支持，见第 5 节）。

### 2.2 角色取值约定

| 取值 | 含义（审计平台） |
|------|------------------|
| `admin` | 管理员（可进系统设置） |
| `user` | 普通用户 |

规则：

- 与 SSO 管理后台「角色」列保持一致。
- 若一人多角色（如同时有 `user`、`admin`）：**只要集合中含 `admin` 即视为管理员**。
- 大小写不敏感（`Admin` / `ADMIN` 均可）。
- **不要**只返回中文「管理员」「普通用户」；请用英文码 `admin` / `user`。

### 2.3 改造要点（SSO 后端）

1. 在处理 `/oauth/userinfo` 时，根据 access_token 对应用户，读取用户表（或等价存储）中的 `role` 字段。
2. 写入响应：
   - 推荐：`roles: [role]`；若业务上支持多角色，返回完整数组。
   - 或：`role: "<单个角色>"`。
3. **不要**依赖审计平台改 `client_id` / `redirect_uri` / 换票流程。
4. 当前审计平台 OAuth scope 为 `openid profile`。若你们用 scope 控制 claim，请保证在现有 scope 下即可返回角色，或告知审计平台需追加的 scope 名称。
5. 改造完成后，**用户需重新走一遍 SSO 登录**（或等 refresh 续期并重新拉 userinfo）后，审计平台才会拿到新角色。

无需为审计平台单独开管理 API；也无需让 OAuth token 能访问 `/api/v1/auth/me`（可选优化，非必须）。

---

## 3. 改造前后对比

### 改造前（现状）

```json
{
  "sub": "16",
  "name": "示例用户",
  "email": "user@example.com",
  "avatar": "...",
  "feishu_id": "..."
}
```

审计平台行为：`role = user`（无系统设置权限）。

### 改造后（期望，管理员）

```json
{
  "sub": "16",
  "name": "示例用户",
  "email": "user@example.com",
  "avatar": "...",
  "feishu_id": "...",
  "roles": ["user", "admin"]
}
```

或：

```json
{
  "sub": "16",
  "name": "示例用户",
  "email": "user@example.com",
  "avatar": "...",
  "feishu_id": "...",
  "role": "admin"
}
```

审计平台行为：`role = admin`（可见「系统设置」）。

### 改造后（期望，普通用户）

```json
{
  "sub": "100",
  "name": "示例用户",
  "email": "zhang@example.com",
  "roles": ["user"]
}
```

审计平台行为：`role = user`（无「系统设置」；业务接口仍可用）。

---

## 4. 验收清单

| # | 步骤 | 期望 |
|---|------|------|
| 1 | 用管理员账号走 OAuth，抓 `GET /oauth/userinfo` | JSON 含 `roles`/`role`，且含 `admin` |
| 2 | 用仅 `user` 账号走 OAuth，抓 userinfo | 有角色字段且**不含** `admin`（或仅为 `user`） |
| 3 | 管理员登录审计平台 | 侧栏有「系统设置」；`GET /api/settings` → **200** |
| 4 | 普通用户登录审计平台 | 侧栏**无**「系统设置」；`GET /api/settings` → **403** |
| 5 | 两类用户访问 `GET /api/scans/{id}/stats`（有效 Bearer） | 均 **200** |
| 6 | 在 SSO 后台把用户角色从 user 改为 admin 后重新登录 | 审计平台权限随之变为管理员 |

自测示例（SSO 侧）：

```http
GET /oauth/userinfo HTTP/1.1
Host: sso.example.com
Authorization: Bearer <oauth_access_token>
```

---

## 5. 审计平台已兼容的字段形态

改完后请尽量用 **`roles: string[]`**。以下形态审计平台均可识别：

- `"roles": ["admin", "user"]`
- `"role": "admin"`
- `"role": "user,admin"`（逗号 / 分号分隔）
- `"roles": [{"name": "admin"}, {"name": "user"}]`（对象取 `name` / `code` / `role`）
- `"authorities"` / `"groups"`：同上解析规则

若最终字段名无法做成上述任一形式，请把 **真实 userinfo 样例 JSON** 回传审计平台，以便补映射。

---

## 6. 排错说明

- userinfo **没有任何可识别角色字段** → 审计平台按普通用户处理。
- OAuth token 调不通 `/api/v1/auth/me` **不影响**对接：只需 userinfo 带角色。
- 改角色后仍像普通用户：请确认已**重新 SSO 登录**，并再次抓包确认 userinfo 已含新角色。

---

## 7. 联系

改造完成或字段需定制时，请提供：

1. 改造后的 userinfo 样例（admin / user 各一份）  
2. 若调整了 scope，说明新的 scope 字符串  

文档版本：基于 `sso.example.com` 联调实测整理；SSO 改完后审计平台无需发版即可识别（用户重新登录即可）。
