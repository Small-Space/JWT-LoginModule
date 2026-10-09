# JWT 认证技术库（FastAPI）

> 从 `fastapi-management-system` 项目剥离、重构而成的**通用 JWT 认证组件**。
> 与业务解耦：不依赖任何 ORM / 用户模型 / 数据库，可直接嵌入任意 FastAPI 项目。
> 
> **当前版本：v1.2.0**（生产写法：refresh 令牌仅通过 HttpOnly Cookie 交付，不进响应体）

---

## 一、技术栈

| 能力     | 库                | 说明                       |
| ------ | ---------------- | ------------------------ |
| Web 框架 | FastAPI          | 依赖注入、路由                  |
| JWT    | python-jose      | 令牌签发 / 校验（HS256）         |
| 密码哈希   | passlib + bcrypt | 替代原项目的明文存储               |
| 数据校验   | Pydantic v2      | 请求 / 响应模型                |
| 测试     | pytest + httpx   | TestClient 单元测试 + 真实服务冒烟 |

## 二、目录结构

```
jwt_auth_lib/
├── jwt_auth/                  # 技术库核心包
│   ├── config.py              # JWTSettings：密钥 / 算法 / 有效期 / Cookie 参数（支持环境变量覆盖）
│   ├── security.py            # 令牌创建 / 解码 / 类型校验 + 密码哈希 + 密码重置令牌
│   ├── deps.py                # FastAPI 认证依赖：Header + Cookie 双通道提取、当前用户注入
│   ├── router.py              # 内置路由工厂：/login /logout /me /refresh
│   ├── schemas.py             # LoginRequest / TokenResponse / RefreshRequest / TokenPayload
│   └── __init__.py            # 统一出口
├── examples/
│   └── demo_main.py           # 可运行示例（内存用户，无数据库依赖）
├── scripts/
│   └── smoke_test.py          # 真实服务冒烟测试脚本
├── tests/                     # pytest 单元测试（32 个用例）
│   ├── conftest.py            # 路径注入（jwt_auth 包实体位于项目根）
│   ├── test_security.py
│   ├── test_deps.py
│   └── test_router.py
├── requirements.txt           # 依赖清单
└── pyproject.toml             # 包元数据 / 可 pip install -e
```

## 三、核心设计（对应原始项目）

| 原始项目                                                         | 本技术库                                       | 说明                  |
| ------------------------------------------------------------ | ------------------------------------------ | ------------------- |
| `auth/services.py` 的 `SECRET_KEY / ALGORITHM / create_token` | `security.py` + `config.py`                | 令牌逻辑独立，配置集中化        |
| `auth/routers.py` 的 `oauth2_scheme`                          | `deps.py` 闭包工厂                             | 可配置 tokenUrl        |
| `auth/routers.py` 的 `protected_route`                        | `deps.get_current_identity`                | 同一套校验逻辑，返回类型化载荷     |
| 登录成功写 HttpOnly Cookie                                        | `router.py` 保留并参数化                         | `cookie_*` 全部走配置    |
| 密码**明文**存储                                                   | `security.hash_password / verify_password` | **修复项**：默认启用 bcrypt |

**解耦关键点**：本库不 import 任何业务模型。业务侧只需要注入两个函数：

- `authenticate(username, password) -> 用户 | None`（登录用）
- `get_user(sub) -> 用户 | None`（受保护接口取用户用）

同步 / 异步实现均兼容（内部 `inspect.isawaitable` 自动处理）。

## 四、接入指南（三步）

### 1. 安装 / 引入

```bash
# 方式 A：直接把 jwt_auth/ 目录拷进项目（零依赖安装）
# 方式 B：本目录内 pip install -e . （可编辑安装）
pip install -r requirements.txt
```

### 2. 组装认证

```python
from jwt_auth import JWTSettings, create_auth_deps, create_auth_router, hash_password, verify_password

# 生产：密钥用环境变量注入（JWTSettings 默认读 JWT_SECRET_KEY）
settings = JWTSettings(secret_key="your-strong-secret")
auth_deps = create_auth_deps(settings=settings)          # tokenUrl 默认 /auth/login

# 业务实现：登录认证函数（查库 + 校验密码，可以是 async 或 sync）
async def authenticate(username: str, password: str):
    user = await your_db.get_user(username)
    if user and verify_password(password, user.pwd_hash):
        return user
    return None

app.include_router(create_auth_router(authenticate, auth_deps))
```

### 3. 保护业务接口（两种粒度）

```python
from fastapi import Depends

# 只校验身份（等价原项目 /protected）
@app.get("/orders")
async def orders(identity=Depends(auth_deps.get_current_identity)):
    return {"current_user": identity.sub}

# 校验并注入完整用户对象（业务查询函数注入）
@app.get("/profile")
async def profile(user=Depends(auth_deps.get_current_user(your_db.get_user))):
    return user
```

> 令牌传递支持双通道：`Authorization: Bearer <token>` 优先，缺失时自动回退读取
> HttpOnly Cookie（默认 key：`access_token`，与原始项目前端兼容）。

## 五、内置接口

| 方法   | 路径              | 说明                                                                         |
| ---- | --------------- | -------------------------------------------------------------------------- |
| POST | `/auth/login`   | 校验用户名密码，签发 access + refresh 令牌，**均写入 HttpOnly Cookie**；响应体只返回 access_token |
| POST | `/auth/logout`  | 清除 access + refresh 两个 Cookie                                              |
| GET  | `/auth/me`      | 受保护示例：返回当前用户名                                                              |
| POST | `/auth/refresh` | 用 refresh 令牌换取新 access 令牌；**优先读 Cookie，body 仅兜底**（见"生产写法"）                 |

## 六、配置项（JWTSettings）

| 字段                            | 默认值                          | 说明                       |
| ----------------------------- | ---------------------------- | ------------------------ |
| `secret_key`                  | 自动生成 / 环境变量 `JWT_SECRET_KEY` | 生产必须固定                   |
| `algorithm`                   | `HS256`                      | 签名算法                     |
| `access_token_expire_minutes` | `60`                         | 访问令牌有效期                  |
| `refresh_token_expire_days`   | `7`                          | 刷新令牌有效期                  |
| `cookie_key`                  | `access_token`               | Cookie 名（访问令牌）           |
| `refresh_cookie_key`          | `refresh_token`              | Cookie 名（刷新令牌，v1.2.0 新增） |
| `cookie_httponly`             | `True`                       | 防 XSS 窃取                 |
| `cookie_secure`               | `False`                      | 生产 HTTPS 环境置 `True`      |
| `cookie_samesite`             | `lax`                        | CSRF 防护                  |

## 七、生产写法（v1.2.0 升级要点）

**refresh 令牌只走 HttpOnly Cookie，永远不进响应体**（JS 不可读，防 XSS 窃取）：

```
登录成功：
  Set-Cookie: access_token=...; HttpOnly
  Set-Cookie: refresh_token=...; HttpOnly      ← 新增
  响应体：{ access_token, token_type, expires_in }   ← 不含 refresh_token

access 过期后：
  POST /auth/refresh   ← 无需 body！浏览器自动携带 refresh_token Cookie
  响应体：{ 新的 access_token, ... }

登出：
  清除 access_token + refresh_token 两个 Cookie
```

**前端适配要点：**

1. 跨域请求必须带 `withCredentials: true`（同源部署可省略），否则 Cookie 不会上传；
2. 前端只管 access_token（响应体或 Cookie 双通道均可）；refresh_token 由浏览器自动管理；
3. 401 拦截器：收到 401 → 自动调 `/auth/refresh`（无 body）→ 换新 access_token → 重放原请求；刷新也失败则跳登录页；
4. `/auth/refresh` 的 body 字段（`refresh_token`）保留为**非浏览器客户端兜底**（如移动 App 自行保存 refresh_token 后传入）。

**上线前必改配置：**

- 环境变量 `JWT_SECRET_KEY` 设为固定强密钥（否则每次重启随机生成，所有已签发令牌失效）；
- `cookie_secure=True`（HTTPS 部署必需）。

## 八、运行与验证

```bash
# 1. 创建虚拟环境并安装依赖
py -3.12 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt

# 2. 单元测试（32 个用例）
.\.venv\Scripts\python -m pytest -v

# 3. 运行示例服务（内存用户，打开 http://127.0.0.1:8000/docs 交互调试）
.\.venv\Scripts\python examples\demo_main.py

# 4. 真实服务冒烟（示例服务运行中执行）
.\.venv\Scripts\python scripts\smoke_test.py http://127.0.0.1:8000
```

**当前验证状态**：32/32 单元测试通过（含 refresh Cookie 优先逻辑、access 冒充 refresh 拒绝）；admin 业务模块全流程 17/17 通过；真实服务链路（登录 → Cookie 刷新 → 新 token 访问）验证通过。

## 九、版本记录

- **v1.0.0**：技术库剥离，bcrypt 哈希、双通道鉴权、refresh token 机制、密码重置令牌。
- **v1.1.0**：密码重置令牌（`create_password_reset_token` / `verify_password_reset_token`，type=`reset`，15 分钟有效）。
- **v1.2.0（当前）**：**生产写法**——refresh 令牌仅 HttpOnly Cookie 交付（响应体不再返回）；`/refresh` 优先读 Cookie（body 兜底）；`/logout` 清除双 Cookie；新增 `refresh_cookie_key` 配置；`TokenResponse` 不再含 refresh_token。

## 十、与原始项目的差异与增强

1. **密码哈希**：原项目 `db_user.pwd != user.password` 为明文比较，本库默认 `bcrypt` 哈希存储。
2. **刷新令牌**：新增 refresh token 与 `/auth/refresh` 端点（原项目无）。
3. **类型化载荷**：原 `protected_route` 返回 `{"username": ...}`，本库返回 `TokenPayload`，并拒绝把 refresh 令牌当 access 使用。
4. **完全解耦**：原代码 `from OrmSystem.templates.models import Users, Villagers` 等业务依赖全部移除。
5. **配置可调**：密钥 / 有效期 / Cookie 行为集中为 `JWTSettings`，支持环境变量注入。
6. **密码重置令牌**（v1.1.0）：`create_password_reset_token` / `verify_password_reset_token`（type=`reset`，默认 15 分钟有效），送达通道（邮件/短信）由业务侧实现。
7. **生产级令牌交付**（v1.2.0）：refresh 令牌仅 HttpOnly Cookie 交付，防 XSS 窃取；前端无需管理 refresh 令牌。


