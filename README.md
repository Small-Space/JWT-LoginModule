# JWT 认证技术库（FastAPI）

> 从 `fastapi-management-system` 项目剥离、重构而成的**通用 JWT 认证组件**。
> 与业务解耦：不依赖任何 ORM / 用户模型 / 数据库，可直接嵌入任意 FastAPI 项目。

---

## 一、技术栈

| 能力 | 库 | 说明 |
|------|-----|------|
| Web 框架 | FastAPI | 依赖注入、路由 |
| JWT | python-jose | 令牌签发 / 校验（HS256） |
| 密码哈希 | passlib + bcrypt | 替代原项目的明文存储 |
| 数据校验 | Pydantic v2 | 请求 / 响应模型 |
| 测试 | pytest + httpx | TestClient 单元测试 + 真实服务冒烟 |

## 二、目录结构

```
jwt_auth_lib/
├── jwt_auth/                  # 技术库核心包
│   ├── config.py              # JWTSettings：密钥 / 算法 / 有效期 / Cookie 参数（支持环境变量覆盖）
│   ├── security.py            # 令牌创建 / 解码 / 类型校验 + 密码哈希
│   ├── deps.py                # FastAPI 认证依赖：Header + Cookie 双通道提取、当前用户注入
│   ├── router.py              # 内置路由工厂：/login /logout /me /refresh
│   ├── schemas.py             # LoginRequest / TokenResponse / RefreshRequest / TokenPayload
│   └── __init__.py            # 统一出口
├── examples/
│   └── demo_main.py           # 可运行示例（内存用户，无数据库依赖）
├── scripts/
│   └── smoke_test.py          # 真实服务冒烟测试脚本
├── tests/                     # pytest 单元测试（28 个用例）
│   ├── test_security.py
│   ├── test_deps.py
│   └── test_router.py
├── requirements.txt           # 依赖清单
└── pyproject.toml             # 包元数据 / 可 pip install -e
```

## 三、核心设计（对应原始项目）

| 原始项目 | 本技术库 | 说明 |
|---------|---------|------|
| `auth/services.py` 的 `SECRET_KEY / ALGORITHM / create_token` | `security.py` + `config.py` | 令牌逻辑独立，配置集中化 |
| `auth/routers.py` 的 `oauth2_scheme` | `deps.py` 闭包工厂 | 可配置 tokenUrl |
| `auth/routers.py` 的 `protected_route` | `deps.get_current_identity` | 同一套校验逻辑，返回类型化载荷 |
| 登录成功写 HttpOnly Cookie | `router.py` 保留并参数化 | `cookie_*` 全部走配置 |
| 密码**明文**存储 | `security.hash_password / verify_password` | **修复项**：默认启用 bcrypt |

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

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/auth/login` | 校验用户名密码，签发 access + refresh 令牌，写 HttpOnly Cookie |
| POST | `/auth/logout` | 清除 Cookie |
| GET | `/auth/me` | 受保护示例：返回当前用户名 |
| POST | `/auth/refresh` | 用 refresh 令牌换取新 access 令牌 |

## 六、配置项（JWTSettings）

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `secret_key` | 自动生成 / 环境变量 `JWT_SECRET_KEY` | 生产必须固定 |
| `algorithm` | `HS256` | 签名算法 |
| `access_token_expire_minutes` | `60` | 访问令牌有效期 |
| `refresh_token_expire_days` | `7` | 刷新令牌有效期 |
| `cookie_key` | `access_token` | Cookie 名 |
| `cookie_httponly` | `True` | 防 XSS 窃取 |
| `cookie_secure` | `False` | 生产 HTTPS 环境置 `True` |
| `cookie_samesite` | `lax` | CSRF 防护 |

## 七、运行与验证

```bash
# 1. 创建虚拟环境并安装依赖
py -3.12 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt

# 2. 单元测试（28 个用例）
.\.venv\Scripts\python -m pytest -v

# 3. 运行示例服务（内存用户，打开 http://127.0.0.1:8000/docs 交互调试）
.\.venv\Scripts\python examples\demo_main.py

# 4. 真实服务冒烟（示例服务运行中执行）
.\.venv\Scripts\python scripts\smoke_test.py http://127.0.0.1:8000
```

**当前验证状态**：28/28 单元测试通过；真实 HTTP 冒烟 11/11 通过
（注册 → 错误密码 401 → 登录 → Header/Cookie 双通道 → 无令牌 401 → 刷新 → 登出）。

## 八、与原始项目的差异与增强

1. **密码哈希**：原项目 `db_user.pwd != user.password` 为明文比较，本库默认 `bcrypt` 哈希存储。
2. **刷新令牌**：新增 refresh token 与 `/auth/refresh` 端点（原项目无）。
3. **类型化载荷**：原 `protected_route` 返回 `{"username": ...}`，本库返回 `TokenPayload`，并拒绝把 refresh 令牌当 access 使用。
4. **完全解耦**：原代码 `from OrmSystem.templates.models import Users, Villagers` 等业务依赖全部移除。
5. **配置可调**：密钥 / 有效期 / Cookie 行为集中为 `JWTSettings`，支持环境变量注入。

## 九、迁移回原项目的映射（如需要回写）

- 原 `auth/services.py` → 本库 `jwt_auth/security.py`（`create_token(data, expires_delta)` 仍可直接调用，签名兼容）
- 原 `auth/routers.py` 的 `protected_route` → `auth_deps.get_current_identity`
- 原登录路由的 Cookie 行为 → `create_auth_router` 默认行为一致（key=`access_token`）
- 原项目若继续使用，可将 `auth/` 模块整体替换为对本库的薄封装 + 业务查询函数。
