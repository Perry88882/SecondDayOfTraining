# SQL 注入漏洞测试与修复实验报告

> **实验环境**: Kali Linux / Python 3.13 / Flask + SQLite  
> **实验日期**: 2026-07-20  
> **测试目标**: http://127.0.0.1:5000  
> **代码仓库**: https://github.com/Perry88882/SecondDayOfTraining  
> **作者**: Perry Pu（蒲宇贤）

---

## 一、设计思路与架构

### 1.1 整体架构

在已有 V3.0 登录系统基础上（PBKDF2 哈希 + CSRF + Rate Limit + 安全响应头），新增两个功能模块：

```
┌─────────────────────────────────────────────────┐
│                   Flask 应用                     │
├─────────────────┬───────────────────────────────┤
│   登录模块 (不变) │   注册模块 (新增)              │
│   数据源: 内存字典 │   数据源: SQLite → data/users.db │
│   密码: PBKDF2   │   SQL: f-string 拼接 → 参数化   │
├─────────────────┼───────────────────────────────┤
│                 │   搜索模块 (新增)              │
│                 │   数据源: SQLite → data/users.db │
│                 │   SQL: f-string 拼接 → 参数化   │
│                 │   权限: 需登录 session            │
└─────────────────┴───────────────────────────────┘
```

### 1.2 数据存储设计

系统使用**双存储架构**，明确区分：

| 存储层 | 数据源 | 用途 | 密码方式 |
|--------|--------|------|---------|
| 内存 | Python dict `USERS` | 登录凭据（admin/alice） | PBKDF2 哈希 |
| SQLite | `data/users.db` | 注册 + 搜索 | 明文 → PBKDF2 哈希 |

### 1.3 数据库设计

```sql
CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email    TEXT,
    phone    TEXT
);

-- 默认数据
INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com', '13800138000');
INSERT OR IGNORE INTO users VALUES (2, 'alice', 'alice2025', 'alice@example.com', '13900139001');
```

### 1.4 路由设计

| 路由 | 方法 | 认证 | 功能 |
|------|------|------|------|
| `/login` | GET/POST | CSRF | 登录（内存比对，不变） |
| `/register` | GET/POST | CSRF | 注册 → 写入 SQLite |
| `/search` | GET | Session（需登录） | 搜索 → 读取 SQLite |
| `/` | GET | — | 首页 + 搜索结果展示 |

### 1.5 模板设计

```
templates/
├── base.html          ← 母版：导航栏新增"注册"链接
├── login.html         ← 登录：新增注册成功提示
├── index.html         ← 首页：新增搜索框 + 结果表格
├── register.html      ← 新建：注册表单
└── error.html         ← 不变
```

---

## 二、漏洞分析

### 2.1 漏洞原理

注册和搜索功能中，SQL 语句使用 **Python f-string 字符串拼接**构建，用户输入直接嵌入 SQL 语句：

```python
# 注册 — f-string 拼接（漏洞代码）
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

# 搜索 — f-string 拼接（漏洞代码）  
query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**攻击面分析**：

| 攻击向量 | 注入点 | 难度 | 危害 |
|---------|--------|------|------|
| UNION 注入 | `/search?keyword=` | 低（有回显） | 获取任意数据 |
| OR 永真条件 | `/search?keyword=` | 低 | 绕过搜索限制，获取全部用户 |
| INSERT 注入 | `/register` POST body | 中 | 控制数据库插入内容 |
| 密码明文存储 | `init_db()` 初始数据 | — | admin123 / alice2025 明文可见 |

### 2.2 攻击面详细分析

#### 攻击面 1：搜索 — UNION 注入（高危）

用户输入 `' UNION SELECT 1,'hack','hack@x.com','666'--` 后：

```sql
-- 原始 SQL 结构
SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'

-- 注入后变为
SELECT * FROM users
WHERE username LIKE '%' UNION SELECT 1,'hack','hack@x.com','666'--%' OR email LIKE '%...%'

-- 效果：
-- 1. 第一个 SELECT 匹配 username LIKE '%%'（全部用户）
-- 2. UNION 合并第二个 SELECT 的伪造数据
-- 3. -- 注释掉后续 OR email LIKE 条件
```

结果：攻击者构造的伪造数据 `(1, 'hack', 'hack@x.com', '666')` 会出现在搜索结果表中。

#### 攻击面 2：搜索 — OR 永真条件（中危）

用户输入 `' OR '1'='1` 后：

```sql
-- 注入后变为
SELECT * FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
                       ↑ '1'='1' 永真
```

结果：WHERE 条件永远为真，返回数据库全部用户。

#### 攻击面 3：注册 — INSERT 注入（中危）

用户输入用户名 `hacker', 'evilpw', 'evil@x.com', '999')--` 后：

```sql
-- 注入后变为
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'evilpw', 'evil@x.com', '999')--', '原始密码', '原始邮箱', '原始手机')
                                        ↑ -- 注释掉后续值
```

结果：攻击者完全控制插入的四个字段值，INSERT 按 `('hacker', 'evilpw', 'evil@x.com', '999')` 执行。

#### 攻击面 4：默认密码明文（高危）

```sql
INSERT OR IGNORE INTO users (...) VALUES (1, 'admin', 'admin123', ...);
INSERT OR IGNORE INTO users (...) VALUES (2, 'alice', 'alice2025', ...);
```

结果：数据库文件中 admin 和 alice 的密码以明文 `admin123` / `alice2025` 存储。

### 2.3 安全边界分析

| 模块 | SQL 注入风险 | 已有防护 |
|------|------------|---------|
| `/login` | ❌ 无风险（内存 dict + PBKDF2，不走 SQL） | PBKDF2 + CSRF + Rate Limit |
| `/register` | ⚠️ f-string 拼接 | CSRF（但 @csrf.exempt 绕过了） |
| `/search` | ⚠️ f-string 拼接 | Session 认证（需登录） |

**关键发现**：登录模块本身没有 SQL 注入，因为它走的是内存字典 + Werkzeug 哈希比对，完全不涉及 SQLite。注册和搜索是唯二的注入点。

---

## 三、POC 测试过程与结果

### 3.1 测试环境准备

```bash
cd /opt/Class01
rm -f data/users.db          # 清空数据库
python3 app.py               # 启动服务
```

### 3.2 POC 1：UNION 注入（搜索回显）

**攻击载荷**：
```
keyword=' UNION SELECT 1,'INJECTED','pwned','evil@x.com','999'--
URL 编码后:
%27%20UNION%20SELECT%201,%27INJECTED%27,%27pwned%27,%27evil@x.com%27,%27999%27--
```

**实际效果** — f-string 拼接生成的 SQL：
```sql
SELECT * FROM users WHERE username LIKE '%' UNION SELECT 1,'INJECTED','pwned','evil@x.com','999'--%' OR email LIKE '%' UNION SELECT 1,'INJECTED','pwned','evil@x.com','999'--%'
```

**漏洞版本测试结果**：

| ID | 用户名 | 密码 | 邮箱 | 手机 |
|----|--------|------|------|------|
| 1 | **INJECTED** | pwned | evil@x.com | 999 |
| 1 | admin | admin123 | admin@example.com | 13800138000 |
| 2 | alice | alice2025 | alice@example.com | 13900139001 |

> ✅ **漏洞确认**：伪造数据 `INJECTED` 成功出现在搜索结果表格中。

### 3.3 POC 2：OR 注入（绕过搜索限制）

**攻击载荷**：
```
keyword=' OR '1'='1
URL 编码后: %27%20OR%20%271%27%3D%271
```

**实际效果** — f-string 拼接生成的 SQL：
```sql
SELECT * FROM users WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
```

**漏洞版本测试结果**：

| ID | 用户名 | 密码 | 邮箱 | 手机 |
|----|--------|------|------|------|
| 1 | admin | admin123 | admin@example.com | 13800138000 |
| 2 | alice | alice2025 | alice@example.com | 13900139001 |
| 3 | testuser | mypass123 | u@x.com | 13800001111 |
| 4 | hacker', 'evilpw', 'evil@x.com', '999')-- | ... | ... | ... |

> ✅ **漏洞确认**：永真条件使 WHERE 失效，返回数据库中全部 4 条用户记录。

### 3.4 POC 3：注册 INSERT 注入

**攻击载荷**：
```
username=hacker', 'evilpw', 'evil@x.com', '999')--
```

**实际效果** — f-string 拼接生成的 SQL：
```sql
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'evilpw', 'evil@x.com', '999')--', 'irrelevant', '', '')
```

**控制台日志**：
```
[REGISTER SQL] INSERT INTO users (username, password, email, phone) VALUES ('hacker', 'evilpw', 'evil@x.com', '999')--', ...)
```

> ✅ **漏洞确认**：INSERT 语句被 `--` 截断，攻击者控制了插入的全部字段值。

### 3.5 漏洞清单汇总

| # | 漏洞 | 注入点 | CWE | 验证结果 |
|---|------|--------|-----|---------|
| 1 | UNION 注入 | `/search?keyword=` | CWE-89 | ✅ 伪造数据回显 |
| 2 | OR 永真条件 | `/search?keyword=` | CWE-89 | ✅ 泄露全部用户 |
| 3 | INSERT 注入 | `/register` POST | CWE-89 | ✅ 控制插入内容 |
| 4 | 明文密码存储 | SQLite 默认数据 | CWE-312 | ✅ admin123 可见 |

---

## 四、修复过程

### 4.1 修复策略

| 漏洞 | 修复方案 | 原理 |
|------|---------|------|
| UNION 注入 | 参数化查询 `?` 占位符 | SQL 结构与数据分离，数据库驱动安全绑定 |
| OR 永真条件 | 同 UNION 修复 | 注入语法被当作字面字符串，不改变 SQL 语义 |
| INSERT 注入 | 参数化查询 `?` 占位符 | 同上 |
| 明文密码 | `generate_password_hash()` | PBKDF2/scrypt 哈希，不可逆 |

### 4.2 修复前后代码对比

#### 注册 — 修复前 → 修复后

```python
# ❌ 修复前：f-string 字符串拼接
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
conn.execute(query)

# ✅ 修复后：参数化查询 + PBKDF2 密码哈希
password_hash = generate_password_hash(password)
query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
conn.execute(query, (username, password_hash, email, phone))
```

#### 搜索 — 修复前 → 修复后

```python
# ❌ 修复前：f-string 字符串拼接
query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
rows = conn.execute(query).fetchall()

# ✅ 修复后：参数化查询
like_pattern = f"%{keyword}%"
query = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
rows = conn.execute(query, (like_pattern, like_pattern)).fetchall()
```

### 4.3 为什么参数化查询能杜绝注入？

```
字符串拼接方式：
  "SELECT ... WHERE username LIKE '%" + 用户输入 + "%'"
  → 用户输入 ' OR '1'='1 直接拼入 SQL 字符串
  → SQL 解析器将 ' 解释为字符串结束符
  → 后续内容被解析为 SQL 关键字

参数化查询方式：
  "SELECT ... WHERE username LIKE ?"
  conn.execute(query, ("%' OR '1'='1%",))
  → SQL 结构在数据库端编译完成后再传参数
  → 参数值 '%\' OR \'1\'=\'1%' 中单引号被自动转义
  → 整个参数被当作一个 LIKE 匹配字符串处理
  → 搜索 0 条结果（因为没有人的用户名/邮箱包含这个字符串）
```

---

## 五、修复结果验证

### 5.1 修复后 POC 重新测试

| POC | 攻击载荷 | 修复前 | 修复后 |
|-----|---------|--------|--------|
| UNION 注入 | `' UNION SELECT ...` | ✅ 伪造数据回显 | ❌ **返回 0 条** |
| OR 永真条件 | `' OR '1'='1` | ✅ 泄露全部用户 | ❌ **返回 0 条** |
| INSERT 注入 | `hacker', ...)--` | ✅ 控制插入 | ❌ **用户名字面存储** |
| 密码查看 | `SELECT * FROM users` | admin123 明文 | ✅ **PBKDF2 哈希** |

### 5.2 控制台日志验证

修复后搜索 `' OR '1'='1` 时控制台输出：
```
[SEARCH SQL] SELECT * FROM users WHERE username LIKE ? OR email LIKE ?
params=(%' OR '1'='1%, %' OR '1'='1%)
```

可以清晰看到：整个注入字符串被包装在 `%...%` 中作为 LIKE 参数传入，不再被解析为 SQL 关键字。

### 5.3 正常功能回归测试

| 功能 | 测试用例 | 修复前 | 修复后 |
|------|---------|--------|--------|
| 正常搜索 | keyword=admin | ✅ 返回 admin | ✅ 返回 admin |
| 正常注册 | username=normal_user | ✅ 注册成功 | ✅ 注册成功 |
| 注册跳转 | 注册后跳转登录页 | ✅ "注册成功" | ✅ "注册成功" |
| 登录 | admin/Admin@2025#Secure | ✅ 登录成功 | ✅ 登录成功 |
| 未登录搜索 | 直接访问 /search | ✅ 302 跳转登录 | ✅ 302 跳转登录 |
| CSRF 保护 | POST /login 无 token | ✅ 400 | ✅ 400 |

---

## 六、完整修复清单

```
修复项                      修复方式                       文件/位置
────────────────────────────────────────────────────────────────
import sqlite3              新增模块导入                   app.py L12
init_db()                   初始化 SQLite + 建表 + 默认数据  app.py L125-152
/register (GET)             展示注册表单                   app.py L400-433
/register (POST)            参数化 INSERT + PBKDF2         app.py L420-424
/search (GET)               参数化 SELECT（需登录）         app.py L439-469
搜索框 + 结果表格            登录后显示                     index.html
register.html               注册表单模板                   新建
base.html                   导航栏新增"注册"链接            修改
login.html                  新增注册成功提示               修改
SQL 控制台日志              保留 print() 输出               app.py L421/L456
```

---

## 七、安全测试命令速查

### 正常功能测试
```bash
# 正常搜索
curl -s "http://127.0.0.1:5000/search?keyword=admin" -b /tmp/s.txt

# 正常注册  
curl -s http://127.0.0.1:5000/register -X POST \
  -d "csrf_token=...&username=newuser&password=pass123&email=n@t.com&phone=10086"
```

### SQL 注入测试（修复后均应返回 0 条或无效）
```bash
# UNION 注入
curl -s "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27INJECTED%27,%27pwned%27,%27999%27--" -b /tmp/s.txt

# OR 注入
curl -s "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271" -b /tmp/s.txt

# 注册注入
curl -s http://127.0.0.1:5000/register -X POST \
  -d "username=hacker', 'evilpw', 'evil@x.com', '999')--&password=irrelevant"
```

---

## 八、总结

1. **先设计后实现**：双存储架构清晰分离了登录（内存 PBKDF2）和注册/搜索（SQLite）的职责边界
2. **f-string 拼接是 SQL 注入的根本原因**：用户输入直接嵌入 SQL 语句，单引号改变 SQL 结构
3. **参数化查询是根治方案**：SQL 结构与数据分离，不依赖转义或过滤
4. **密码必须哈希存储**：注册密码从明文存储升级为 PBKDF2，与登录模块保持一致
5. **纵深防御**：参数化查询 + PBKDF2 + CSRF + Rate Limit + 安全响应头 = 全链路安全
6. **登录模块无 SQL 注入**：因为走的是内存字典 + Werkzeug 哈希比对，不涉及 SQLite

---

## 附录 A：项目结构

```
Class01/
├── app.py                          # Flask 主程序 (V5.0)
├── requirements.txt
├── .secret_key
├── data/
│   └── users.db                    # SQLite 数据库
├── templates/
│   ├── base.html                   # 母版（含"注册"链接）
│   ├── login.html                  # 登录页（含"注册成功"提示）
│   ├── index.html                  # 首页（含搜索框 + 结果表格）
│   ├── register.html               # 注册页
│   └── error.html
└── static/css/style.css
```

## 附录 B：启动方式

```bash
pip install -r requirements.txt
cd /opt/Class01 && python3 app.py
# http://127.0.0.1:5000
```

默认账号（登录用）: `admin / Admin@2025#Secure`, `alice / Alice@2025#Secure`

---

*GitHub: https://github.com/Perry88882/SecondDayOfTraining*  
*日期: 2026-07-20*
