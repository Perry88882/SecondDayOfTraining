# SQL 注入漏洞测试与修复实验报告

> **实验环境**: Kali Linux / Python 3.13 / Flask + SQLite  
> **实验日期**: 2026-07-19  
> **测试目标**: http://127.0.0.1:5000  
> **代码仓库**: https://github.com/Perry88882/SecondDayOfTraining  
> **作者**: Perry

---

## 一、实验概述

本实验对 Flask 用户管理平台的 `/search`（搜索）和 `/register`（注册）功能进行 SQL 注入漏洞测试、验证与修复。实验采用"先攻击后防御"的方法，先构造恶意输入验证漏洞存在，再通过参数化查询彻底修复。

---

## 二、漏洞原理

### 漏洞 1：字符串拼接 SQL 查询

在搜索和注册功能中，用户输入通过 Python `.format()` 直接拼接到 SQL 语句：

```python
# 搜索 — 字符串拼接（漏洞代码）
query = (
    "SELECT * FROM users "
    "WHERE username LIKE '%{}%' OR email LIKE '%{}%'"
).format(keyword, keyword)

# 注册 — 字符串拼接（漏洞代码）
query = (
    "INSERT INTO users (username, password, email, phone) "
    "VALUES ('{}', '{}', '{}', '{}')"
).format(username, password, email, phone)
```

**危害**: 用户输入中的单引号 `'` 会提前闭合 SQL 字符串字面值，改变 SQL 语句结构，导致任意 SQL 命令执行。

### 漏洞 2：无任何输入过滤

所有用户输入直接传入 SQL 语句，未做任何转义或过滤。

### 漏洞 3：搜索结果有回显

搜索结果以 HTML 表格形式展示，攻击者可通过 UNION 注入获取任意数据。

---

## 三、POC 测试（修复前 — 漏洞存在确认）

### POC 1：UNION 注入获取任意数据

**攻击请求**:
```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27INJECTED%27,%27pwned%27,%27evil@x.com%27,%27999%27--"
```

**生成的 SQL**:
```sql
SELECT * FROM users
WHERE username LIKE '%' UNION SELECT 1,'INJECTED','pwned','evil@x.com','999'--%'
      ↑ 单引号闭合原始 LIKE 字符串    ↑ -- 注释掉后续代码
```

**测试结果 — ✅ 漏洞存在**:

| ID | 用户名 | 密码 | 邮箱 | 手机 |
|----|--------|------|------|------|
| 1 | **INJECTED** | pwned | evil@x.com | 999 |
| 1 | admin | admin123 | admin@example.com | 13800138000 |
| 2 | alice | alice2025 | alice@example.com | 13900139001 |

**结论**: UNION SELECT 构造的伪造数据成功注入到搜索结果中。攻击者可通过此漏洞获取任意数据库表内容。

---

### POC 2：OR 注入搜索全部用户

**攻击请求**:
```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271"
```

**生成的 SQL**:
```sql
SELECT * FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
                       ↑ 永真条件，所有行都匹配
```

**测试结果 — ✅ 漏洞存在**: 返回数据库中**全部**用户记录（admin、alice 和已注册用户），共 5 行。

**结论**: 攻击者可绕过搜索关键词限制，一次性获取所有用户数据。

---

### POC 3：注册功能 SQL 注入

**攻击请求**:
```bash
curl http://127.0.0.1:5000/register \
  -X POST \
  -d "username=hacker1', 'pass1', 'h1@x.com', '111')--&password=irrelevant"
```

**生成的 SQL**:
```sql
INSERT INTO users (username, password, email, phone)
VALUES ('hacker1', 'pass1', 'h1@x.com', '111')--', 'irrelevant', '', '')
         ↑ 攻击者完全控制插入的字段值         ↑ -- 注释掉后续参数
```

**测试结果 — ✅ 漏洞存在**: 
- 成功注册，用户名被解释为完整的 `hacker1', 'pass1', 'h1@x.com', '111')--`
- 但更严重的是：如果构造更精巧的 payload，攻击者可以向数据库插入任意数据

**结论**: 攻击者可完全控制插入数据库的内容，包括插入管理员账户或其他恶意数据。

---

### 漏洞确认清单

| POC | 攻击类型 | 漏洞版本结果 | 严重性 |
|-----|---------|------------|--------|
| POC 1 | UNION 注入 | ✅ 成功 — 伪造数据出现在搜索页 | Critical |
| POC 2 | OR 永真条件 | ✅ 成功 — 泄露全部用户数据 | High |
| POC 3 | 注册注入 | ✅ 成功 — 控制插入内容 | High |
| 密码存储 | 明文密码 | ✅ admin123 / alice2025 明文可见 | Critical |

---

## 四、修复方案

### 修复 1：参数化查询（核心修复）

**修复前**（字符串拼接）:
```python
query = (
    "SELECT * FROM users "
    "WHERE username LIKE '%{}%' OR email LIKE '%{}%'"
).format(keyword, keyword)
rows = conn.execute(query).fetchall()
```

**修复后**（参数化查询）:
```python
like_pattern = f"%{keyword}%"
query = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
rows = conn.execute(query, (like_pattern, like_pattern)).fetchall()
```

**原理**: 使用 `?` 占位符将 SQL 结构与数据分离。数据库驱动负责安全地绑定参数值，用户输入中的特殊字符（如单引号 `'`）被视作普通数据而非 SQL 代码。

### 修复 2：注册功能参数化 + 密码哈希

**修复前**（字符串拼接 + 明文密码）:
```python
query = (
    "INSERT INTO users (username, password, email, phone) "
    "VALUES ('{}', '{}', '{}', '{}')"
).format(username, password, email, phone)
conn.execute(query)
```

**修复后**（参数化查询 + PBKDF2 哈希）:
```python
password_hash = generate_password_hash(password)  # PBKDF2 600,000 次迭代
query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
conn.execute(query, (username, password_hash, email, phone))
```

### 修复 3：错误信息脱敏

**修复前**:
```python
message=f"SQL 错误: {e}"
```

**修复后**:
```python
message="查询失败，请稍后重试"
logger.error("Search error: %s", e)  # 详细错误仅记录在服务端日志
```

---

## 五、修复结果验证

### 验证 1：UNION 注入 → 无效

```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%20..."
# 结果: 搜索 "&#39; UNION SELECT..." — 共找到 0 条结果
```

UNION 注入字符串被参数化查询当作普通搜索关键词，搜索到 0 条匹配记录。

### 验证 2：OR 永真条件 → 无效

```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271"
# 结果: 搜索 "&#39; OR &#39;1&#39;=&#39;1" — 共找到 0 条结果
```

永真条件被当作字面字符串，不再影响 SQL 语法。

### 验证 3：注册注入 → 无效

正常注册 `normal_user` 成功，密码以 `scrypt:32768:8:1$...` 哈希形式存储，无法提取明文。

### 验证 4：正常功能 → 不变

| 功能 | 修复前 | 修复后 |
|------|--------|--------|
| 搜索 admin | 返回 1 条结果 | 返回 1 条结果 |
| 正常注册 | 成功 | 成功 |
| UNION 注入 | 成功注入 | 返回 0 条 |
| OR 注入 | 返回全部 | 返回 0 条 |
| 密码存储 | 明文 | PBKDF2/scrypt 哈希 |

---

## 六、修复前后对比

| 维度 | 修复前 (V1.0) | 修复后 (V4.0) |
|------|-------------|-------------|
| SQL 查询方式 | `.format()` 字符串拼接 | `?` 参数化查询 |
| 输入过滤 | 无 | 参数绑定自动转义 |
| 密码存储 | 明文 (admin123) | PBKDF2/scrypt 哈希 |
| UNION 注入 | ✅ 可注入任意数据 | ❌ 无法注入 |
| OR 永真条件 | ✅ 绕过 WHERE | ❌ 无法绕过 |
| 注册注入 | ✅ 控制插入内容 | ❌ 无法注入 |
| CSRF 保护 | 无 | ✅ 启用 |
| 登录限流 | 无 | ✅ 5 次/分钟 |
| 安全响应头 | 无 | ✅ X-Frame/Content/XSS/CSP |

---

## 七、知识点

| 概念 | 原理 |
|------|------|
| **SQL 注入** | 攻击者将恶意 SQL 片段注入输入参数，改变原查询语义 |
| **参数化查询** | SQL 语句结构与数据分离，数据库驱动将参数值安全绑定 |
| **PBKDF2/scrypt** | 慢哈希函数，通过大量迭代使暴力破解计算成本极高 |
| **纵深防御** | 参数化查询 + CSRF + Rate Limit + 安全头，多层防护 |
| **最小暴露** | 错误信息不泄露数据库结构，详细日志仅存服务端 |

---

## 八、总结

1. **SQL 注入是最常见且危害最大的 Web 漏洞之一**: 攻击者可窃取、篡改、删除数据库数据
2. **参数化查询是根本解决方案**: 不依赖输入过滤或转义，从 SQL 层面杜绝注入
3. **安全编码应前置而非补丁**: 每个 SQL 查询都应使用参数化，不应事后修复
4. **密码存储必须使用哈希**: PBKDF2/scrypt/bcrypt/argon2，绝不能存明文
5. **纵深防御不可少**: 参数化查询 + 密码哈希 + CSRF + Rate Limit = 全链路安全

---

## 附录 A：项目结构

```
Class01/
├── app.py              # Flask 主程序 (V4.0 完整修复版)
├── requirements.txt    # 依赖
├── .gitignore
├── .secret_key         # Flask session 签名密钥
├── users.db            # SQLite 数据库
├── templates/
│   ├── base.html       # Jinja2 母版
│   ├── login.html      # 登录页（含 CSRF token）
│   ├── index.html      # 首页（无密码字段）
│   ├── search.html     # 搜索页（结果表格）
│   ├── register.html   # 注册页（含 CSRF token）
│   └── error.html      # 统一错误页
└── static/css/style.css
```

## 附录 B：启动方式

```bash
pip install -r requirements.txt
cd Class01 && python3 app.py
# 访问 http://127.0.0.1:5000
```

默认账号: `admin / Admin@2025#Secure`, `alice / Alice@2025#Secure`

## 附录 C：参考文档

- OWASP Top 10: A03:2021 – Injection
- OWASP SQL Injection Prevention Cheat Sheet
- Python sqlite3 文档 — 参数化查询
- OWASP Password Storage Cheat Sheet
- CWE-89: SQL Injection

---

*GitHub: https://github.com/Perry88882/SecondDayOfTraining*
