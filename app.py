import os

from flask import Flask, render_template, request, redirect, session
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ─── 安全密钥 ────────────────────────────────────────────
# 若存在密钥文件则读取（保证重启后 session 仍有效）
# 否则随机生成并保存，部署时建议手动固定
secret_key_file = os.path.join(os.path.dirname(__file__), ".secret_key")
if os.path.exists(secret_key_file):
    with open(secret_key_file) as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = os.urandom(24).hex()
    with open(secret_key_file, "w") as f:
        f.write(app.secret_key)
    print(f"[安全] 已生成新密钥并保存至 {secret_key_file}")

# ─── Session 安全配置 ────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,   # 开发环境无 HTTPS，部署时改为 True
)

# ─── CSRF 保护 ───────────────────────────────────────────
csrf = CSRFProtect(app)

# ─── 限流保护 ────────────────────────────────────────────
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


# 限流触发时的友好提示
@app.errorhandler(429)
def rate_limit_handler(e):
    return render_template("login.html", error="操作过于频繁，请 1 分钟后再试", is_rate_limit=True), 429

# ─── 用户数据库 ─────────────────────────────────────────
# 密码经过 werkzeug 哈希存储，不再存明文
_admin_pw = "Admin@2025#Secure"
_alice_pw = "Alice@2025#Secure"

USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash(_admin_pw),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash(_alice_pw),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# 首次启动时在控制台打印初始密码（唯一可见的地方）
print("=" * 56)
print("             用户管理系统 V2（安全版）")
print("=" * 56)
print(f"  默认账号       密码")
print(f"  ─────────────────────────────")
print(f"  admin          {_admin_pw}")
print(f"  alice          {_alice_pw}")
print(f"  ─────────────────────────────")
print(f"  上线后请务必修改默认密码！")
print("=" * 56)


# ─── 辅助函数 ───────────────────────────────────────────
def get_safe_user(username):
    """返回不含密码字段的用户信息"""
    user = USERS.get(username)
    if user:
        return {k: v for k, v in user.items() if k != "password"}
    return None


# ─── 安全响应头 ─────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# ─── 路由 ───────────────────────────────────────────────
@app.route("/")
def index():
    username = session.get("username")
    user_info = get_safe_user(username) if username else None
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", override_defaults=False)
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            return redirect("/")

        # 模糊错误提示 —— 不区分"用户不存在"和"密码错误"
        error = "用户名或密码错误"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


# ─── CSRF 豁免（登出是 GET，不需要） ────────────────────
# Flask-WTF 默认保护所有 POST，无需额外配置


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
