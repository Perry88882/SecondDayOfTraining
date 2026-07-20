"""
用户信息管理平台 — Flask 主应用 (V4.0 完整修复版)
─────────────────────────────────────────────────
安全特性:  PBKDF2 密码哈希 · CSRF 防护 · 登录限流
          Session 安全 · 安全响应头 · 参数化查询
鲁棒性:   结构化日志 · 类型标注 · 全局异常处理
          输入验证 · 密钥容错 · 一致性错误响应

变更历史:
  V1.0 - 功能原型 (明文密码, 无保护)
  V2.0 - 安全加固 (PBKDF2, CSRF, Rate Limit)
  V3.0 - 鲁棒性升级 (日志, 异常处理, 安全头)
  V4.0 - SQL注入修复 (参数化查询, 注册密码哈希)
"""

import logging
import os
import sqlite3
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional, Tuple

from flask import (
    Flask, Response, abort, redirect, render_template,
    request, session, url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import check_password_hash, generate_password_hash

# ─────────────────────────────────────────────────────
#  日志配置
# ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("user-management")


# ─────────────────────────────────────────────────────
#  应用工厂 & 配置
# ─────────────────────────────────────────────────────
class AppConfig:
    """集中管理所有可配置项"""

    HOST: str = "0.0.0.0"
    PORT: int = 5000
    DEBUG: bool = True

    # 密码校验
    MIN_PASSWORD_LENGTH: int = 6
    MAX_PASSWORD_LENGTH: int = 128
    MAX_USERNAME_LENGTH: int = 64

    # 限流
    LOGIN_RATE_LIMIT: str = "5 per minute"
    GLOBAL_DAILY_LIMIT: str = "200 per day"
    GLOBAL_HOURLY_LIMIT: str = "50 per hour"

    # 会话
    SESSION_PERMANENT: bool = True
    SESSION_LIFETIME_MINUTES: int = 60

    # 安全密钥文件
    SECRET_KEY_FILE: str = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".secret_key"
    )


# ─────────────────────────────────────────────────────
#  用户数据模型
# ─────────────────────────────────────────────────────
@dataclass
class User:
    """用户领域模型"""

    username: str
    password_hash: str           # pbkdf2:sha256:600000$salt$hash
    role: str = "user"
    email: str = ""
    phone: str = ""
    balance: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_safe_dict(self) -> Dict[str, Any]:
        """序列化为前端安全字典 —— 排除密码哈希"""
        result = asdict(self)
        result.pop("password_hash", None)
        return result


# ─────────────────────────────────────────────────────
#  内存用户存储
# ─────────────────────────────────────────────────────
def _init_user_store() -> Dict[str, User]:
    """初始化内置用户"""
    return {
        "admin": User(
            username="admin",
            password_hash=generate_password_hash("Admin@2025#Secure"),
            role="admin",
            email="admin@example.com",
            phone="13800138000",
            balance=99999,
        ),
        "alice": User(
            username="alice",
            password_hash=generate_password_hash("Alice@2025#Secure"),
            role="user",
            email="alice@example.com",
            phone="13900139001",
            balance=100,
        ),
    }


USERS: Dict[str, User] = _init_user_store()


# ─────────────────────────────────────────────────────
#  SQLite 数据库（用于 /register 和 /search）
# ─────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


def _init_sqlite_db() -> None:
    """初始化 SQLite 数据库和 users 表"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（密码使用 PBKDF2 哈希）
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password, email, phone) "
        "VALUES (1, 'admin', ?, 'admin@example.com', '13800138000')",
        (generate_password_hash("admin123"),)
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password, email, phone) "
        "VALUES (2, 'alice', ?, 'alice@example.com', '13900139001')",
        (generate_password_hash("alice2025"),)
    )
    conn.commit()
    conn.close()
    logger.info("SQLite 数据库已初始化: %s", DB_PATH)


_init_sqlite_db()


def _get_db() -> sqlite3.Connection:
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────────────────
#  Flask 实例
# ─────────────────────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


# ─────────────────────────────────────────────────────
#  安全密钥加载（带容错）
# ─────────────────────────────────────────────────────
def _load_or_create_secret_key() -> str:
    """加载持久化密钥，失败时安全降级为新随机密钥"""
    key_file = AppConfig.SECRET_KEY_FILE

    if os.path.exists(key_file):
        try:
            with open(key_file) as fh:
                key = fh.read().strip()
            if len(key) >= 32:
                logger.info("已加载持久化密钥: %s", key_file)
                return key
            logger.warning("密钥文件长度不足 (%d 字符)，将重新生成", len(key))
        except (OSError, UnicodeDecodeError) as exc:
            logger.error("读取密钥文件失败: %s，将重新生成", exc)

    new_key = os.urandom(24).hex()
    try:
        with open(key_file, "w") as fh:
            fh.write(new_key)
        os.chmod(key_file, 0o600)
        logger.info("已生成新密钥并保存至 %s", key_file)
    except OSError as exc:
        logger.warning("无法持久化密钥文件 (%s)，重启后 session 将失效", exc)
    return new_key


app.secret_key = _load_or_create_secret_key()

# Session 配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=AppConfig.SESSION_LIFETIME_MINUTES * 60,
)

# ─────────────────────────────────────────────────────
#  安全组件初始化
# ─────────────────────────────────────────────────────
csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[AppConfig.GLOBAL_DAILY_LIMIT, AppConfig.GLOBAL_HOURLY_LIMIT],
    storage_uri="memory://",
)


# ─────────────────────────────────────────────────────
#  辅助函数
# ─────────────────────────────────────────────────────
def get_safe_user(username: Optional[str]) -> Optional[Dict[str, Any]]:
    """按用户名获取不含密码哈希的用户信息"""
    if not username:
        return None
    user = USERS.get(username)
    return user.to_safe_dict() if user else None


def validate_login_input(
    username: str, password: str
) -> Tuple[bool, Optional[str]]:
    """校验登录表单输入的合法性"""
    if not username or not password:
        return False, "用户名和密码不能为空"

    if len(username) > AppConfig.MAX_USERNAME_LENGTH:
        return False, "用户名或密码错误"

    if len(password) > AppConfig.MAX_PASSWORD_LENGTH:
        return False, "用户名或密码错误"

    if len(password) < AppConfig.MIN_PASSWORD_LENGTH:
        return False, "用户名或密码错误"

    return True, None


def _log_login_attempt(username: str, success: bool, ip: str) -> None:
    """记录登录尝试"""
    status = "SUCCESS" if success else "FAILURE"
    logger.info(
        "LOGIN_ATTEMPT | user=%s | status=%s | ip=%s",
        username, status, ip,
    )


# ─────────────────────────────────────────────────────
#  全局异常处理
# ─────────────────────────────────────────────────────
@app.errorhandler(CSRFError)
def handle_csrf_error(exc: CSRFError) -> Tuple[str, int]:
    """CSRF token 缺失或无效"""
    logger.warning("CSRF validation failed: %s (ip=%s)", exc.description, request.remote_addr)
    return render_template("error.html",
                           code=400,
                           title="请求被拒绝",
                           message="安全验证失败，请返回上一页刷新后重试。"), 400


@app.errorhandler(429)
def handle_rate_limit(exc: Exception) -> Tuple[str, int]:
    """限流触发"""
    logger.info("Rate limit triggered (ip=%s)", request.remote_addr)
    return render_template(
        "login.html",
        error="操作过于频繁，请 1 分钟后再试",
        is_rate_limit=True,
    ), 429


@app.errorhandler(404)
def handle_not_found(exc: Exception) -> Tuple[str, int]:
    """页面不存在"""
    return render_template("error.html",
                           code=404,
                           title="页面未找到",
                           message="您访问的页面不存在。"), 404


@app.errorhandler(500)
def handle_internal_error(exc: Exception) -> Tuple[str, int]:
    """服务器内部错误"""
    logger.exception("Internal server error: %s", exc)
    return render_template("error.html",
                           code=500,
                           title="服务器错误",
                           message="服务器内部错误，请稍后重试。"), 500


@app.errorhandler(413)
def handle_too_large(exc: Exception) -> Tuple[str, int]:
    """请求体过大"""
    return render_template("error.html",
                           code=413,
                           title="请求过大",
                           message="提交的数据超过大小限制。"), 413


# ─────────────────────────────────────────────────────
#  安全响应头
# ─────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response: Response) -> Response:
    """为每个响应注入安全加固头"""
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    content_type = response.headers.get("Content-Type", "")
    if "text/html" in content_type:
        for key, val in headers.items():
            if key not in response.headers:
                response.headers[key] = val
    return response


# ═══════════════════════════════════════════════════════════
#  搜索功能 — ✅ 参数化查询（已修复 SQL 注入）
# ═══════════════════════════════════════════════════════════
@app.route("/search")
def search() -> str:
    """搜索用户 —— 使用参数化查询，杜绝 SQL 注入"""
    keyword = request.args.get("keyword", "")
    conn = _get_db()

    # 修复：参数化查询，使用 ? 占位符
    like_pattern = f"%{keyword}%"
    query = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"

    logger.info("SEARCH query: %s [params: %s, %s]", query, like_pattern, like_pattern)

    try:
        rows = conn.execute(query, (like_pattern, like_pattern)).fetchall()
    except sqlite3.Error as e:
        conn.close()
        logger.error("Search error: %s", e)
        return render_template("error.html",
                               code=500,
                               title="查询错误",
                               message="查询失败，请稍后重试"), 500
    conn.close()

    results = [dict(r) for r in rows]
    return render_template("search.html",
                           keyword=keyword,
                           results=results,
                           count=len(results))


# ═══════════════════════════════════════════════════════════
#  注册功能 — ✅ 参数化查询 + PBKDF2 密码哈希（已修复 SQL 注入）
# ═══════════════════════════════════════════════════════════
@app.route("/register", methods=["GET", "POST"])
def register() -> str:
    """用户注册 —— 参数化查询 + PBKDF2 哈希，杜绝 SQL 注入"""
    error: Optional[str] = None
    success: Optional[str] = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        if not username or not password:
            error = "用户名和密码不能为空"
        elif len(password) < 6:
            error = "密码长度不能少于 6 位"
        else:
            conn = _get_db()

            # 修复：参数化查询 + PBKDF2 密码哈希
            password_hash = generate_password_hash(password)
            query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"

            logger.info("REGISTER: username=%s", username)

            try:
                conn.execute(query, (username, password_hash, email, phone))
                conn.commit()
                success = f"注册成功！欢迎 {username}"
            except sqlite3.IntegrityError:
                conn.rollback()
                error = "用户名已存在"
            except sqlite3.Error as e:
                conn.rollback()
                logger.error("Register error: %s", e)
                error = "注册失败，请稍后重试"
            finally:
                conn.close()

    return render_template("register.html", error=error, success=success)


# ─────────────────────────────────────────────────────
#  已加固路由（V3.0 代码，含 CSRF + Rate Limit）
# ─────────────────────────────────────────────────────
@app.route("/")
def index() -> str:
    """首页 —— 已登录展示用户信息，未登录提示跳转"""
    username = session.get("username")
    user_info = get_safe_user(username)
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit(AppConfig.LOGIN_RATE_LIMIT, override_defaults=False)
def login() -> str:
    """登录页 —— GET 展示表单，POST 验证凭据"""
    error: Optional[str] = None
    is_rate_limit: bool = False

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 阶段 1：输入合法性校验
        is_valid, validation_error = validate_login_input(username, password)
        if not is_valid:
            _log_login_attempt(username or "<empty>", False, request.remote_addr)
            return render_template("login.html", error=validation_error)

        # 阶段 2：凭据验证
        user = USERS.get(username)
        if user and check_password_hash(user.password_hash, password):
            # 登录成功
            session.clear()
            session["username"] = username
            session["login_at"] = datetime.now(timezone.utc).isoformat()
            session.permanent = AppConfig.SESSION_PERMANENT

            _log_login_attempt(username, True, request.remote_addr)
            logger.info("User '%s' logged in from %s", username, request.remote_addr)
            return redirect(url_for("index"))

        _log_login_attempt(username, False, request.remote_addr)
        error = "用户名或密码错误"

    return render_template("login.html", error=error, is_rate_limit=is_rate_limit)


@app.route("/logout")
def logout() -> Response:
    """登出"""
    session.clear()
    logger.info("User logged out (ip=%s)", request.remote_addr)
    return redirect(url_for("index"))


@app.route("/health")
def health() -> Tuple[Dict[str, str], int]:
    """健康检查端点"""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}, 200


# ─────────────────────────────────────────────────────
#  启动信息
# ─────────────────────────────────────────────────────
def _print_banner() -> None:
    """控制台输出默认账号信息"""
    banner = """
╔══════════════════════════════════════════════════════╗
║           用户管理系统 V4.0（完整修复版）             ║
╠══════════════════════════════════════════════════════╣
║  默认账号          密码                              ║
║  ────────────────────────────────────────────────    ║
║  admin             Admin@2025#Secure                  ║
║  alice             Alice@2025#Secure                  ║
╠══════════════════════════════════════════════════════╣
║  ⚠  上线后请立即修改默认密码                          ║
╚══════════════════════════════════════════════════════╝
"""
    print(banner)


# ─────────────────────────────────────────────────────
#  主入口
# ─────────────────────────────────────────────────────
if __name__ == "__main__":
    _print_banner()
    app.run(
        debug=AppConfig.DEBUG,
        host=AppConfig.HOST,
        port=AppConfig.PORT,
    )
