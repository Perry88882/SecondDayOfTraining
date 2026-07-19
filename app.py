"""
用户信息管理平台 — Flask 主应用 (V3.0 鲁棒版)
─────────────────────────────────────────────────
安全特性:  PBKDF2 密码哈希 · CSRF 防护 · 登录限流
          Session 安全 · 安全响应头 · 输入校验
鲁棒性:   结构化日志 · 类型标注 · 全局异常处理
          输入验证 · 密钥容错 · 一致性错误响应
"""

import logging
import os
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
        # 生产环境可追加 FileHandler: logging.FileHandler("app.log")
    ],
)
logger = logging.getLogger("user-management")


# ─────────────────────────────────────────────────────
#  应用工厂 & 配置
# ─────────────────────────────────────────────────────
class AppConfig:
    """集中管理所有可配置项，避免魔术值散布在代码中"""

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
    """用户领域模型 —— 密码字段由 werkzeug 哈希管理"""

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
#  用户存储（生产环境应迁移至数据库）
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
#  Flask 实例
# ─────────────────────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 限制请求体最大 16KB


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
            if len(key) >= 32:                  # 至少 16 字节 hex
                logger.info("已加载持久化密钥: %s", key_file)
                return key
            logger.warning("密钥文件长度不足 (%d 字符)，将重新生成", len(key))
        except (OSError, UnicodeDecodeError) as exc:
            logger.error("读取密钥文件失败: %s，将重新生成", exc)

    # 生成新密钥
    new_key = os.urandom(24).hex()
    try:
        with open(key_file, "w") as fh:
            fh.write(new_key)
        os.chmod(key_file, 0o600)               # 仅 owner 可读写
        logger.info("已生成新密钥并保存至 %s", key_file)
    except OSError as exc:
        logger.warning("无法持久化密钥文件 (%s)，重启后 session 将失效", exc)
    return new_key


app.secret_key = _load_or_create_secret_key()

# Session 配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,                # 开发环境；部署时改为 True
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
    """按用户名获取不含密码哈希的用户信息，不存在则返回 None"""
    if not username:
        return None
    user = USERS.get(username)
    return user.to_safe_dict() if user else None


def validate_login_input(
    username: str, password: str
) -> Tuple[bool, Optional[str]]:
    """
    校验登录表单输入的合法性。
    返回 (is_valid, error_message)。
    """
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
    """记录登录尝试（结构化日志，未来可接入审计系统）"""
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
    """服务器内部错误 —— 避免泄露堆栈信息到前端"""
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
    # 仅对 HTML 页面注入，静态资源可跳过
    content_type = response.headers.get("Content-Type", "")
    if "text/html" in content_type:
        for key, val in headers.items():
            if key not in response.headers:
                response.headers[key] = val
    return response


# ─────────────────────────────────────────────────────
#  路由
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
            # 登录成功 —— 重新生成 session 防止 session fixation
            session.clear()
            session["username"] = username
            session["login_at"] = datetime.now(timezone.utc).isoformat()
            session.permanent = AppConfig.SESSION_PERMANENT

            _log_login_attempt(username, True, request.remote_addr)
            logger.info("User '%s' logged in from %s", username, request.remote_addr)
            return redirect(url_for("index"))

        # 登录失败
        _log_login_attempt(username, False, request.remote_addr)
        error = "用户名或密码错误"          # 统一消息，不区分具体失败原因

    return render_template("login.html", error=error, is_rate_limit=is_rate_limit)


@app.route("/logout")
def logout() -> Response:
    """登出 —— 清空全部 session 数据后重定向首页"""
    session.clear()
    logger.info("User logged out (ip=%s)", request.remote_addr)
    return redirect(url_for("index"))


@app.route("/health")
def health() -> Tuple[Dict[str, str], int]:
    """健康检查端点 —— 供负载均衡/监控系统使用"""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}, 200


# ─────────────────────────────────────────────────────
#  启动信息
# ─────────────────────────────────────────────────────
def _print_banner() -> None:
    """控制台输出默认账号信息（唯一凭据可见之处）"""
    banner = """
╔══════════════════════════════════════════════════════╗
║           用户管理系统 V3.0（鲁棒安全版）             ║
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
