"""
零信任安全网关 - MVP（报告取证版 / A 档）
功能点：
- 统一读取 Bearer Token（Header 优先，Body 备选）
- 开发期不验签（便于快速跑实验）→ 已留 TODO：可切换为 Keycloak JWKS 严格验签
- 基于上下文的简单信任分计算（IP变更、时间段、频率、设备指纹）
- 决策：allow / allow_restricted / require_mfa / deny，并给出 reason（用于 TopN 统计）
- Prometheus 指标：/metrics 暴露 Counter/Histogram（决策数量/延迟）
- CSV 追加 out/decisions.csv，便于不用 Prometheus 也能做图
"""

import os
import csv
import time
import json
import hashlib
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, render_template
import jwt
import redis

# ========== 环境变量 ==========
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM = os.getenv("REALM", "my-company")
CLIENT_ID = os.getenv("CLIENT_ID", "my-app")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
CSV_PATH = os.getenv("CSV_PATH", "out/decisions.csv")

# ========== Prometheus 指标 ==========
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
DECISIONS = Counter("zt_decisions_total", "Zero Trust decisions", ["action", "reason"])
LATENCY = Histogram("zt_decision_latency_seconds", "Decision latency seconds")

# ========== Flask & Redis ==========
app = Flask(__name__)
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# ========== TODO（可选，生产化时启用严格验签） ==========
# from jwt import PyJWKClient
# OIDC_ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"
# JWKS_URL = f"{OIDC_ISSUER}/protocol/openid-connect/certs"
# _jwk_client = PyJWKClient(JWKS_URL)
# def decode_and_verify(token: str):
#     key = _jwk_client.get_signing_key_from_jwt(token).key
#     return jwt.decode(
#         token, key, algorithms=["RS256"],
#         audience=CLIENT_ID, issuer=OIDC_ISSUER,
#         options={"require": ["exp", "iat", "nbf"], "verify_signature": True}
#     )

# ========== 工具函数 ==========
def read_bearer_token(req, body_token=None):
    """优先读 Authorization: Bearer xxx；否则读 body.token"""
    h = req.headers.get("Authorization", "")
    if h.startswith("Bearer "):
        return h.replace("Bearer ", "", 1).strip()
    return (body_token or "").strip()

def get_client_ip(req):
    """兼容反向代理/隧道的真实客户端 IP"""
    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return req.remote_addr or "0.0.0.0"

def ensure_csv_header(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ts", "user_id", "trust_score", "resource", "action", "reason"])

# ========== 核心类 ==========
class ZeroTrustGateway:
    """零信任网关核心：计算信任分 & 执行策略 & 记日志"""
    def __init__(self):
        self.suspicious_ips = set()
        self.user_behavior = {}

    def calculate_trust_score(self, user_id, request_context):
        """
        简易信任分：
        - IP 变化：-20
        - 非常规时间（<6 或 >23）：-15
        - 1分钟频率 > 30：-30
        - 敏感操作：-10
        - 未知设备：-25
        """
        score = 100

        # 1) IP变化
        last_ip = redis_client.get(f"user:{user_id}:last_ip")
        current_ip = request_context.get("ip")
        if last_ip and last_ip != current_ip:
            score -= 20

        # 2) 时间段
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 23:
            score -= 15

        # 3) 访问频率（滑动 1 分钟窗口）
        key_ac = f"user:{user_id}:access_count"
        access_count = redis_client.incr(key_ac)
        redis_client.expire(key_ac, 60)
        if access_count > 30:
            score -= 30

        # 4) 敏感操作
        if request_context.get("sensitive_operation"):
            score -= 10

        # 5) 设备指纹
        device_fingerprint = self._get_device_fingerprint(request_context)
        known_device = redis_client.sismember(f"user:{user_id}:devices", device_fingerprint)
        if not known_device:
            score -= 25
            # 学习：把该设备记为认识（仅用于 MVP 演示）
            redis_client.sadd(f"user:{user_id}:devices", device_fingerprint)

        # 保存状态
        redis_client.set(f"user:{user_id}:last_ip", current_ip)
        redis_client.set(f"user:{user_id}:trust_score", score)

        return max(0, min(100, score))

    def _get_device_fingerprint(self, context):
        """匿名化设备指纹（最小实现：UA + 语言 + 可选平台/时区）"""
        raw = "|".join([
            context.get("user_agent", ""),
            context.get("accept_language", ""),
            context.get("platform", ""),
            context.get("timezone", ""),
        ])
        return hashlib.sha256(raw.encode()).hexdigest()

    def enforce_zero_trust_policy(self, user_id, trust_score, resource):
        """
        执行策略 + 返回可解释 reason（用于报告 TopN）
        映射：
          >=80  : allow / low_risk
          >=60  : allow_restricted / mid_risk_readonly
          >=40  : require_mfa / high_risk_stepup
          else : deny / very_high_risk
        """
        if trust_score >= 80:
            policy = {
                "action": "allow",
                "restrictions": None,
                "monitoring_level": "normal",
                "reason": "low_risk",
            }
        elif trust_score >= 60:
            policy = {
                "action": "allow_restricted",
                "restrictions": ["read_only"],
                "monitoring_level": "enhanced",
                "reason": "mid_risk_readonly",
            }
        elif trust_score >= 40:
            policy = {
                "action": "require_mfa",
                "restrictions": ["minimal_access"],
                "monitoring_level": "strict",
                "reason": "high_risk_stepup",
            }
        else:
            policy = {
                "action": "deny",
                "restrictions": ["blocked"],
                "monitoring_level": "alert",
                "reason": "very_high_risk",
            }

        self._log_access_decision(user_id, trust_score, resource, policy)
        return policy

    def _log_access_decision(self, user_id, trust_score, resource, decision):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "trust_score": trust_score,
            "resource": resource,
            "decision": decision.get("action", ""),
            "reason": decision.get("reason", ""),
        }
        redis_client.lpush("access_logs", json.dumps(entry))
        redis_client.ltrim("access_logs", 0, 999)

gateway = ZeroTrustGateway()

# ========== 装饰器（开发期验 token：不验签）==========
def verify_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = read_bearer_token(request)
        if not token:
            return jsonify({"error": "未提供认证令牌"}), 401
        try:
            # 开发模式：不验签；生产化请切到 decode_and_verify()
            payload = jwt.decode(token, options={"verify_signature": False})
            request.user = payload
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({"error": f"令牌无效: {str(e)}"}), 401
    return decorated

# ========== 路由 ==========
@app.route("/")
def index():
    return "<h3>Zero-Trust Gateway (MVP / Report Mode)</h3>"

@app.route("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

@app.route("/healthz")
def healthz():
    try:
        redis_client.ping()
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "err", "error": str(e)}), 500

@app.route("/api/access-request", methods=["POST"])
def access_request():
    """零信任访问请求（统计友好版）"""
    started = time.time()
    ensure_csv_header(CSV_PATH)

    data = request.get_json(force=True, silent=True) or {}
    token = read_bearer_token(request, data.get("token"))

    if not token:
        return jsonify({"error": "需要认证令牌"}), 401

    try:
        # 开发模式：不验签；若要严格验签请切换为 decode_and_verify(token)
        user_info = jwt.decode(token, options={"verify_signature": False})
        user_id = user_info.get("preferred_username", "unknown")
        roles = user_info.get("realm_access", {}).get("roles", [])
    except Exception as e:
        return jsonify({"error": f"令牌无效: {str(e)}"}), 401

    request_context = {
        "ip": get_client_ip(request),
        "user_agent": request.headers.get("User-Agent", ""),
        "accept_language": request.headers.get("Accept-Language", ""),
        "sensitive_operation": (data.get("resource", "") or "/").startswith("/admin"),
        # 可选：前端可传 platform/timezone 等补丁
        "platform": data.get("platform", ""),
        "timezone": data.get("timezone", ""),
    }

    trust_score = gateway.calculate_trust_score(user_id, request_context)
    resource = data.get("resource", "/")
    policy = gateway.enforce_zero_trust_policy(user_id, trust_score, resource)

    # —— 指标打点 —— #
    LATENCY.observe(time.time() - started)
    DECISIONS.labels(policy["action"], policy.get("reason", "unknown")).inc()

    # —— 追加 CSV（便于不用 Prometheus 也能画图） —— #
    try:
        with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([datetime.now().isoformat(), user_id, trust_score, resource, policy["action"], policy.get("reason", "")])
    except Exception:
        pass

    response = {
        "user_id": user_id,
        "roles": roles,
        "trust_score": trust_score,
        "access_decision": policy["action"],
        "restrictions": policy.get("restrictions", []),
        "monitoring_level": policy["monitoring_level"],
        "reason": policy.get("reason", ""),
        "timestamp": datetime.now().isoformat(),
    }

    # 返回码：allow/allow_restricted=200；require_mfa=428；deny=403
    action = policy["action"]
    if action == "deny":
        code = 403
    elif action == "require_mfa":
        code = 428  # 报告中可统计为 Step-up 次数
    else:
        code = 200

    return jsonify(response), code

@app.route("/api/user-behavior/<user_id>", methods=["GET"])
@verify_token
def get_user_behavior(user_id):
    trust_score = redis_client.get(f"user:{user_id}:trust_score") or 100
    last_ip = redis_client.get(f"user:{user_id}:last_ip") or "unknown"
    access_count = redis_client.get(f"user:{user_id}:access_count") or 0

    return jsonify({
        "user_id": user_id,
        "current_trust_score": int(trust_score),
        "last_known_ip": last_ip,
        "recent_access_count": int(access_count),
        "risk_level": "high" if int(trust_score) < 60 else "medium" if int(trust_score) < 80 else "low"
    })

@app.route("/api/simulate-attack", methods=["POST"])
def simulate_attack():
    attack_type = (request.json or {}).get("type", "brute_force")
    if attack_type == "location_change":
        gateway.calculate_trust_score("john", {
            "ip": "203.0.113.0",
            "user_agent": request.headers.get("User-Agent", ""),
            "accept_language": "zh-CN"
        })
    return jsonify({"message": f"已模拟 {attack_type} 攻击"})

# ========== 主入口 ==========
if __name__ == "__main__":
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    print("🚀 零信任网关启动: http://localhost:5000")
    print("   健康检查:      /healthz")
    print("   Prom指标:      /metrics")
    app.run(host="0.0.0.0", port=5000, debug=True)
