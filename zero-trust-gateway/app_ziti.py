# -*- coding: utf-8 -*-
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
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST


KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM = os.getenv("REALM", "my-company")
CLIENT_ID = os.getenv("CLIENT_ID", "my-app")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
CSV_PATH = os.getenv("CSV_PATH", "out/decisions_ziti.csv")
USE_ZITI = os.getenv("USE_ZITI", "false").lower() == "true"
ZITI_CONTROLLER = os.getenv("ZITI_CONTROLLER", "localhost:1280")


DECISIONS = Counter("zt_decisions_total", "Zero Trust decisions", ["action", "reason", "layer"])
LATENCY = Histogram("zt_decision_latency_seconds", "Decision latency seconds")
TRUST_SCORE = Histogram("zt_trust_score", "Trust score distribution", ["layer"])
ZITI_CONNECTIONS = Counter("ziti_connections_total", "OpenZiti connection attempts", ["status"])


app = Flask(__name__)
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


ziti_enabled = False
if USE_ZITI:
    try:
        import openziti
        print("OpenZiti模块已加载")
        ziti_enabled = True
    except ImportError:
        print("OpenZiti未安装，运行在标准模式")
        USE_ZITI = False

def read_bearer_token(req, body_token=None):
    h = req.headers.get("Authorization", "")
    if h.startswith("Bearer "):
        return h.replace("Bearer ", "", 1).strip()
    return (body_token or "").strip()

def get_client_ip(req):
    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    if USE_ZITI and req.headers.get("X-Openziti-Identity"):
        return "ziti-network"
    return req.remote_addr or "0.0.0.0"

def get_ziti_identity(req):
    return req.headers.get("X-Openziti-Identity", None)

def ensure_csv_header(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ts", "user_id", "trust_score", "network_score", "app_score", "resource", "action", "reason", "via_ziti"])

class EnhancedZeroTrustGateway:
    
    def __init__(self):
        self.suspicious_ips = set()
        self.user_behavior = {}
        
    def calculate_network_trust_score(self, user_id, request_context):
        """网络层信任分（OpenZiti相关）"""
        score = 50
        
        if request_context.get("via_ziti"):
            score += 30
            ZITI_CONNECTIONS.labels(status="authenticated").inc()
        else:
            ZITI_CONNECTIONS.labels(status="direct").inc()
            
        if request_context.get("ziti_identity"):
            score += 20
            
        return min(100, score)
    
    def calculate_app_trust_score(self, user_id, request_context):
        score = 100
        
        last_ip = redis_client.get(f"user:{user_id}:last_ip")
        current_ip = request_context.get("ip")
        if last_ip and last_ip != current_ip and current_ip != "ziti-network":
            score -= 20
            
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 23:
            score -= 15
            
        key_ac = f"user:{user_id}:access_count"
        access_count = redis_client.incr(key_ac)
        redis_client.expire(key_ac, 60)
        if access_count > 30:
            score -= 30
            
        if request_context.get("sensitive_operation"):
            score -= 10
            
        device_fingerprint = self._get_device_fingerprint(request_context)
        known_device = redis_client.sismember(f"user:{user_id}:devices", device_fingerprint)
        if not known_device:
            score -= 25
            redis_client.sadd(f"user:{user_id}:devices", device_fingerprint)
            
        redis_client.set(f"user:{user_id}:last_ip", current_ip)
        
        return max(0, min(100, score))
    
    def calculate_combined_trust_score(self, user_id, request_context):
        network_score = self.calculate_network_trust_score(user_id, request_context)
        app_score = self.calculate_app_trust_score(user_id, request_context)
        
        TRUST_SCORE.labels(layer="network").observe(network_score)
        TRUST_SCORE.labels(layer="application").observe(app_score)
        
        if USE_ZITI:
            combined_score = (network_score * 0.3 + app_score * 0.7)
        else:
            combined_score = app_score
            
        combined_score = int(combined_score)
        redis_client.set(f"user:{user_id}:trust_score", combined_score)
        TRUST_SCORE.labels(layer="combined").observe(combined_score)
        
        return combined_score, network_score, app_score
    
    def _get_device_fingerprint(self, context):
        raw = "|".join([
            context.get("user_agent", ""),
            context.get("accept_language", ""),
            context.get("platform", ""),
            context.get("timezone", ""),
        ])
        return hashlib.sha256(raw.encode()).hexdigest()
    
    def enforce_policy_with_layers(self, user_id, combined_score, network_score, app_score, resource):
        if combined_score >= 80:
            policy = {
                "action": "allow",
                "restrictions": None,
                "monitoring_level": "normal",
                "reason": "high_trust_both_layers" if network_score > 70 else "high_trust_app_layer",
            }
        elif combined_score >= 60:
            # 如果网络层分数高但应用层分数低，给予限制访问
            if network_score >= 80 and app_score < 60:
                reason = "network_trusted_app_suspicious"
            else:
                reason = "mid_risk_readonly"
                
            policy = {
                "action": "allow_restricted",
                "restrictions": ["read_only"],
                "monitoring_level": "enhanced",
                "reason": reason,
            }
        elif combined_score >= 40:
            policy = {
                "action": "require_mfa",
                "restrictions": ["minimal_access"],
                "monitoring_level": "strict",
                "reason": "low_trust_stepup_required",
            }
        else:
            policy = {
                "action": "deny",
                "restrictions": ["blocked"],
                "monitoring_level": "alert",
                "reason": "very_low_trust_blocked",
            }
            
        self._log_enhanced_decision(user_id, combined_score, network_score, app_score, resource, policy)
        return policy
    
    def _log_enhanced_decision(self, user_id, combined_score, network_score, app_score, resource, decision):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "trust_score": combined_score,
            "network_score": network_score,
            "app_score": app_score,
            "resource": resource,
            "decision": decision.get("action", ""),
            "reason": decision.get("reason", ""),
            "via_ziti": USE_ZITI,
        }
        redis_client.lpush("access_logs", json.dumps(entry))
        redis_client.ltrim("access_logs", 0, 999)

gateway = EnhancedZeroTrustGateway()

#路由
@app.route("/")
def index():
    mode = "OpenZiti Enhanced" if USE_ZITI else "Standard"
    return f"<h3>Zero-Trust Gateway ({mode} Mode)</h3>"

@app.route("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

@app.route("/healthz")
def healthz():
    try:
        redis_client.ping()
        status = {
            "status": "ok",
            "mode": "openziti" if USE_ZITI else "standard",
            "ziti_enabled": ziti_enabled
        }
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"status": "err", "error": str(e)}), 500

@app.route("/api/access-request", methods=["POST"])
def access_request():
    """增强版零信任访问请求"""
    started = time.time()
    ensure_csv_header(CSV_PATH)
    
    data = request.get_json(force=True, silent=True) or {}
    token = read_bearer_token(request, data.get("token"))
    
    if not token:
        return jsonify({"error": "需要认证令牌"}), 401
        
    try:
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
        "platform": data.get("platform", ""),
        "timezone": data.get("timezone", ""),
        # OpenZiti相关
        "via_ziti": request.headers.get("X-Via-Ziti", "false") == "true" or USE_ZITI,
        "ziti_identity": get_ziti_identity(request),
    }
    
    # 计算多层信任分
    combined_score, network_score, app_score = gateway.calculate_combined_trust_score(user_id, request_context)
    resource = data.get("resource", "/")
    policy = gateway.enforce_policy_with_layers(user_id, combined_score, network_score, app_score, resource)
    
    # 指标记录
    LATENCY.observe(time.time() - started)
    layer = "ziti" if USE_ZITI else "standard"
    DECISIONS.labels(policy["action"], policy.get("reason", "unknown"), layer).inc()
    
    # CSV记录
    try:
        with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                datetime.now().isoformat(), 
                user_id, 
                combined_score,
                network_score,
                app_score,
                resource, 
                policy["action"], 
                policy.get("reason", ""),
                USE_ZITI
            ])
    except Exception:
        pass
        
    response = {
        "user_id": user_id,
        "roles": roles,
        "trust_score": combined_score,
        "network_trust_score": network_score,
        "app_trust_score": app_score,
        "access_decision": policy["action"],
        "restrictions": policy.get("restrictions", []),
        "monitoring_level": policy["monitoring_level"],
        "reason": policy.get("reason", ""),
        "via_ziti": USE_ZITI,
        "timestamp": datetime.now().isoformat(),
    }
    
    # 返回码
    action = policy["action"]
    if action == "deny":
        code = 403
    elif action == "require_mfa":
        code = 428
    else:
        code = 200
        
    return jsonify(response), code

@app.route("/api/user-behavior/<user_id>", methods=["GET"])
def get_user_behavior(user_id):
    trust_score = redis_client.get(f"user:{user_id}:trust_score") or 100
    last_ip = redis_client.get(f"user:{user_id}:last_ip") or "unknown"
    access_count = redis_client.get(f"user:{user_id}:access_count") or 0
    
    devices = list(redis_client.smembers(f"user:{user_id}:devices"))
    
    return jsonify({
        "user_id": user_id,
        "current_trust_score": int(trust_score),
        "last_known_ip": last_ip,
        "recent_access_count": int(access_count),
        "known_devices": len(devices),
        "risk_level": "high" if int(trust_score) < 60 else "medium" if int(trust_score) < 80 else "low",
        "ziti_enabled": USE_ZITI
    })

@app.route("/api/simulate-ziti", methods=["POST"])
def simulate_ziti_connection():
    """模拟OpenZiti连接（测试用）"""
    data = request.get_json() or {}
    action = data.get("action", "connect")
    
    if action == "connect":
        request.headers.environ["X-Via-Ziti"] = "true"
        request.headers.environ["X-Openziti-Identity"] = "test-user@ziti"
        return jsonify({"message": "模拟OpenZiti连接成功", "identity": "test-user@ziti"})
    elif action == "disconnect":
        return jsonify({"message": "模拟断开OpenZiti连接"})
    else:
        return jsonify({"error": "未知操作"}), 400

if __name__ == "__main__":
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    port = 5001 if USE_ZITI else 5000
    mode = "OpenZiti增强" if USE_ZITI else "标准"
    
    print(f"🚀 零信任网关启动 ({mode}模式): http://localhost:{port}")
    print(f"   健康检查:      /healthz")
    print(f"   Prom指标:      /metrics")
    print(f"   OpenZiti:      {'✅ 已启用' if USE_ZITI else '❌ 未启用'}")
    
    app.run(host="0.0.0.0", port=port, debug=True)