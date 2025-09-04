"""
零信任安全网关 - 核心业务逻辑
"""
from flask import Flask, request, jsonify, render_template
from functools import wraps
import jwt
import json
from datetime import datetime
import redis
import hashlib

app = Flask(__name__)

# Redis连接
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

# 配置
KEYCLOAK_URL = "http://localhost:8080"
REALM = "my-company"
CLIENT_ID = "my-app"
RISK_THRESHOLD = 70

class ZeroTrustGateway:
    """零信任网关核心类"""
    
    def __init__(self):
        self.suspicious_ips = set()
        self.user_behavior = {}
        
    def calculate_trust_score(self, user_id, request_context):
        """计算用户信任分数"""
        score = 100
        
        # 1. IP地址变化检查
        last_ip = redis_client.get(f"user:{user_id}:last_ip")
        current_ip = request_context['ip']
        
        if last_ip and last_ip != current_ip:
            score -= 20
            print(f"⚠️ IP变化: {last_ip} -> {current_ip}")
        
        # 2. 时间异常检查
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 23:
            score -= 15
            print(f"⚠️ 异常时间: {current_hour}点")
        
        # 3. 访问频率检查
        access_count = redis_client.incr(f"user:{user_id}:access_count")
        redis_client.expire(f"user:{user_id}:access_count", 60)
        
        if access_count > 30:
            score -= 30
            print(f"⚠️ 高频访问: {access_count}次/分钟")
        
        # 4. 敏感操作检查
        if request_context.get('sensitive_operation'):
            score -= 10
        
        # 5. 设备指纹检查
        device_fingerprint = self._get_device_fingerprint(request_context)
        known_device = redis_client.sismember(f"user:{user_id}:devices", device_fingerprint)
        
        if not known_device:
            score -= 25
            print(f"⚠️ 未知设备: {device_fingerprint[:8]}")
        
        # 保存状态
        redis_client.set(f"user:{user_id}:last_ip", current_ip)
        redis_client.set(f"user:{user_id}:trust_score", score)
        
        return max(0, score)
    
    def _get_device_fingerprint(self, context):
        """生成设备指纹"""
        data = f"{context.get('user_agent', '')}|{context.get('accept_language', '')}"
        return hashlib.md5(data.encode()).hexdigest()
    
    def enforce_zero_trust_policy(self, user_id, trust_score, resource):
        """执行零信任策略"""
        if trust_score >= 80:
            policy = {'action': 'allow', 'restrictions': None, 'monitoring_level': 'normal'}
        elif trust_score >= 60:
            policy = {'action': 'allow_restricted', 'restrictions': ['read_only'], 'monitoring_level': 'enhanced'}
        elif trust_score >= 40:
            policy = {'action': 'require_mfa', 'restrictions': ['minimal_access'], 'monitoring_level': 'strict'}
        else:
            policy = {'action': 'deny', 'restrictions': ['blocked'], 'monitoring_level': 'alert'}
        
        # 记录决策
        self._log_access_decision(user_id, trust_score, resource, policy)
        return policy
    
    def _log_access_decision(self, user_id, trust_score, resource, decision):
        """记录访问决策"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'trust_score': trust_score,
            'resource': resource,
            'decision': decision['action']
        }
        redis_client.lpush('access_logs', json.dumps(log_entry))
        redis_client.ltrim('access_logs', 0, 999)

gateway = ZeroTrustGateway()

def verify_token(f):
    """JWT令牌验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': '未提供认证令牌'}), 401
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            request.user = payload
            return f(*args, **kwargs)
        except:
            return jsonify({'error': '令牌无效'}), 401
    return decorated_function

# ========== 路由 ==========

@app.route('/')
def index():
    """主页"""
    return render_template('index.html')

@app.route('/api/access-request', methods=['POST'])
def access_request():
    """零信任访问请求"""
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': '需要认证令牌'}), 401
    
    try:
        user_info = jwt.decode(token, options={"verify_signature": False})
        user_id = user_info.get('preferred_username', 'unknown')
    except:
        return jsonify({'error': '令牌无效'}), 401
    
    request_context = {
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'accept_language': request.headers.get('Accept-Language', ''),
        'sensitive_operation': data.get('resource', '').startswith('/admin')
    }
    
    trust_score = gateway.calculate_trust_score(user_id, request_context)
    resource = data.get('resource', '/')
    policy = gateway.enforce_zero_trust_policy(user_id, trust_score, resource)
    
    response = {
        'user_id': user_id,
        'trust_score': trust_score,
        'access_decision': policy['action'],
        'restrictions': policy.get('restrictions', []),
        'monitoring_level': policy['monitoring_level'],
        'timestamp': datetime.now().isoformat()
    }
    
    status_code = 403 if policy['action'] == 'deny' else 428 if policy['action'] == 'require_mfa' else 200
    return jsonify(response), status_code

@app.route('/api/user-behavior/<user_id>', methods=['GET'])
@verify_token
def get_user_behavior(user_id):
    """获取用户行为分析"""
    trust_score = redis_client.get(f"user:{user_id}:trust_score") or 100
    last_ip = redis_client.get(f"user:{user_id}:last_ip") or "unknown"
    access_count = redis_client.get(f"user:{user_id}:access_count") or 0
    
    return jsonify({
        'user_id': user_id,
        'current_trust_score': int(trust_score),
        'last_known_ip': last_ip,
        'recent_access_count': int(access_count),
        'risk_level': 'high' if int(trust_score) < 60 else 'medium' if int(trust_score) < 80 else 'low'
    })

@app.route('/api/simulate-attack', methods=['POST'])
def simulate_attack():
    """模拟攻击场景"""
    attack_type = request.json.get('type', 'brute_force')
    
    if attack_type == 'location_change':
        gateway.calculate_trust_score('john', {
            'ip': '203.0.113.0',
            'user_agent': request.headers.get('User-Agent'),
            'accept_language': 'zh-CN'
        })
    
    return jsonify({'message': f'已模拟 {attack_type} 攻击'})

if __name__ == '__main__':
    print("🚀 零信任网关启动在 http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)