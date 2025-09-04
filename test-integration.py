"""
集成测试脚本 - 测试所有组件是否正常工作
"""
import requests
import json
import time

def test_keycloak():
    """测试1: Keycloak是否运行"""
    print("\n🔍 测试 Keycloak...")
    try:
        # 获取Keycloak配置
        response = requests.get(
            "http://localhost:8080/realms/my-company/.well-known/openid-configuration"
        )
        if response.status_code == 200:
            print("✅ Keycloak正在运行")
            print("   - 领域 'my-company' 已配置")
            return True
        else:
            print("⚠️  Keycloak运行中，但领域未配置")
            print("   请按照说明创建 'my-company' 领域")
            return False
    except:
        print("❌ Keycloak未运行或无法访问")
        return False

def test_prometheus():
    """测试2: Prometheus是否运行"""
    print("\n🔍 测试 Prometheus...")
    try:
        response = requests.get("http://localhost:9090/-/healthy")
        if response.status_code == 200:
            print("✅ Prometheus正在运行")
            return True
    except:
        print("❌ Prometheus未运行")
        return False

def test_grafana():
    """测试3: Grafana是否运行"""
    print("\n🔍 测试 Grafana...")
    try:
        response = requests.get("http://localhost:3000/api/health")
        if response.status_code == 200:
            print("✅ Grafana正在运行")
            return True
    except:
        print("❌ Grafana未运行")
        return False

def get_keycloak_token():
    """测试4: 获取访问令牌"""
    print("\n🔍 测试用户登录...")
    
    # Keycloak token端点
    token_url = "http://localhost:8080/realms/my-company/protocol/openid-connect/token"
    
    # 使用客户端密钥（从Keycloak复制的）
    data = {
        'client_id': 'my-app',
        'client_secret': '5crfQLEILUsi1Wp6dHXlK16tIsiEg7iC',  # 👈 粘贴你的密钥
        'username': 'john',
        'password': 'password123',
        'grant_type': 'password'
    }
    
    try:
        response = requests.post(token_url, data=data)
        if response.status_code == 200:
            token_data = response.json()
            print("✅ 用户认证成功!")
            print(f"   - 用户: john")
            print(f"   - Token类型: {token_data['token_type']}")
            print(f"   - 有效期: {token_data['expires_in']}秒")
            return token_data['access_token']
        else:
            print(f"⚠️  认证失败 - 状态码: {response.status_code}")
            print(f"   响应: {response.text}")
            return None
    except Exception as e:
        print(f"❌ 无法连接到Keycloak: {e}")
        return None

def main():
    """运行所有测试"""
    print("="*50)
    print("🚀 零信任MVP集成测试")
    print("="*50)
    
    # 测试各个组件
    keycloak_ok = test_keycloak()
    prometheus_ok = test_prometheus()
    grafana_ok = test_grafana()
    
    # 如果Keycloak配置正确，测试认证
    if keycloak_ok:
        token = get_keycloak_token()
        if token:
            print("\n🎉 恭喜！基础MVP已经搭建完成！")
            print("\n下一步可以：")
            print("1. 在Grafana中创建监控面板")
            print("2. 添加OpenZiti进行网络隔离")
            print("3. 集成异常检测模块")
    
    print("\n" + "="*50)
    print("📊 测试结果汇总：")
    print(f"  Keycloak: {'✅' if keycloak_ok else '❌'}")
    print(f"  Prometheus: {'✅' if prometheus_ok else '❌'}")
    print(f"  Grafana: {'✅' if grafana_ok else '❌'}")
    print("="*50)

if __name__ == "__main__":
    # 先安装requests: pip install requests
    main()