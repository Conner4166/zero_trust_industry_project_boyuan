"""
OpenZiti增强版网关测试脚本
对比测试：
1. 标准模式访问（直接HTTP）
2. OpenZiti模式访问（通过安全隧道）
"""

import os
import time
import json
import requests
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt

# 配置
KC_BASE = os.getenv("KC_BASE", "http://localhost:8080")
REALM = os.getenv("KC_REALM", "my-company")
CLIENT_ID = os.getenv("KC_CLIENT_ID", "my-app")
USERNAME = os.getenv("KC_USERNAME", "alice")
PASSWORD = os.getenv("KC_PASSWORD", "alicepwd")

# 两个网关地址
STANDARD_GATEWAY = "http://localhost:5000/api/access-request"
ZITI_GATEWAY = "http://localhost:5001/api/access-request"

class ZitiTester:
    def __init__(self):
        self.token = None
        self.results = {
            "standard": [],
            "ziti": []
        }
        
    def get_token(self):
        """从Keycloak获取token"""
        url = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/token"
        data = {
            "client_id": CLIENT_ID,
            "grant_type": "password",
            "username": USERNAME,
            "password": PASSWORD,
        }
        r = requests.post(url, data=data, timeout=15)
        r.raise_for_status()
        self.token = r.json()["access_token"]
        print(f"✅ 获取Token成功")
        return self.token
    
    def test_standard_mode(self, resource="/finance/report", count=10):
        """测试标准模式"""
        print(f"\n📊 测试标准模式 - {resource}")
        headers = {"Authorization": f"Bearer {self.token}"}
        
        for i in range(count):
            body = {"resource": resource}
            t0 = time.perf_counter()
            
            try:
                resp = requests.post(STANDARD_GATEWAY, headers=headers, json=body, timeout=10)
                latency_ms = int((time.perf_counter() - t0) * 1000)
                
                data = resp.json()
                self.results["standard"].append({
                    "timestamp": datetime.now().isoformat(),
                    "resource": resource,
                    "trust_score": data.get("trust_score", 0),
                    "app_score": data.get("app_trust_score", 0),
                    "network_score": data.get("network_trust_score", 0),
                    "decision": data.get("access_decision", ""),
                    "reason": data.get("reason", ""),
                    "latency_ms": latency_ms,
                    "status_code": resp.status_code
                })
                
                print(f"  [{i+1}/{count}] Trust: {data.get('trust_score')} | Decision: {data.get('access_decision')} | Latency: {latency_ms}ms")
                
            except Exception as e:
                print(f"  ❌ Error: {e}")
                
            if i < count - 1:
                time.sleep(0.1)
    
    def test_ziti_mode(self, resource="/finance/report", count=10):
        """测试OpenZiti模式"""
        print(f"\n🔐 测试OpenZiti模式 - {resource}")
        
        # 模拟通过OpenZiti连接
        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Via-Ziti": "true",
            "X-Openziti-Identity": f"{USERNAME}@openziti"
        }
        
        for i in range(count):
            body = {"resource": resource}
            t0 = time.perf_counter()
            
            try:
                resp = requests.post(ZITI_GATEWAY, headers=headers, json=body, timeout=10)
                latency_ms = int((time.perf_counter() - t0) * 1000)
                
                data = resp.json()
                self.results["ziti"].append({
                    "timestamp": datetime.now().isoformat(),
                    "resource": resource,
                    "trust_score": data.get("trust_score", 0),
                    "app_score": data.get("app_trust_score", 0),
                    "network_score": data.get("network_trust_score", 0),
                    "decision": data.get("access_decision", ""),
                    "reason": data.get("reason", ""),
                    "latency_ms": latency_ms,
                    "status_code": resp.status_code
                })
                
                print(f"  [{i+1}/{count}] Trust: {data.get('trust_score')} (Net: {data.get('network_trust_score')}, App: {data.get('app_trust_score')}) | Decision: {data.get('access_decision')} | Latency: {latency_ms}ms")
                
            except Exception as e:
                print(f"  ❌ Error: {e}")
                
            if i < count - 1:
                time.sleep(0.1)
    
    def test_attack_scenarios(self):
        """测试攻击场景"""
        print(f"\n⚔️ 测试攻击场景")
        
        scenarios = [
            {
                "name": "正常访问",
                "headers": {"Authorization": f"Bearer {self.token}"},
                "resource": "/finance/report"
            },
            {
                "name": "高频访问（DDoS模拟）",
                "headers": {"Authorization": f"Bearer {self.token}"},
                "resource": "/admin/panel",
                "rapid": True
            },
            {
                "name": "设备变更（新User-Agent）",
                "headers": {
                    "Authorization": f"Bearer {self.token}",
                    "User-Agent": "Suspicious-Bot/1.0"
                },
                "resource": "/admin/panel"
            },
            {
                "name": "通过OpenZiti的可疑访问",
                "headers": {
                    "Authorization": f"Bearer {self.token}",
                    "X-Via-Ziti": "true",
                    "X-Openziti-Identity": "suspicious@ziti",
                    "User-Agent": "Suspicious-Bot/1.0"
                },
                "resource": "/admin/panel"
            }
        ]
        
        for scenario in scenarios:
            print(f"\n  🎯 {scenario['name']}")
            
            # 测试标准网关
            if scenario.get("rapid"):
                # 快速发送多个请求
                for _ in range(35):
                    resp = requests.post(
                        STANDARD_GATEWAY,
                        headers=scenario["headers"],
                        json={"resource": scenario["resource"]},
                        timeout=5
                    )
            else:
                resp = requests.post(
                    STANDARD_GATEWAY,
                    headers=scenario["headers"],
                    json={"resource": scenario["resource"]},
                    timeout=10
                )
            
            std_data = resp.json() if resp.status_code != 403 else {"access_decision": "deny"}
            print(f"    标准模式: Trust={std_data.get('trust_score', 'N/A')} Decision={std_data.get('access_decision')}")
            
            # 测试OpenZiti网关
            if "X-Via-Ziti" in scenario.get("headers", {}):
                resp = requests.post(
                    ZITI_GATEWAY,
                    headers=scenario["headers"],
                    json={"resource": scenario["resource"]},
                    timeout=10
                )
                ziti_data = resp.json() if resp.status_code != 403 else {"access_decision": "deny"}
                print(f"    Ziti模式: Trust={ziti_data.get('trust_score', 'N/A')} (Net={ziti_data.get('network_trust_score', 'N/A')}, App={ziti_data.get('app_trust_score', 'N/A')}) Decision={ziti_data.get('access_decision')}")
    
    def generate_report(self):
        """生成对比报告"""
        print(f"\n📈 生成对比报告")
        
        # 创建输出目录
        os.makedirs("out/reports", exist_ok=True)
        
        # 转换为DataFrame
        df_standard = pd.DataFrame(self.results["standard"])
        df_ziti = pd.DataFrame(self.results["ziti"])
        
        if not df_standard.empty and not df_ziti.empty:
            # 统计分析
            stats = {
                "Standard Mode": {
                    "Avg Trust Score": df_standard["trust_score"].mean(),
                    "Avg Latency (ms)": df_standard["latency_ms"].mean(),
                    "Allow Rate": (df_standard["decision"] == "allow").mean() * 100,
                    "Deny Rate": (df_standard["decision"] == "deny").mean() * 100
                },
                "OpenZiti Mode": {
                    "Avg Trust Score": df_ziti["trust_score"].mean(),
                    "Avg Network Score": df_ziti["network_score"].mean(),
                    "Avg App Score": df_ziti["app_score"].mean(),
                    "Avg Latency (ms)": df_ziti["latency_ms"].mean(),
                    "Allow Rate": (df_ziti["decision"] == "allow").mean() * 100,
                    "Deny Rate": (df_ziti["decision"] == "deny").mean() * 100
                }
            }
            
            # 保存统计结果
            with open("out/reports/ziti_comparison.json", "w") as f:
                json.dump(stats, f, indent=2)
            
            # 打印统计结果
            print("\n📊 统计结果:")
            for mode, data in stats.items():
                print(f"\n  {mode}:")
                for key, value in data.items():
                    print(f"    {key}: {value:.2f}")
            
            # 生成可视化（如果可能）
            try:
                fig, axes = plt.subplots(2, 2, figsize=(12, 8))
                
                # 信任分对比
                axes[0, 0].bar(["Standard", "OpenZiti"], 
                             [stats["Standard Mode"]["Avg Trust Score"], 
                              stats["OpenZiti Mode"]["Avg Trust Score"]])
                axes[0, 0].set_title("Average Trust Score")
                axes[0, 0].set_ylabel("Score")
                
                # 延迟对比
                axes[0, 1].bar(["Standard", "OpenZiti"],
                             [stats["Standard Mode"]["Avg Latency (ms)"],
                              stats["OpenZiti Mode"]["Avg Latency (ms)"]])
                axes[0, 1].set_title("Average Latency")
                axes[0, 1].set_ylabel("Milliseconds")
                
                # 决策分布 - Standard
                axes[1, 0].pie([stats["Standard Mode"]["Allow Rate"],
                              stats["Standard Mode"]["Deny Rate"]],
                             labels=["Allow", "Deny"],
                             autopct='%1.1f%%')
                axes[1, 0].set_title("Standard Mode Decisions")
                
                # 决策分布 - OpenZiti
                axes[1, 1].pie([stats["OpenZiti Mode"]["Allow Rate"],
                              stats["OpenZiti Mode"]["Deny Rate"]],
                             labels=["Allow", "Deny"],
                             autopct='%1.1f%%')
                axes[1, 1].set_title("OpenZiti Mode Decisions")
                
                plt.suptitle("Zero Trust Gateway - OpenZiti Integration Comparison")
                plt.tight_layout()
                plt.savefig("out/reports/ziti_comparison.png")
                print("\n✅ 报告已保存到 out/reports/")
                
            except Exception as e:
                print(f"\n⚠️ 无法生成图表: {e}")
        else:
            print("\n⚠️ 数据不足，无法生成报告")

def main():
    print("=" * 60)
    print("零信任网关 - OpenZiti集成测试")
    print("=" * 60)
    
    tester = ZitiTester()
    
    # 1. 获取Token
    tester.get_token()
    
    # 2. 测试标准模式
    tester.test_standard_mode("/finance/report", 10)
    tester.test_standard_mode("/admin/panel", 10)
    
    # 3. 测试OpenZiti模式
    tester.test_ziti_mode("/finance/report", 10)
    tester.test_ziti_mode("/admin/panel", 10)
    
    # 4. 测试攻击场景
    tester.test_attack_scenarios()
    
    # 5. 生成报告
    tester.generate_report()
    
    print("\n" + "=" * 60)
    print("测试完成！")
    print("=" * 60)

if __name__ == "__main__":
    main()