#!/bin/bash
set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# 配置参数
KEYCLOAK_BASE="${KC_BASE:-http://localhost:8080}"
REALM="${KC_REALM:-my-company}"
CLIENT_ID="${KC_CLIENT_ID:-my-app}"
USERNAME="${KC_USERNAME:-alice}"
PASSWORD="${KC_PASSWORD:-alicepwd}"

STANDARD_GATEWAY="http://localhost:5000/api/access-request"
ZITI_SERVICE_URL="http://flask-gateway:7000/api/access-request"
ZITI_CLIENT_CONTAINER="ziti-client"
COUNT_PER_CASE="${COUNT:-10}"

# 获取 Keycloak Token
get_access_token() {
    echo -e "${YELLOW}1) 获取 Keycloak Token ...${NC}"
    
    TOKEN_URL="${KEYCLOAK_BASE}/realms/${REALM}/protocol/openid-connect/token"
    
    RESPONSE=$(curl -sS -X POST "${TOKEN_URL}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=${CLIENT_ID}" \
        -d "grant_type=password" \
        -d "username=${USERNAME}" \
        -d "password=${PASSWORD}")
    
    ACCESS_TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    
    if [ -z "$ACCESS_TOKEN" ]; then
        echo -e "${RED}❌ 无法获取 access_token${NC}"
        echo "$RESPONSE"
        exit 1
    fi
    
    echo -e "${GREEN}   ✅ 成功${NC}"
    echo "$ACCESS_TOKEN"
}

# 标准模式访问
invoke_standard_access() {
    local token=$1
    local resource=$2
    
    START=$(date +%s%3N)
    
    RESPONSE=$(curl -sS -w '\n%{http_code}' -X POST "${STANDARD_GATEWAY}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "{\"resource\": \"${resource}\"}")
    
    END=$(date +%s%3N)
    LATENCY=$((END - START))
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    JSON_RESPONSE=$(echo "$RESPONSE" | head -n-1)
    
    echo "${JSON_RESPONSE}" | jq -c ". + {mode: \"standard\", resource: \"${resource}\", status_code: ${HTTP_CODE}, latency_ms: ${LATENCY}}"
}

# Ziti 模式访问
invoke_ziti_access() {
    local token=$1
    local resource=$2
    local extra_headers=${3:-}
    
    HEADERS="-H 'Authorization: Bearer ${token}' -H 'Content-Type: application/json' -H 'X-Via-Ziti: true' -H 'X-Openziti-Identity: ${USERNAME}@openziti'"
    
    if [ -n "$extra_headers" ]; then
        HEADERS="$HEADERS $extra_headers"
    fi
    
    CMD="sh -c \"START=\\\$(date +%s%3N); curl -sS -w '\\n%{http_code}' ${HEADERS} ${ZITI_SERVICE_URL} -d '{\\\"resource\\\": \\\"${resource}\\\"}'; echo \\nLATENCY:\\\$((\\\$(date +%s%3N) - \\\$START))\""
    
    RESPONSE=$(docker exec ${ZITI_CLIENT_CONTAINER} sh -c "
        START=\$(date +%s%3N)
        curl -sS -w '\n%{http_code}' \
            -H 'Authorization: Bearer ${token}' \
            -H 'Content-Type: application/json' \
            -H 'X-Via-Ziti: true' \
            -H 'X-Openziti-Identity: ${USERNAME}@openziti' \
            ${ZITI_SERVICE_URL} \
            -d '{\"resource\": \"${resource}\"}'
        echo
        echo \"LATENCY:\$((\$(date +%s%3N) - \$START))\"
    ")
    
    HTTP_CODE=$(echo "$RESPONSE" | grep -E '^[0-9]{3}$' | tail -n1)
    LATENCY=$(echo "$RESPONSE" | grep "LATENCY:" | cut -d: -f2)
    JSON_RESPONSE=$(echo "$RESPONSE" | grep -v -E '^[0-9]{3}$|^LATENCY:')
    
    echo "${JSON_RESPONSE}" | jq -c ". + {mode: \"ziti\", resource: \"${resource}\", status_code: ${HTTP_CODE}, latency_ms: ${LATENCY}}"
}

# 打印统计
print_stats() {
    local title=$1
    local data=$2
    
    if [ -z "$data" ]; then
        echo -e "${YELLOW}[$title] 无数据${NC}"
        return
    fi
    
    local count=$(echo "$data" | wc -l)
    local allow_count=$(echo "$data" | jq -r '.access_decision' | grep -c "allow" || echo 0)
    local deny_count=$(echo "$data" | jq -r '.access_decision' | grep -c "deny" || echo 0)
    
    local avg_trust=$(echo "$data" | jq -s 'add/length | .trust_score' | cut -d. -f1)
    local avg_app=$(echo "$data" | jq -s 'add/length | .app_trust_score' | cut -d. -f1)
    local avg_net=$(echo "$data" | jq -s 'add/length | .network_trust_score' | cut -d. -f1)
    local avg_latency=$(echo "$data" | jq -s 'add/length | .latency_ms' | cut -d. -f1)
    
    echo -e "${CYAN}=== $title ===${NC}"
    echo "数量: $count, 允许: $allow_count, 拒绝: $deny_count"
    echo "平均信任: $avg_trust, 平均应用分: $avg_app, 平均网络分: $avg_net"
    echo "平均延迟(ms): $avg_latency"
    echo
}

# 主测试流程
main() {
    echo -e "${GREEN}==================================================="
    echo "零信任网关 —— 标准 vs Ziti 模式测试"
    echo -e "===================================================${NC}\n"
    
    # 获取 token
    TOKEN=$(get_access_token)
    
    # 收集测试数据
    STD_FINANCE=""
    STD_ADMIN=""
    ZITI_FINANCE=""
    ZITI_ADMIN=""
    
    echo -e "\n${YELLOW}[标准] /finance/report x ${COUNT_PER_CASE}${NC}"
    for i in $(seq 1 ${COUNT_PER_CASE}); do
        result=$(invoke_standard_access "$TOKEN" "/finance/report")
        STD_FINANCE="${STD_FINANCE}${result}\n"
        sleep 0.1
    done
    
    echo -e "\n${YELLOW}[标准] /admin/panel x ${COUNT_PER_CASE}${NC}"
    for i in $(seq 1 ${COUNT_PER_CASE}); do
        result=$(invoke_standard_access "$TOKEN" "/admin/panel")
        STD_ADMIN="${STD_ADMIN}${result}\n"
        sleep 0.1
    done
    
    echo -e "\n${YELLOW}[Ziti] /finance/report x ${COUNT_PER_CASE}${NC}"
    for i in $(seq 1 ${COUNT_PER_CASE}); do
        result=$(invoke_ziti_access "$TOKEN" "/finance/report")
        ZITI_FINANCE="${ZITI_FINANCE}${result}\n"
        sleep 0.1
    done
    
    echo -e "\n${YELLOW}[Ziti] /admin/panel x ${COUNT_PER_CASE}${NC}"
    for i in $(seq 1 ${COUNT_PER_CASE}); do
        result=$(invoke_ziti_access "$TOKEN" "/admin/panel")
        ZITI_ADMIN="${ZITI_ADMIN}${result}\n"
        sleep 0.1
    done
    
    echo -e "\n${MAGENTA}[攻击场景] 高频访问 /admin/panel (标准)${NC}"
    for i in $(seq 1 35); do
        invoke_standard_access "$TOKEN" "/admin/panel" > /dev/null
    done
    
    # 打印统计
    echo
    print_stats "标准 /finance/report" "$(echo -e "$STD_FINANCE")"
    print_stats "标准 /admin/panel" "$(echo -e "$STD_ADMIN")"
    print_stats "Ziti /finance/report" "$(echo -e "$ZITI_FINANCE")"
    print_stats "Ziti /admin/panel" "$(echo -e "$ZITI_ADMIN")"
    
    echo -e "${GREEN}测试完成！${NC}"
    echo -e "${CYAN}提示：${NC}"
    echo " - 决策明细已写入 CSV（查看 docker logs flask-gateway-ziti）"
    echo " - 访问 http://localhost:5001/metrics 查看 Prometheus 指标"
}

# 检查依赖
if ! command -v jq &> /dev/null; then
    echo -e "${RED}错误：需要安装 jq${NC}"
    echo "安装方法：apt-get install jq 或 brew install jq"
    exit 1
fi

# 运行主函数
main