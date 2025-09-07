#!/bin/bash
set -euo pipefail

echo "修复 Edge Router..."

# 1. 停止 Edge Router
docker compose stop ziti-edge-router
docker compose rm -f ziti-edge-router

# 2. 清理 Edge Router 数据卷
docker volume rm zero-trust-gateway_ziti_router_data 2>/dev/null || true

# 3. 获取 Edge Router JWT
echo "获取 Edge Router JWT..."
docker exec ziti-controller bash -c '
  ziti edge login https://ziti-controller:1280 -u admin -p admin123 -y
  
  # 重新生成 JWT（如果 Edge Router 已存在）
  if ziti edge list edge-routers | grep -q edge-router-1; then
    echo "Edge Router 已存在，重新生成 enrollment token..."
    ziti edge re-enroll edge-router edge-router-1 --jwt-output-file /persistent/edge-router-1.jwt
  else
    echo "创建新的 Edge Router..."
    ziti edge create edge-router edge-router-1 \
      --tunneler-enabled \
      --jwt-output-file /persistent/edge-router-1.jwt
  fi
'

# 4. 拷贝 JWT 到宿主机
docker cp ziti-controller:/persistent/edge-router-1.jwt ./openziti/identities/

# 5. 读取 JWT 内容作为环境变量
export ZITI_ROUTER_TOKEN=$(cat ./openziti/identities/edge-router-1.jwt)

# 6. 使用环境变量启动 Edge Router
echo "启动 Edge Router（使用 JWT token）..."
ZITI_ROUTER_TOKEN=$ZITI_ROUTER_TOKEN docker compose up -d ziti-edge-router

# 7. 等待 Edge Router 启动
echo "等待 Edge Router 启动..."
sleep 15

# 8. 检查状态
echo "检查 Edge Router 状态..."
docker exec ziti-controller ziti edge list edge-routers

# 9. 如果仍然离线，尝试手动 enroll
if ! docker exec ziti-controller ziti edge list edge-routers | grep -q "true"; then
    echo "Edge Router 仍然离线，尝试手动 enroll..."
    
    # 进入容器手动 enroll
    docker exec ziti-edge-router bash -c '
        # 查找 JWT 文件
        JWT_FILE=""
        if [ -f "/var/openziti/edge-router-1.jwt" ]; then
            JWT_FILE="/var/openziti/edge-router-1.jwt"
        elif [ -f "/persistent/edge-router-1.jwt" ]; then
            JWT_FILE="/persistent/edge-router-1.jwt"
        elif [ ! -z "$ZITI_ENROLL_TOKEN" ]; then
            echo "$ZITI_ENROLL_TOKEN" > /tmp/router.jwt
            JWT_FILE="/tmp/router.jwt"
        fi
        
        if [ ! -z "$JWT_FILE" ] && [ -f "$JWT_FILE" ]; then
            echo "使用 JWT: $JWT_FILE"
            ziti router enroll "$JWT_FILE" --engine openssl
        else
            echo "错误：找不到 JWT 文件"
            exit 1
        fi
    '
    
    # 重启 Edge Router
    docker compose restart ziti-edge-router
    sleep 10
fi

# 10. 最终验证
echo "===== 最终状态 ====="
echo "Edge Routers:"
docker exec ziti-controller ziti edge list edge-routers

echo -e "\nTerminators:"
docker exec ziti-controller ziti edge list terminators

echo -e "\n如果 Edge Router 仍然离线，查看详细日志："
echo "docker exec ziti-edge-router cat /tmp/tmp.*.txt | tail -50"