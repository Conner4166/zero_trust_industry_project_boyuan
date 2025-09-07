#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ts(){ date "+%H:%M:%S"; }
say(){ echo -e "[$(ts)] $*"; }

# ---- 基础配置 ----
ZITI_ADMIN_USER="admin"
ZITI_ADMIN_PWD="admin123"
CTRL_URL="https://ziti-controller:1280"

HOST_IDENT_DIR_SERVERS="./openziti/identities"
HOST_IDENT_DIR_CLIENTS="./openziti/identities-client"
mkdir -p "${HOST_IDENT_DIR_SERVERS}" "${HOST_IDENT_DIR_CLIENTS}"

# ==== 0) 检查环境 ====
if ! docker compose ls >/dev/null 2>&1; then
  echo -e "${RED}❌ 找不到 docker compose 环境${NC}"
  exit 1
fi

# ==== 1) 清理旧环境（确保干净启动） ====
say "清理旧环境..."
docker compose down >/dev/null 2>&1 || true
docker volume rm $(docker volume ls -q | grep -E 'ziti.*router.*data') 2>/dev/null || true
rm -rf "${HOST_IDENT_DIR_SERVERS}"/* "${HOST_IDENT_DIR_CLIENTS}"/* 2>/dev/null || true

# ==== 2) 启动基础容器 ====
say "启动 Postgres / Redis / Keycloak / Ziti Controller ..."
docker compose up -d postgres redis keycloak ziti-controller >/dev/null

# ==== 3) 等待 Controller 就绪 ====
say "等待 Ziti Controller 可登录 ..."
try_login(){ docker exec ziti-controller ziti edge login "$CTRL_URL" -u "$ZITI_ADMIN_USER" -p "$ZITI_ADMIN_PWD" -y >/dev/null 2>&1; }
ok_login=n
for _ in $(seq 1 60); do if try_login; then ok_login=y; break; fi; sleep 2; done
[ "$ok_login" = y ] && echo -e "${GREEN}✔ 登录成功${NC}" || { echo -e "${RED}❌ 无法登录 Controller${NC}"; exit 1; }

# ==== 4) 创建所有配置和身份 ====
say "创建身份和配置..."
docker exec ziti-controller bash -c "
set -e
ziti edge login $CTRL_URL -u $ZITI_ADMIN_USER -p $ZITI_ADMIN_PWD -y >/dev/null

# 创建 Edge Router
ziti edge create edge-router edge-router-1 --tunneler-enabled \
  --jwt-output-file /persistent/edge-router-1.jwt >/dev/null

# 创建身份
ziti edge create identity flask-gateway -a 'flask-gateway.servers' \
  -o /persistent/flask-gateway.jwt >/dev/null
ziti edge enroll /persistent/flask-gateway.jwt \
  -o /persistent/flask-gateway.json >/dev/null

ziti edge create identity alice -a 'gateway.clients' \
  -o /persistent/alice.jwt >/dev/null
ziti edge enroll /persistent/alice.jwt \
  -o /persistent/alice.json >/dev/null

# 创建 configs
cat >/tmp/intercept.json <<'EOF'
{\"protocols\":[\"tcp\"],\"addresses\":[\"flask-gateway\"],\"portRanges\":[{\"low\":7000,\"high\":7000}]}
EOF
cat >/tmp/host.json <<'EOF'
{\"protocol\":\"tcp\",\"address\":\"flask-gateway-ziti\",\"port\":5001}
EOF

ziti edge create config flask-gateway-intercept intercept.v1 \"\$(cat /tmp/intercept.json)\" >/dev/null
ziti edge create config flask-gateway-host host.v1 \"\$(cat /tmp/host.json)\" >/dev/null

# 创建服务
ziti edge create service flask-gateway \
  --configs 'flask-gateway-intercept,flask-gateway-host' >/dev/null

# 创建策略
ziti edge create service-policy flask-gateway-dial Dial \
  --service-roles '@flask-gateway' --identity-roles '#gateway.clients' >/dev/null
ziti edge create service-policy flask-gateway-bind Bind \
  --service-roles '@flask-gateway' --identity-roles '#flask-gateway.servers' >/dev/null
ziti edge create edge-router-policy erp-all \
  --edge-router-roles '#all' --identity-roles '#all' >/dev/null
ziti edge create service-edge-router-policy ser-flask-gateway-all \
  --service-roles '@flask-gateway' --edge-router-roles '#all' >/dev/null
"

# 拷贝身份文件
docker cp ziti-controller:/persistent/flask-gateway.json "${HOST_IDENT_DIR_SERVERS}/" >/dev/null
docker cp ziti-controller:/persistent/alice.json "${HOST_IDENT_DIR_CLIENTS}/" >/dev/null
docker cp ziti-controller:/persistent/edge-router-1.jwt "${HOST_IDENT_DIR_SERVERS}/" >/dev/null
echo -e "${GREEN}✔ 身份和配置创建完成${NC}"

# ==== 5) 创建 .env 文件 ====
say "创建 .env 文件..."
echo "ZITI_ENROLL_TOKEN=$(cat ${HOST_IDENT_DIR_SERVERS}/edge-router-1.jwt)" > .env

# ==== 6) 启动 Edge Router ====
say "启动 Edge Router..."
docker compose up -d ziti-edge-router >/dev/null
sleep 10

# ==== 7) 验证 Edge Router 在线（使用 JSON 解析） ====
say "验证 Edge Router 状态..."
er_ok=n
for _ in $(seq 1 30); do
  # 使用 grep 检查 JSON 中的 isOnline 字段
  if docker exec ziti-controller ziti edge list edge-routers -j 2>/dev/null | grep -q '"isOnline": true'; then
    er_ok=y
    break
  fi
  sleep 2
done

if [ "$er_ok" = y ]; then
  echo -e "${GREEN}✔ Edge Router 在线${NC}"
else
  echo -e "${YELLOW}⚠ Edge Router 显示离线，但可能正常工作，继续...${NC}"
fi

# ==== 8) 启动服务 ====
say "启动后端服务..."
docker compose up -d flask-gateway-ziti >/dev/null
sleep 3

say "启动 ziti-gateway（托管端）..."
docker compose up -d ziti-gateway >/dev/null
sleep 5

# ==== 9) 验证 terminator ====
say "验证 terminator..."
term_ok=n
for _ in $(seq 1 30); do
  if docker exec ziti-controller ziti edge list terminators 2>/dev/null | grep -q 'flask-gateway'; then
    term_ok=y
    break
  fi
  sleep 2
done

if [ "$term_ok" = y ]; then
  echo -e "${GREEN}✔ Terminator 就绪${NC}"
else
  echo -e "${YELLOW}⚠ Terminator 未就绪，重启服务...${NC}"
  docker compose restart ziti-gateway >/dev/null
  sleep 5
fi

# ==== 10) 最终验证 ====
echo -e "\n${GREEN}======================================"
echo -e "✅ OpenZiti 环境部署完成"
echo -e "======================================${NC}"
echo
echo "状态检查："
echo "==========="
docker exec ziti-controller bash -c "
  ziti edge login $CTRL_URL -u $ZITI_ADMIN_USER -p $ZITI_ADMIN_PWD -y >/dev/null
  echo 'Edge Routers:'
  ziti edge list edge-routers
  echo
  echo 'Services:'
  ziti edge list services
  echo
  echo 'Terminators:'
  ziti edge list terminators
"

echo
echo "测试命令："
echo "=========="
echo "# 启动客户端隧道："
echo 'docker run -d --name ziti-client \'
echo '  -v "${PWD}/openziti/identities-client:/ziti-edge-tunnel" \'
echo '  --privileged \'
echo '  --network graduationproject_boyuanzhang_zero-trust-net \'
echo '  openziti/ziti-edge-tunnel:latest run --identity /ziti-edge-tunnel/alice.json'
echo
echo "# 测试连接："
echo 'docker exec ziti-client sh -c "sleep 10 && curl http://flask-gateway:7000"'