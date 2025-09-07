#!/usr/bin/env bash
set -euo pipefail

# ====== 美化 & 小工具 ======
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ts(){ date "+%H:%M:%S"; }
say(){ echo -e "[$(ts)] $*"; }

# ====== 与 docker-compose.yml 一致的基础配置 ======
ZITI_ADMIN_USER="admin"
ZITI_ADMIN_PWD="admin123"
CTRL_URL="https://ziti-controller:1280"              # 用容器名访问，避免宿主 TLS 信任问题

# 身份目录（区分服务端与客户端）
HOST_IDENT_DIR_SERVERS="./openziti/identities"
HOST_IDENT_DIR_CLIENTS="./openziti/identities-client"
mkdir -p "${HOST_IDENT_DIR_SERVERS}" "${HOST_IDENT_DIR_CLIENTS}"

# ====== 1) 起基础容器 ======
say "启动 Postgres / Redis / Keycloak / Ziti Controller ..."
docker compose up -d postgres redis keycloak ziti-controller >/dev/null

# ====== 2) 等 Controller 可登录 ======
say "等待 Ziti Controller 可登录 ..."
try_login(){ docker exec ziti-controller ziti edge login "$CTRL_URL" -u "$ZITI_ADMIN_USER" -p "$ZITI_ADMIN_PWD" -y >/dev/null 2>&1; }
ok_login=n
for _ in $(seq 1 120); do if try_login; then ok_login=y; break; fi; sleep 2; done
if [ "$ok_login" != y ]; then
  echo -e "${RED}❌ 无法登录 Controller。建议先查看：docker logs ziti-controller --tail=200${NC}"
  exit 1
fi
echo -e "${GREEN}✔ 登录成功${NC}"

# ====== 3) 幂等创建/准备两份身份：flask-gateway(服务器) / alice(客户端) ======
say "创建/准备身份（flask-gateway / alice）..."
docker exec ziti-controller ziti edge login "$CTRL_URL" -u "$ZITI_ADMIN_USER" -p "$ZITI_ADMIN_PWD" -y >/dev/null

ensure_identity_json(){
  local NAME="$1" ATTR="$2" COPY_TO_DIR="$3"
  local JWT="/persistent/${NAME}.jwt"
  local JSON="/persistent/${NAME}.json"

  # 先尝试 generate identity-token（可能输出 {"token":"..."}）
  if docker exec ziti-controller sh -lc "ziti edge generate identity-token ${NAME} > ${JWT} 2>/dev/null"; then
    docker exec ziti-controller sh -lc '
      f="'"${JWT}"'"; if grep -q "\"token\"" "$f" 2>/dev/null; then
        if command -v jq >/dev/null 2>&1; then tok=$(jq -r .token "$f"); else tok=$(sed -n '\''s/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'\'' "$f"|head -n1); fi
        [ -n "$tok" ] && printf "%s" "$tok" > "$f"
      fi'
    # 如果不是裸 JWT（三段），回退到 create -o 生成
    if ! docker exec ziti-controller sh -lc "grep -Eq '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' ${JWT}"; then
      docker exec ziti-controller ziti edge delete identity "${NAME}" >/dev/null 2>&1 || true
      docker exec ziti-controller ziti edge create identity "${NAME}" -a "${ATTR}" -o "${JWT}"
    fi
  else
    # 老版本 CLI：直接 create identity -o 产 JWT
    docker exec ziti-controller ziti edge delete identity "${NAME}" >/dev/null 2>&1 || true
    docker exec ziti-controller ziti edge create identity "${NAME}" -a "${ATTR}" -o "${JWT}"
  fi

  docker exec ziti-controller ziti edge enroll "${JWT}" -o "${JSON}"
  docker cp "ziti-controller:${JSON}" "${COPY_TO_DIR}/${NAME}.json" >/dev/null
  echo "    ✔ ${NAME}.json -> ${COPY_TO_DIR}/"
}
# 服务器身份 -> identities
ensure_identity_json "flask-gateway" "flask-gateway.servers" "${HOST_IDENT_DIR_SERVERS}"
# 客户端身份 -> identities-client
ensure_identity_json "alice"         "gateway.clients"        "${HOST_IDENT_DIR_CLIENTS}"

echo -e "${GREEN}✔ 身份 JSON 就绪：${HOST_IDENT_DIR_SERVERS}/flask-gateway.json, ${HOST_IDENT_DIR_CLIENTS}/alice.json${NC}"

# ====== 4) 在 Controller 内：创建 configs / service / 策略（幂等） ======
say "在 Controller 内创建 configs / service / 策略（幂等）..."
docker exec -i ziti-controller bash <<'IN_CTR'
set -euo pipefail
ziti edge login https://ziti-controller:1280 -u admin -p admin123 -y >/dev/null

# 生成干净 JSON（LF、无 BOM）
cat >/tmp/intercept.json <<'JSON'
{"protocols":["tcp"],"addresses":["flask-gateway"],"portRanges":[{"low":7000,"high":7000}]}
JSON
cat >/tmp/host.json <<'JSON'
{"protocol":"tcp","address":"flask-gateway-ziti","port":5001,"listenOptions":{"bindUsingEdgeIdentity":true}}
JSON

# 清理旧对象
ziti edge delete service flask-gateway 2>/dev/null || true
ziti edge delete config  flask-gateway-intercept 2>/dev/null || true
ziti edge delete config  flask-gateway-host      2>/dev/null || true
ziti edge delete service-policy flask-gateway-dial 2>/dev/null || true
ziti edge delete service-policy flask-gateway-bind 2>/dev/null || true
ziti edge delete service-edge-router-policy ser-flask-gateway-all 2>/dev/null || true
ziti edge delete edge-router-policy erp-all 2>/dev/null || true

# 创建 config + service
ziti edge create config flask-gateway-intercept intercept.v1 "$(cat /tmp/intercept.json)"
ziti edge create config flask-gateway-host      host.v1      "$(cat /tmp/host.json)"
ziti edge create service flask-gateway --configs "flask-gateway-intercept,flask-gateway-host"

# 创建 Service Policies（新版需 --semantic AnyOf）
ziti edge create service-policy flask-gateway-dial Dial \
  --semantic AnyOf --service-roles "@flask-gateway" --identity-roles "#gateway.clients"

ziti edge create service-policy flask-gateway-bind Bind \
  --semantic AnyOf --service-roles "@flask-gateway" --identity-roles "#flask-gateway.servers"

# 服务映射到所有 ER（SERP）
ziti edge create service-edge-router-policy ser-flask-gateway-all \
  --service-roles "@flask-gateway" --edge-router-roles "#all" >/dev/null || true

# 关键：给身份放行到 ER（ERP）
ziti edge create edge-router-policy erp-all \
  --edge-router-roles "#all" \
  --identity-roles "#flask-gateway.servers,#gateway.clients" >/dev/null || true
IN_CTR
echo -e "${GREEN}✔ configs/service/策略 创建完成${NC}"

# ====== 5) Edge Router：确保 JWT 存在；若 ER 已存在但无 JWT -> 重新签发；随后 enroll 并重启 ======
say "启动/注册 Edge Router ..."

ensure_er_jwt(){
  local ER_NAME="edge-router-1"
  local HOST_JWT="${HOST_IDENT_DIR_SERVERS}/${ER_NAME}.jwt"

  # 查询是否存在同名 ER
  if docker exec ziti-controller ziti edge list edge-routers | grep -qE "[[:space:]]${ER_NAME}[[:space:]]"; then
    if [ ! -f "${HOST_JWT}" ]; then
      echo "    ⚠ 检测到 ${ER_NAME} 已存在，但本机缺少 JWT，执行重新签发"
      docker exec ziti-controller ziti edge delete edge-router "${ER_NAME}" >/dev/null 2>&1 || true
      docker exec ziti-controller ziti edge create edge-router "${ER_NAME}" \
        --tunneler-enabled --jwt-output-file /persistent/${ER_NAME}.jwt >/dev/null
      docker cp ziti-controller:/persistent/${ER_NAME}.jwt "${HOST_JWT}" >/dev/null
      echo "    ✔ 重新签发 ER JWT -> ${HOST_JWT}"
    fi
  else
    docker exec ziti-controller ziti edge create edge-router "${ER_NAME}" \
      --tunneler-enabled --jwt-output-file /persistent/${ER_NAME}.jwt >/dev/null
    docker cp ziti-controller:/persistent/${ER_NAME}.jwt "${HOST_JWT}" >/dev/null
    echo "    ✔ 生成 ER JWT -> ${HOST_JWT}"
  fi
}

ensure_er_jwt

# 起容器（第一次起不影响，后面会 enroll 然后 restart）
docker compose up -d ziti-edge-router >/dev/null || true
sleep 2

# 拷贝 JWT 并 enroll（幂等；已 enroll 会返回非零可忽略）
if [ -f "${HOST_IDENT_DIR_SERVERS}/edge-router-1.jwt" ]; then
  docker cp "${HOST_IDENT_DIR_SERVERS}/edge-router-1.jwt" ziti-edge-router:/tmp/er.jwt >/dev/null
  if docker exec ziti-edge-router sh -lc 'ziti-router enroll --jwt /tmp/er.jwt' >/dev/null 2>&1; then
    echo "    ✔ edge-router-1 已成功 enroll"
  else
    echo -e "${YELLOW}⚠ enroll 可能已执行过（容器已有身份），继续${NC}"
  fi
else
  echo -e "${RED}❌ 仍缺少 edge-router-1.jwt，无法 enroll（请检查上一步签发）${NC}"
  exit 1
fi

# 重启让路由器以已注册身份运行
docker restart ziti-edge-router >/dev/null
echo -e "${GREEN}✔ Edge Router 已启动并完成注册${NC}"

# 可选：等待 ER 在线
say "等待 Edge Router 在线 ..."
er_ok=n
for _ in $(seq 1 30); do
  if docker exec ziti-controller ziti edge list edge-routers | grep -qE "online[[:space:]]+true"; then er_ok=y; break; fi
  sleep 2
done
[ "$er_ok" = y ] && echo -e "${GREEN}✔ Edge Router 在线${NC}" || echo -e "${YELLOW}⚠ 仍未检测到在线状态，可稍后再查${NC}"

# ====== 6) 先把后端应用（flask-gateway-ziti）起来，再起 edge-tunnel（ziti-gateway） ======
say "启动后端应用（flask-gateway-ziti）..."
docker compose up -d flask-gateway-ziti >/dev/null || true
sleep 2
docker logs --tail=30 flask-gateway-ziti || true

say "启动 ziti-gateway（edge-tunnel 托管服务）..."
docker compose up -d ziti-gateway >/dev/null || true
echo -e "${GREEN}✔ ziti-gateway 已启动${NC}"

# ====== 7) 等 terminator 出现（服务真正挂载成功的标志） ======
say "等待 terminator（最多 90 秒）..."
ok=n
for _ in $(seq 1 30); do
  out="$(docker exec ziti-controller ziti edge list terminators || true)"
  if echo "$out" | grep -q 'flask-gateway'; then ok=y; break; fi
  sleep 3
done
if [ "$ok" = y ]; then
  echo -e "${GREEN}✔ terminator 就绪：服务已被托管${NC}"
else
  echo -e "${YELLOW}⚠ 仍未看到 terminator，建议查看日志：${NC}"
  echo "  docker logs -n 150 ziti-gateway"
  echo "  docker logs -n 150 ziti-edge-router"
  echo "  docker logs -n 150 flask-gateway-ziti"
fi

echo -e "${GREEN}\n======================================"
echo -e "✅ OpenZiti 引导完成"
echo -e "======================================${NC}"
echo "验证："
echo "  docker exec ziti-controller ziti edge list services"
echo "  docker exec ziti-controller ziti edge list service-policies"
echo "  docker exec ziti-controller ziti edge list edge-router-policies"
echo "  docker exec ziti-controller ziti edge list service-edge-router-policies"
echo "  docker exec ziti-controller ziti edge list terminators"
echo
echo "查看托管日志："
echo "  docker logs -f ziti-gateway | grep -i host"
echo
echo "如需面板："
echo "  docker compose up -d prometheus grafana"
echo "  打开 http://localhost:9090 及 http://localhost:3000 (admin/admin)"
