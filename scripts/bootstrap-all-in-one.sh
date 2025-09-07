#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ts(){ date "+%H:%M:%S"; }
say(){ echo -e "[$(ts)] $*"; }

# ---- 基础配置（与 docker-compose.yml 对齐）----
ZITI_ADMIN_USER="admin"
ZITI_ADMIN_PWD="admin123"
CTRL_URL="https://ziti-controller:1280"

HOST_IDENT_DIR_SERVERS="./openziti/identities"
HOST_IDENT_DIR_CLIENTS="./openziti/identities-client"
mkdir -p "${HOST_IDENT_DIR_SERVERS}" "${HOST_IDENT_DIR_CLIENTS}"

# ==== 0) 先确保 compose 文件存在 ====
if ! docker compose ls >/dev/null 2>&1; then
  echo -e "${RED}❌ 找不到 docker compose 环境，请在项目根目录运行本脚本${NC}"
  exit 1
fi

# ==== 1) 起基础容器 ====
say "启动 Postgres / Redis / Keycloak / Ziti Controller ..."
docker compose up -d postgres redis keycloak ziti-controller >/dev/null

# ==== 2) 等 Controller 可登录 ====
say "等待 Ziti Controller 可登录 ..."
try_login(){ docker exec ziti-controller ziti edge login "$CTRL_URL" -u "$ZITI_ADMIN_USER" -p "$ZITI_ADMIN_PWD" -y >/dev/null 2>&1; }
ok_login=n
for _ in $(seq 1 120); do if try_login; then ok_login=y; break; fi; sleep 2; done
[ "$ok_login" = y ] && echo -e "${GREEN}✔ 登录成功${NC}" || { echo -e "${RED}❌ 无法登录 Controller${NC}"; exit 1; }

# ==== 3) 幂等创建身份：flask-gateway(服务器) / alice(客户端) ====
say "创建/准备身份（flask-gateway / alice）..."
docker exec ziti-controller ziti edge login "$CTRL_URL" -u "$ZITI_ADMIN_USER" -p "$ZITI_ADMIN_PWD" -y >/dev/null

ensure_identity_json(){
  local NAME="$1" ATTR="$2" COPY_TO_DIR="$3"
  local JWT="/persistent/${NAME}.jwt"
  local JSON="/persistent/${NAME}.json"

  # 先尝试 generate identity-token（可能返回 {"token":...}）
  if docker exec ziti-controller sh -lc "ziti edge generate identity-token ${NAME} > ${JWT} 2>/dev/null"; then
    docker exec ziti-controller sh -lc '
      f="'"${JWT}"'"; if grep -q "\"token\"" "$f" 2>/dev/null; then
        if command -v jq >/dev/null 2>&1; then tok=$(jq -r .token "$f"); else tok=$(sed -n '\''s/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'\'' "$f"|head -n1); fi
        [ -n "$tok" ] && printf "%s" "$tok" > "$f"
      fi'
    if ! docker exec ziti-controller sh -lc "grep -Eq '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' ${JWT}"; then
      docker exec ziti-controller ziti edge delete identity "${NAME}" >/dev/null 2>&1 || true
      docker exec ziti-controller ziti edge create identity "${NAME}" -a "${ATTR}" -o "${JWT}"
    fi
  else
    docker exec ziti-controller ziti edge delete identity "${NAME}" >/dev/null 2>&1 || true
    docker exec ziti-controller ziti edge create identity "${NAME}" -a "${ATTR}" -o "${JWT}"
  fi

  docker exec ziti-controller ziti edge enroll "${JWT}" -o "${JSON}" >/dev/null
  docker cp "ziti-controller:${JSON}" "${COPY_TO_DIR}/${NAME}.json" >/dev/null
  echo "    ✔ ${NAME}.json -> ${COPY_TO_DIR}/"
}
# 服务器身份 -> identities
ensure_identity_json "flask-gateway" "flask-gateway.servers" "${HOST_IDENT_DIR_SERVERS}"
# 客户端身份 -> identities-client
ensure_identity_json "alice"         "gateway.clients"        "${HOST_IDENT_DIR_CLIENTS}"
echo -e "${GREEN}✔ 身份 JSON 就绪${NC}"

# ==== 4) 在 Controller 内：创建 configs / service / 策略（幂等）====
say "在 Controller 内创建 configs / service / 策略 ..."
docker exec -i ziti-controller bash <<'IN_CTR'
set -euo pipefail
ziti edge login https://ziti-controller:1280 -u admin -p admin123 -y >/dev/null

# 幂等清理（无则忽略）
for x in "flask-gateway" ; do ziti edge delete service "$x" 2>/dev/null || true; done
for x in "flask-gateway-intercept" "flask-gateway-host" ; do ziti edge delete config "$x" 2>/dev/null || true; done
for x in "flask-gateway-dial" "flask-gateway-bind" ; do ziti edge delete service-policy "$x" 2>/dev/null || true; done
for x in "ser-flask-gateway-all" ; do ziti edge delete service-edge-router-policy "$x" 2>/dev/null || true; done
for x in "erp-all" ; do ziti edge delete edge-router-policy "$x" 2>/dev/null || true; done

# 写入 JSON
cat >/tmp/intercept.json <<'JSON'
{"protocols":["tcp"],"addresses":["flask-gateway"],"portRanges":[{"low":7000,"high":7000}]}
JSON
cat >/tmp/host.json <<'JSON'
{"protocol":"tcp","address":"flask-gateway-ziti","port":5001,"listenOptions":{"bindUsingEdgeIdentity":true}}
JSON

# 创建 config + service
ziti edge create config  flask-gateway-intercept intercept.v1 "$(cat /tmp/intercept.json)" >/dev/null
ziti edge create config  flask-gateway-host      host.v1      "$(cat /tmp/host.json)"      >/dev/null
ziti edge create service flask-gateway --configs "flask-gateway-intercept,flask-gateway-host" >/dev/null

# Service Policies（方向正确）
ziti edge create service-policy flask-gateway-dial Dial \
  --semantic AnyOf --service-roles "@flask-gateway" --identity-roles "#gateway.clients" >/dev/null

ziti edge create service-policy flask-gateway-bind Bind \
  --semantic AnyOf --service-roles "@flask-gateway" --identity-roles "#flask-gateway.servers" >/dev/null

# Service ↔ Edge Router
ziti edge create service-edge-router-policy ser-flask-gateway-all \
  --service-roles "@flask-gateway" --edge-router-roles "#all" >/dev/null

# 给身份放行到 ER
ziti edge create edge-router-policy erp-all \
  --edge-router-roles "#all" \
  --identity-roles "#flask-gateway.servers,#gateway.clients" >/dev/null
IN_CTR
echo -e "${GREEN}✔ configs/service/策略 创建完成${NC}"

# ==== 5) Edge Router：强制清空旧卷 + 重新签发 + 带 token 首启 ====
say "准备 Edge Router ..."

# 5.1 停 & 删容器（忽略错误）
docker compose stop ziti-edge-router >/dev/null 2>&1 || true
docker compose rm -f ziti-edge-router >/dev/null 2>&1 || true

# 5.2 清数据卷（不同 compose 名称可能不一样，统统尝试一下）
#    只要清到包含 ziti_router_data 的卷即可，避免旧 config.yml 干扰首启 enroll
for v in $(docker volume ls --format '{{.Name}}' | grep -E 'ziti[_-]router[_-]data|ziti_router_data' || true); do
  docker volume rm "$v" >/dev/null 2>&1 || true
done

# 5.3 Controller 内签发/重签发 JWT
docker exec ziti-controller sh -lc '
  set -e
  ziti edge login https://ziti-controller:1280 -u admin -p admin123 -y
  if ziti edge list edge-routers | grep -q " edge-router-1 "; then
    ziti edge re-enroll edge-router edge-router-1 --jwt-output-file /persistent/edge-router-1.jwt
  else
    ziti edge create edge-router edge-router-1 --tunneler-enabled \
      --jwt-output-file /persistent/edge-router-1.jwt
  fi
'

# 5.4 拷贝 JWT 到宿主
docker cp ziti-controller:/persistent/edge-router-1.jwt "${HOST_IDENT_DIR_SERVERS}/edge-router-1.jwt" >/dev/null
echo "    ✔ JWT -> ${HOST_IDENT_DIR_SERVERS}/edge-router-1.jwt"

# 5.5 **带 token 首启 ER（关键步骤）**
ZITI_ENROLL_TOKEN="$(cat "${HOST_IDENT_DIR_SERVERS}/edge-router-1.jwt")" \
docker compose up -d ziti-edge-router >/dev/null
echo "    ✔ ER 首次启动（已带 token）"

# 5.6 等 ER online
say "等待 Edge Router online ..."
er_ok=n
for _ in $(seq 1 40); do
  if docker exec ziti-controller ziti edge list edge-routers | awk '/edge-router-1/ && $3=="true" {f=1} END{exit !f}'; then
    er_ok=y; break
  fi
  sleep 2
done
if [ "$er_ok" = y ]; then
  echo -e "${GREEN}✔ ER online${NC}"
else
  echo -e "${YELLOW}⚠ ER 未 online，继续后续步骤，但 terminator 可能仍无${NC}"
fi

# ==== 6) 起后端 & 托管端 ====
say "启动后端 flask-gateway-ziti ..."
docker compose up -d flask-gateway-ziti >/dev/null || true
sleep 2

say "启动 ziti-gateway（托管端）..."
docker compose up -d ziti-gateway >/dev/null || true
sleep 2

# ==== 7) 等 terminator ====
say "等待 terminator（最多 90 秒）..."
ok=n
for _ in $(seq 1 30); do
  out="$(docker exec ziti-controller ziti edge list terminators || true)"
  if echo "$out" | grep -q 'flask-gateway'; then ok=y; break; fi
  sleep 3
done
if [ "$ok" = y ]; then
  echo -e "${GREEN}✔ terminator 就绪${NC}"
else
  echo -e "${YELLOW}⚠ 未见 terminator：拍服务 + 重启托管端${NC}"
  docker exec ziti-controller sh -lc '
    ziti edge login https://ziti-controller:1280 -u admin -p admin123 -y
    ziti edge update service flask-gateway --configs "flask-gateway-intercept,flask-gateway-host" >/dev/null || true
  '
  docker compose restart ziti-gateway >/dev/null || true
  sleep 5
  out="$(docker exec ziti-controller ziti edge list terminators || true)"
  if echo "$out" | grep -q 'flask-gateway'; then
    echo -e "${GREEN}✔ terminator 已出现${NC}"
  else
    echo -e "${RED}❌ 仍无 terminator\n  查看：docker logs --tail 200 ziti-gateway\n       docker logs --tail 200 ziti-edge-router\n       docker logs --tail 200 flask-gateway-ziti${NC}"
  fi
fi

# ==== 8) 可选：提示临时客户端拨测命令 ====
echo -e "${GREEN}\n======================================"
echo -e "✅ 完成（若仍不通，请先看 ER/托管端日志）"
echo -e "======================================${NC}"
echo "可选：临时起一个客户端容器做端到端拨测（需要 Linux 内核 TUN 能力）："
echo "  docker run --rm --name ziti-test \\"
echo "    --network $(docker network ls --format '{{.Name}}' | grep -m1 graduationproject_boyuanzhang_zero-trust-net || echo default) \\"
echo "    --cap-add=NET_ADMIN --device /dev/net/tun \\"
echo "    -v \"${PWD}/openziti/identities-client:/ziti:ro\" \\"
echo "    openziti/ziti-edge-tunnel:latest sh -lc 'ziti-edge-tunnel run -i /ziti/alice.json & sleep 6; getent hosts flask-gateway; curl -sS -w \"\\n%{http_code}\\n\" http://flask-gateway:7000/healthz'"
