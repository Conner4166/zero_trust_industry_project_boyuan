#!/bin/sh
set -euo pipefail

ziti edge login https://ziti-controller:1280 -u admin -p admin123 >/dev/null

# 1) ??????????? JSON?? BOM/CRLF?
cat >/tmp/intercept.json <<'JSON'
{"protocols":["tcp"],"addresses":["flask-gateway"],"portRanges":[{"low":7000,"high":7000}]}
JSON

cat >/tmp/host.json <<'JSON'
{"protocol":"tcp","address":"flask-gateway-ziti","port":5001}
JSON

# 2) ?????????????
ziti edge delete service flask-gateway 2>/dev/null || true
ziti edge delete config  flask-gateway-intercept 2>/dev/null || true
ziti edge delete config  flask-gateway-host      2>/dev/null || true
ziti edge delete service-edge-router-policy ser-flask-gateway-all 2>/dev/null || true
ziti edge delete service-policy sp-flask-gateway-dial  2>/dev/null || true
ziti edge delete service-policy sp-flask-gateway-bind  2>/dev/null || true

# 3) ?????? config????????????????????
ziti edge create config flask-gateway-intercept intercept.v1 "$(cat /tmp/intercept.json)"
ziti edge create config flask-gateway-host      host.v1      "$(cat /tmp/host.json)"

# 4) ??????? config????????? @flask-gateway ????
ziti edge create service flask-gateway \
  --configs "flask-gateway-intercept,flask-gateway-host" \
  --attributes "flask-gateway"

# 5) ???????????
ziti edge create service-edge-router-policy ser-flask-gateway-all \
  --service-roles "@flask-gateway" --edge-router-roles "#all" 2>/dev/null || true

ziti edge create service-policy sp-flask-gateway-dial Dial AnyOf \
  --service-roles "@flask-gateway" --identity-roles "#gateway.clients" 2>/dev/null || true

ziti edge create service-policy sp-flask-gateway-bind Bind AnyOf \
  --service-roles "@flask-gateway" --identity-roles "#flask-gateway.servers" 2>/dev/null || true

# 6) ??????
ziti edge show service flask-gateway