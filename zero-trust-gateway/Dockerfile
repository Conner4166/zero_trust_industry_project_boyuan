FROM python:3.9-slim

WORKDIR /app

# 安装系统依赖（gcc 通常用不到，可留）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 创建输出与身份目录（compose 会挂载 identities，这个只是保证目录存在）
RUN mkdir -p /app/out /app/identities

# 暴露 5001（便于可视化与本地调试）
EXPOSE 5001

# 健康检查（命中你的 /healthz）
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://localhost:5001/healthz || exit 1

# 入口让 compose 覆盖（compose 里已有 command: python app_ziti.py）
CMD ["python", "app_ziti.py"]
