FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g gmgn-cli \
    && npm cache clean --force
WORKDIR /app
COPY --chown=node:node bot.py webhook.py ./
USER node
ENV PYTHONUNBUFFERED=1 PORT=10000 BOT_DB=/tmp/veraz.sqlite3 ENABLE_GMGN=0
EXPOSE 10000
CMD ["python3", "webhook.py"]
