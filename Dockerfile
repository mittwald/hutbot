# Pinned by digest, so rebuilding a commit builds on the same base; Dependabot proposes updates.
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

WORKDIR /app

# procps only, for `ps` in a live pod. No network tooling: nothing at runtime needs curl, wget,
# ping or traceroute, and each would only help whoever managed to run code in here.
RUN apt-get update && apt-get install --no-install-recommends -y procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The bot runs unprivileged. Its code stays root-owned and read-only to it; the one place it
# writes is the state directory, which the chart mounts a volume over (its fsGroup keeps files
# written by an earlier root-run image readable).
RUN groupadd --system --gid 10001 hutbot \
    && useradd --system --uid 10001 --gid hutbot --no-create-home --home-dir /nonexistent \
       --shell /usr/sbin/nologin hutbot \
    && install -d -o 10001 -g 10001 -m 0700 /data
ENV HUTBOT_CONFIG_FILE=/data/bot.json \
    HUTBOT_SCHEDULED_REPLIES_CACHE_FILE=/data/scheduled_replies.json \
    HUTBOT_BUTTON_CACHE_FILE=/data/button_states.json \
    HUTBOT_EMPLOYEE_CACHE_FILE=/data/employees.json \
    HUTBOT_EMPLOYEE_FALLBACK_FILE=/data/employees-fallback.json \
    PYTHONDONTWRITEBYTECODE=1

# Keep build context and image free of local state. These are the only runtime files;
# tests, deploy tooling, VCS data and ignored credentials never enter an image layer.
COPY employee_list.py fileutil.py logutil.py retryutil.py webui.py ./
COPY hutbot/ ./hutbot/
COPY webui_static/ ./webui_static/
# Compiled here, because the root filesystem is read-only at runtime.
RUN python -m compileall -q /app

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["python", "-m", "hutbot"]
