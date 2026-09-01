FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install --no-install-recommends -y procps iputils-ping wget curl traceroute && apt-get clean
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Keep build context and image free of local state. These are the only runtime files;
# tests, deploy tooling, VCS data and ignored credentials never enter an image layer.
COPY employee_list.py logutil.py retryutil.py webui.py ./
COPY hutbot/ ./hutbot/
COPY webui_static/ ./webui_static/

EXPOSE 8080

ENTRYPOINT ["python", "-m", "hutbot"]
