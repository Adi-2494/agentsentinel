# AgentSentinel dashboard (read-only viewer of the event log and saved results).
# The Live Guard and Merge Gate are NOT in this image: they need your Claude
# login, which must never be baked into a container.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AGENTSENTINEL_DB=/app/data/agentsentinel.db \
    AGENTSENTINEL_DEMO_DB=/app/demo/demo.db

WORKDIR /app
COPY requirements-dashboard.txt .
RUN pip install -r requirements-dashboard.txt

COPY core/ core/
COPY dashboard/ dashboard/
COPY .streamlit/ .streamlit/
COPY benchmark/results/ benchmark/results/

# Synthetic, clearly labelled demo log for fresh clones / the public demo.
RUN python -m dashboard.seed_demo /app/demo/demo.db \
    && useradd --create-home --uid 1000 app \
    && mkdir -p /app/data && chown app /app/data

USER app
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health')"
CMD ["streamlit", "run", "dashboard/app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
