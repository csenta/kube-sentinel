FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim

RUN groupadd -r kubesentinel && useradd -r -g kubesentinel -d /home/kubesentinel -m kubesentinel
WORKDIR /app

COPY --from=builder /root/.local /home/kubesentinel/.local
COPY --chown=kubesentinel:kubesentinel . /app

ENV PATH=/home/kubesentinel/.local/bin:$PATH
ENV PYTHONPATH=/app

USER kubesentinel

ENTRYPOINT ["python3", "-m", "kube_sentinel.cli"]
CMD ["--help"]
