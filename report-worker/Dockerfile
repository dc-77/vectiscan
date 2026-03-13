FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r vectiscan && useradd -r -g vectiscan -m vectiscan

WORKDIR /app

COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

USER vectiscan

CMD ["python3", "-m", "reporter"]
