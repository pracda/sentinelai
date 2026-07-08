FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc nmap wget && rm -rf /var/lib/apt/lists/*

RUN wget -qO /tmp/litestream.tar.gz https://github.com/benbjohnson/litestream/releases/download/v0.3.13/litestream-v0.3.13-linux-amd64.tar.gz && tar -xzf /tmp/litestream.tar.gz -C /usr/local/bin litestream && rm /tmp/litestream.tar.gz

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports /data && chmod +x /app/start.sh

EXPOSE 8000

CMD ["/app/start.sh"]