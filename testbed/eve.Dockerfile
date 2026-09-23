FROM python:3.12-slim
WORKDIR /app
COPY attacker/downgrade_relay.py .
CMD ["python3", "downgrade_relay.py", "10.10.0.20"]
