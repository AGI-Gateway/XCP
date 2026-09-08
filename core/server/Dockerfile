FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi "uvicorn[standard]"
COPY xcp_server.py /app/
EXPOSE 9001
CMD ["uvicorn", "xcp_server:app", "--host", "0.0.0.0", "--port", "9001"]
