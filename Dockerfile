FROM public.ecr.aws/docker/library/python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . "uvicorn>=0.30"
EXPOSE 8080
CMD ["uvicorn", "fujioky_auth.portal:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
