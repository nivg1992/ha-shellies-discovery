FROM python:3-alpine
COPY . /app
WORKDIR /app
ENV CFLAGS=-fcommon
RUN CFLAGS=-fcommon apk add --no-cache \
        gcc \
        linux-headers \
        musl-dev
RUN pip install -r ./standalone/requirements.txt
CMD ["python", "main.py"]