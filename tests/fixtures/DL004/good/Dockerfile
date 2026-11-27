FROM debian:12-slim
RUN curl -fsSLo /tmp/install.sh https://example.com/install.sh \
 && echo "9f2c  /tmp/install.sh" | sha256sum -c - \
 && sh /tmp/install.sh
RUN wget -O /tmp/setup.sh https://example.com/setup.sh
RUN curl -fsSL https://example.com/health.txt
RUN apt-get update && apt-get install -y --no-install-recommends curl
CMD ["bash"]
