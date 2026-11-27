FROM debian:12-slim
RUN curl -fsSL https://example.com/install.sh | sh
RUN wget -qO- https://example.com/setup.sh | bash
RUN curl -s https://example.com/tool.sh \
    | /bin/sh -s -- --prefix=/usr
CMD ["bash"]
