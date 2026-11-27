FROM debian:12-slim
RUN apt-get update && apt-get install -y curl git
RUN apt update && apt install -y ca-certificates
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && apt-get install -y vim
CMD ["bash"]
