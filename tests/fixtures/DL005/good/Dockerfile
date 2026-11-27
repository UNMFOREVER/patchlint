FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y -o APT::Install-Recommends=false git
RUN apt-get update && apt-get -y install --no-install-recommends python3
RUN apt-get remove -y curl
RUN apt-get update # apt-get install -y unzip
CMD ["bash"]
