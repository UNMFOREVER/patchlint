FROM debian:12-slim
RUN chmod 777 /usr/local/bin/entrypoint.sh
RUN chmod -R 777 /srv/app
RUN chmod '0777' /tmp/drop
RUN echo hi && chmod a+rwx /opt/run.sh
CMD ["bash"]
