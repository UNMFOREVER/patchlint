FROM debian:12-slim
RUN chmod 750 /usr/local/bin/entrypoint.sh
RUN chmod -R 644 /srv/app/static
RUN chmod -R u+rwX,go+rX /srv/app
RUN echo 'chmod 777 is bad' > /tmp/note.txt # keep chmod 777 out
CMD ["bash"]
