ARG BUILD_FROM
FROM $BUILD_FROM

# Install ClamAV and Python dependencies
RUN apk add --no-cache \
    clamav \
    clamav-daemon \
    clamav-libunrar \
    python3 \
    py3-pip \
    bash \
    curl \
    jq \
    tzdata

RUN pip3 install --break-system-packages flask

# ClamAV config: allow scanning as root inside container
RUN sed -i 's/^#*LocalSocket .*/LocalSocket \/var\/run\/clamav\/clamd.sock/' /etc/clamav/clamd.conf && \
    sed -i 's/^#*User .*/User root/' /etc/clamav/clamd.conf && \
    sed -i 's/^#*TCPSocket .*/TCPSocket 3310/' /etc/clamav/clamd.conf && \
    sed -i 's/^#*LogFile .*/LogFile \/var\/log\/clamav\/clamav.log/' /etc/clamav/clamd.conf && \
    sed -i 's/^#*LogTime .*/LogTime yes/' /etc/clamav/clamd.conf && \
    echo "MaxFileSize 100M" >> /etc/clamav/clamd.conf && \
    echo "MaxScanSize 400M" >> /etc/clamav/clamd.conf

RUN sed -i 's/^#*DatabaseOwner .*/DatabaseOwner root/' /etc/clamav/freshclam.conf && \
    sed -i 's/^#*UpdateLogFile .*/UpdateLogFile \/var\/log\/clamav\/freshclam.log/' /etc/clamav/freshclam.conf && \
    sed -i 's/^#*LogTime .*/LogTime yes/' /etc/clamav/freshclam.conf

# Runtime directories
RUN mkdir -p /var/run/clamav /var/log/clamav /data /data/quarantine /data/history

COPY app/ /app/
COPY run.sh /run.sh
RUN chmod +x /run.sh

WORKDIR /app
CMD ["/run.sh"]
