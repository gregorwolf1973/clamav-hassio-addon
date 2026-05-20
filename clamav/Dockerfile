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

# Write clamd.conf from scratch — the Alpine default has an "Example" line
# that blocks the daemon, plus a lot of commented-out defaults. Cleaner to
# author our own minimal config.
RUN cat > /etc/clamav/clamd.conf <<'EOF'
LogFile /var/log/clamav/clamav.log
LogTime yes
LogClean no
LogVerbose no
PidFile /var/run/clamav/clamd.pid
DatabaseDirectory /data/clamav-db
LocalSocket /var/run/clamav/clamd.sock
LocalSocketMode 666
FixStaleSocket yes
TCPSocket 3310
TCPAddr 127.0.0.1
MaxConnectionQueueLength 30
MaxThreads 10
ReadTimeout 300
User root
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanHTML yes
ScanArchive yes
MaxFileSize 100M
MaxScanSize 400M
MaxRecursion 10
MaxFiles 10000
ConcurrentDatabaseReload no
EOF

# freshclam.conf — same reasoning, no "Example" line
RUN cat > /etc/clamav/freshclam.conf <<'EOF'
DatabaseDirectory /data/clamav-db
UpdateLogFile /var/log/clamav/freshclam.log
LogTime yes
LogVerbose no
DatabaseOwner root
DatabaseMirror database.clamav.net
MaxAttempts 3
ScriptedUpdates yes
CompressLocalDatabase no
SafeBrowsing no
Bytecode yes
EOF

# Runtime directories. /var/run is tmpfs and gets wiped on container restart,
# so run.sh re-creates it. /var/lib/clamav holds the signature DB.
RUN mkdir -p /var/run/clamav /var/log/clamav \
             /data /data/quarantine /data/history /data/clamav-db && \
    chmod 755 /var/run/clamav /var/log/clamav /data/clamav-db

COPY app/ /app/
COPY run.sh /run.sh
RUN chmod +x /run.sh

WORKDIR /app
CMD ["/run.sh"]
