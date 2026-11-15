FROM mcr.microsoft.com/devcontainers/javascript-node@sha256:447fa75fbc7123952284b50229148e933ea756c40718601fa0ec46edd29fd0c6
USER root
COPY --chown=0:0 verified-codex-package/ /opt/codex/
COPY --chown=0:0 public-notices/ /opt/bootstrap-review/notices/
COPY --chown=0:0 --chmod=0444 public-provenance.json /opt/bootstrap-review/provenance.json
COPY --chown=0:0 --chmod=0444 reviewer-gate.py /opt/bootstrap-review/reviewer-gate.py
ENV PATH="/opt/codex/bin:/opt/codex/codex-resources:/usr/local/bin:/usr/bin:/bin"
USER 65532:65532
ENTRYPOINT ["/usr/bin/prlimit", "--as=17179869184:17179869184", "--", "/usr/bin/python3", "-I", "-S", "-u", "/opt/bootstrap-review/reviewer-gate.py"]
