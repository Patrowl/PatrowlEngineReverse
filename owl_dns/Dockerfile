# Étape de build (builder)
FROM python:3.11-alpine AS builder
ENV ENGINE=owl_dns


# Définir le répertoire de travail
WORKDIR /engine

# Installer les dépendances nécessaires pour construire l'environnement (comme les outils de build)
RUN apk add --no-cache gcc musl-dev libffi-dev

ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"


# Get submodule base_engine
COPY base_engine /base_engine
COPY owl_dns/requirements.txt /engine

COPY owl_dns/metadatas.json.sample /engine/metadatas.json

COPY owl_dns/. /engine

ADD https://github.com/Patrowl/Sublist3r.git /app/Sublist3r
RUN pip install --no-cache-dir -r /app/Sublist3r/requirements.txt
RUN pip install -r /engine/requirements.txt

# Étape finale
FROM python:3.11-alpine

# Définir le répertoire de travail dans l'image finale
WORKDIR /engine

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copier les fichiers nécessaires depuis l'étape de build
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app/Sublist3r /engine/external-libs/Sublist3r
COPY --from=builder /engine /engine

# Installer uniquement les dépendances nécessaires à l'exécution
RUN apk add --no-cache libffi

# Exécuter l'application
CMD ["python", "engine.py"]



# FROM alpine:3.16.3@sha256:b95359c2505145f16c6aa384f9cc74eeff78eb36d308ca4fd902eeeb0a0b161b AS builder

# # gcc, linux-headers, python3-dev and musl-dev are needed to compile EnginesUtils' psutil
# # https://github.com/giampaolo/psutil/blob/master/INSTALL.rst#linux
# RUN apk add --no-cache \
#     gcc~=11.2 \
#     linux-headers~=5.16 \
#     musl-dev~=1.2 \
#     python3~=3.10 \
#     python3-dev~=3.10

# # Install uv
# COPY --from=ghcr.io/astral-sh/uv:0.5.13 /uv /uvx /bin/

# # Setup the virtual environment
# ENV VIRTUAL_ENV=/opt/venv
# RUN uv venv "$VIRTUAL_ENV"
# ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# # Install Python dependencies
# COPY requirements.txt /
# RUN uv pip install --no-cache-dir -r requirements.txt

# # Install Sublist3r's dependencies
# ADD https://github.com/Patrowl/Sublist3r.git /app/Sublist3r
# RUN uv pip install --no-cache-dir -r /app/Sublist3r/requirements.txt


# FROM alpine:3.16.3@sha256:b95359c2505145f16c6aa384f9cc74eeff78eb36d308ca4fd902eeeb0a0b161b AS final
# LABEL name="Patrowl\ DNS\ \(Patrowl engine\)" version="1.5.15rc1"

# # Create required directories for the engine
# RUN mkdir -p /opt/patrowl-engines/owl_dns \
#     && mkdir -p /opt/patrowl-engines/owl_dns/results \
#     && mkdir -p /opt/patrowl-engines/owl_dns/external-libs

# # Change the working directory
# WORKDIR /opt/patrowl-engines/owl_dns

# # Install Python
# RUN apk add --no-cache python3~=3.10

# # Setup the virtual environment
# ENV VIRTUAL_ENV=/opt/venv
# ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# # Retrieve dnstwist and Sublist3r
# ADD https://github.com/elceef/dnstwist.git#20240812 external-libs/dnstwist
# ADD https://github.com/Patrowl/Sublist3r.git#eba9a5548ad0b5f4d8ca7300d1e2a76295abd124 external-libs/Sublist3r

# # Retrieve Python environment
# COPY --from=builder /opt/venv /opt/venv

# # Copy data
# COPY __init__.py .
# COPY engine_owl_dns.py .
# COPY owl_dns.json.sample owl_dns.json
# COPY README.md .
# COPY VERSION .
# COPY etc/ etc/
# COPY modules/ modules/

# EXPOSE 5006

# # Run app.py when the container launches
# CMD ["gunicorn", "engine_owl_dns:app", "--bind", "0.0.0.0:5006", "--access-logfile", "-", "--threads", "10"]
