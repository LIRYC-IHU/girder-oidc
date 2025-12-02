FROM girder/girder:latest-py3

# Install homepage plugin
RUN pip install girder-homepage

# Copy plugin source, install and build frontend assets
COPY girder-oidc /workspace/girder-oidc
RUN pip install -e /workspace/girder-oidc \
    && girder build

# Expose port for Girder web interface
EXPOSE 8080