FROM girder/girder:latest-py3

# Install homepage plugin
RUN pip install girder-homepage girder-oidc \
    && girder build

# Expose port for Girder web interface
EXPOSE 8080