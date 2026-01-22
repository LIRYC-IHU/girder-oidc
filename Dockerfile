FROM girder/girder:latest-py3

# Install homepage plugin
RUN pip install girder-homepage girder-jobs

# Copy the girder-oidc plugin into the container
COPY girder-oidc /plugins/girder-oidc

# Copy the girder-multi-part-zip plugin into the container
COPY girder-multi-part-zip /plugins/girder-multi-part-zip

# Install the girder-oidc plugin and the girder-multi-part-zip plugin
RUN pip install /plugins/girder-oidc /plugins/girder-multi-part-zip

# Build Girder frontend with the new plugins
RUN girder build

# Expose port for Girder web interface
EXPOSE 8080