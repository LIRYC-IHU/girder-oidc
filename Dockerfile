# Girder 5 base. The plugin requires girder>=5 and uses Girder 5 APIs
# (registerPluginStaticContent, ...); a Girder 3 base will not load it.
FROM girder/girder:v5.0.9-py3

# Install the published plugin. Its wheel bundles the pre-built web client
# assets (web_client/dist via package-data), so no separate `girder build`
# step is needed in Girder 5.
RUN pip install --no-cache-dir girder-oidc==0.5.0

EXPOSE 8080