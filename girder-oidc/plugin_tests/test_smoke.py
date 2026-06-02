"""Smoke tests: the plugin is installed, discoverable, and importable."""


def test_plugin_registered():
    from girder.plugin import getPlugin

    plugin = getPlugin('oidc')
    assert plugin is not None
    assert plugin.name == 'oidc'


def test_plugin_modules_importable():
    from girder_oidc.client import OidcClient
    from girder_oidc.settings import PluginSettings
    from girder_oidc.user import createOrReuseUser

    assert OidcClient is not None
    assert createOrReuseUser is not None
    assert PluginSettings.CLIENT_ID == 'oidc.client_id'
