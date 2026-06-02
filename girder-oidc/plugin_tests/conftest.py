"""Pytest configuration for the OIDC plugin tests.

The server/db/admin/user fixtures and the ``@pytest.mark.plugin('oidc')`` marker
come from the installed ``pytest-girder`` package.

The plugin's ``load()`` registers static web-client content and reads the built
``dist`` files to compute cache-bust hashes. Those files are produced by the web
build (``vite``), which doesn't run in the test container, so we create empty
placeholders here — before any server fixture loads the plugin — so that loading
succeeds during tests.
"""

import pathlib

_dist = pathlib.Path(__file__).resolve().parents[1] / 'girder_oidc' / 'web_client' / 'dist'
_dist.mkdir(parents=True, exist_ok=True)
for _name in ('girder-plugin-oidc.umd.cjs', 'style.css'):
    _placeholder = _dist / _name
    if not _placeholder.exists():
        _placeholder.write_text('/* test placeholder */\n')
