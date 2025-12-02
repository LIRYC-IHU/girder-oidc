"""Pytest configuration for OIDC plugin tests."""

import pytest
from girder.test import base


@pytest.fixture(scope='session')
def db(tmpdir_factory):
    """Set up test database."""
    return base.startServer(
        plugins=['oidc']
    )
