"""Tests for the open-redirect guard."""

import pytest

from girder.exceptions import RestException
from girder_oidc.rest import _safeRedirect


def test_empty_defaults_to_root():
    assert _safeRedirect('') == '/'
    assert _safeRedirect(None) == '/'


def test_relative_path_allowed():
    assert _safeRedirect('/') == '/'
    assert _safeRedirect('/collections?foo=bar') == '/collections?foo=bar'


@pytest.mark.parametrize('value', [
    'https://evil.example.com',
    'http://evil.example.com/path',
    '//evil.example.com',
    'relative/no/leading/slash',
    'javascript:alert(1)',
])
def test_open_redirects_rejected(value):
    with pytest.raises(RestException):
        _safeRedirect(value)
