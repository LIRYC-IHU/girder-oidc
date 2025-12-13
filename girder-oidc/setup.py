from setuptools import setup, find_packages

setup(
    name='girder-oidc',
    version='0.0.1',
    description='Girder plugin for OIDC/Keycloak authentication',
    author='Josselin Duchateau',
    license='Apache 2.0',
    packages=find_packages(),
    install_requires=[
        'girder>=3.0.0',
        'python-jose[cryptography]',
        'requests',
    ],
    entry_points={
        'girder.plugin': [
            'oidc = girder_oidc:OidcPlugin',
        ],
    },
    include_package_data=True,
)
