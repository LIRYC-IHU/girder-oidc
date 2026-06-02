from setuptools import find_packages, setup

setup(
    name='girder-oidc',
    version='0.1.0',
    description='Authenticate Girder users through an OpenID Connect provider.',
    author='Josselin Duchateau',
    license='Apache 2.0',
    packages=find_packages(exclude=['plugin_tests']),
    python_requires='>=3.10',
    install_requires=[
        'girder>=5',
        'authlib',
        'requests',
    ],
    entry_points={
        'girder.plugin': [
            'oidc = girder_oidc:OidcPlugin',
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
