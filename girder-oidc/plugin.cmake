# CMake configuration for girder-oidc plugin

find_package(PythonInterp REQUIRED)
find_package(Node.js REQUIRED)

# Add tests
add_python_test(oidc MODULE girder_oidc)
