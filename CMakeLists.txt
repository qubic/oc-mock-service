# Standalone build for the OC mock interface service verifier.
#
# This is intentionally decoupled from the main Qubic.sln / top-level CMake:
# the mock service is a separate deployable, not part of the node build.
#
# Crypto (four_q.h, kangaroo_twelve.h) is VENDORED under vendor/qubic_crypto/
# (a clang-portable copy from core-lite) so the service builds standalone on a
# plain Linux host with no node checkout present. See vendor/qubic_crypto/.
#
# Build:
#   cmake -S oc_mock_service -B oc_mock_service/build \
#         -D CMAKE_CXX_COMPILER=clang++ -D CMAKE_BUILD_TYPE=Release
#   cmake --build oc_mock_service/build

cmake_minimum_required(VERSION 3.16)
project(oc_mock_service CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(VENDOR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/qubic_crypto")

# four_q.h uses AVX2 + AES intrinsics; K12 uses SSE/AVX.
add_compile_options(-mavx2 -maes -Wall -Wextra -Wno-unused-parameter)

# Vendored crypto headers expose their whole API as file-static functions, so
# every TU that includes them warns about the ones it does not call. Treat them
# as SYSTEM headers: our own sources keep full -Wall -Wextra.
include_directories(SYSTEM "${VENDOR}/src" "${VENDOR}")

# NO_UEFI tells the platform headers we are a hosted (OS) build, not bare-metal.
add_compile_definitions(NO_UEFI=1)

add_executable(oc_verify
    src/oc_verify_main.cpp
    src/platform_glue.cpp
)

# Computor-list verifier: checks a fetched Computors payload against the
# arbitrator identity (mirrors processBroadcastComputors in the core).
add_executable(computors_verify
    src/computors_verify_main.cpp
    src/platform_glue.cpp
)

# Test-bundle generator (uses the same vendored crypto to sign real bundles).
add_executable(make_test_bundle
    tests/make_test_bundle.cpp
    src/platform_glue.cpp
)

# Test-computors generator (arbitrator-signed key list matching make_test_bundle's keys).
add_executable(make_test_computors
    tests/make_test_computors.cpp
    src/platform_glue.cpp
)
