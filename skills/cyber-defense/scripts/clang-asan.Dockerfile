# Image for sanitizer PoVs and libFuzzer harnesses (oss-hunt §5b).
# Why a local image: gcc:14 has ASan but no libFuzzer (-fsanitize=fuzzer is clang-only), and
# third-party clang images are an unreviewed supply chain. Debian packages come from the distro.
# Build (outside the Bash sandbox, needs network):
#   docker build -t cyberdef-clang:local - < clang-asan.Dockerfile
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-rt-14-dev llvm make cmake pkg-config autoconf automake libtool ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENV CC=clang CXX=clang++ ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
