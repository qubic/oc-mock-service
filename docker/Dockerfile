ARG BASE_IMAGE="python:3.12-slim"

# Build stage: compile the C++ verifiers (needs clang, x86-64 with AVX2)
FROM ${BASE_IMAGE} AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang cmake make && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B build -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j"$(nproc)"

# Runtime stage
FROM ${BASE_IMAGE} AS runtime

RUN groupadd -r oc && useradd -r -g oc oc

# Mirror the repo layout so the service's default relative paths
# (build/oc_verify, keys/, data/) work without any env configuration.
WORKDIR /opt/qubic/oc-mock-service

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=build /src/build/oc_verify /src/build/computors_verify build/
COPY service/ service/

RUN mkdir -p keys data && chown -R oc:oc keys data

USER oc

EXPOSE 8000

CMD ["uvicorn", "service.app:app", "--host", "0.0.0.0", "--port", "8000"]
