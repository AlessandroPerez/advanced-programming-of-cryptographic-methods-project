# Stage 1: Build Rust binaries
FROM rust:latest as builder

WORKDIR /app

# Copy entire project to the container
COPY . .

# Build binaries separately to speed up rebuilds if needed
RUN cargo build --release -p update_server_keys
RUN cargo build --release -p server
RUN cargo build --release -p tui

# Stage 2: Create a lightweight runtime image
FROM ubuntu:22.04

WORKDIR /app

# Install any required runtime libraries (optional, adjust as needed)
# For example, if you use OpenSSL in your Rust code:
# RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy built binaries from the builder stage
COPY --from=builder /app/target/release/update_server_keys .
COPY --from=builder /app/target/release/server .
COPY --from=builder /app/target/release/tui .

# Copy the config folder (will be overwritten by volume in compose)
COPY config/ ./config/

# Make binaries executable (just in case)
RUN chmod +x update_server_keys server tui

# Set default command (can be overridden in docker-compose)
CMD ["bash"]
