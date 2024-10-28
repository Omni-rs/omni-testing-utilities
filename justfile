set positional-arguments

# Run linting
lint:
    cargo clippy --all-targets -- -D clippy::all -D clippy::nursery

# Check formatting
fmt:
    cargo fmt --check

# Verify all compiles
check:
    cargo check
    
# TODO: Run all tests
test-all:
    cargo test --workspace -- --nocapture