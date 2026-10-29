set shell := ["bash", "-euo", "pipefail", "-c"]

default: check test

_cargo cmd:
	if command -v sccache >/dev/null 2>&1; then RUSTC_WRAPPER=sccache {{cmd}}; else {{cmd}}; fi

check:
	just _cargo "cargo check --workspace --all-targets --all-features --locked"

test:
	just _cargo "cargo test --workspace --all-targets --locked"

build:
	linker_flag=""; \
	if command -v mold >/dev/null 2>&1; then \
		linker_flag="-C link-arg=-fuse-ld=mold"; \
	elif command -v ld.lld >/dev/null 2>&1; then \
		linker_flag="-C link-arg=-fuse-ld=lld"; \
	fi; \
	if command -v sccache >/dev/null 2>&1; then \
		RUSTC_WRAPPER=sccache RUSTFLAGS="${linker_flag} ${RUSTFLAGS:-}" cargo build --release --locked; \
	else \
		RUSTFLAGS="${linker_flag} ${RUSTFLAGS:-}" cargo build --release --locked; \
	fi

dist:
	just _cargo "cargo build --profile dist --locked"

serve config="":
	if [[ -n "{{config}}" ]]; then \
		just _cargo "cargo run -- --config {{config}}"; \
	else \
		just _cargo "cargo run"; \
	fi

minio-up:
	docker compose -f docker-compose.minio.yml up -d minio

minio-down:
	docker compose -f docker-compose.minio.yml down -v

test-s3-it:
	just _cargo "cargo test --features s3 --test state_coordination_s3_integration -- --nocapture"
	just _cargo "cargo test --features s3 --test state_coordination_s3_integration -- --ignored --nocapture"
	just _cargo "cargo test --features s3 --test s3_minio_integration -- --ignored --nocapture"

governance-up:
	docker compose -f docker-compose.governance.yml up -d postgres redis

governance-down:
	docker compose -f docker-compose.governance.yml down -v

test-governance-it:
	just _cargo "cargo test --features redis,postgres --test governance_redis_postgres_integration -- --nocapture"
	just _cargo "cargo test --features redis,postgres --test governance_redis_postgres_integration -- --ignored --nocapture"
	just _cargo "cargo test --features redis --test state_coordination_redis_lock_integration -- --nocapture"
	just _cargo "cargo test --features redis --test state_coordination_redis_lock_integration -- --ignored --nocapture"
	just _cargo "cargo test --features postgres --test state_coordination_postgres_integration -- --ignored --nocapture"
