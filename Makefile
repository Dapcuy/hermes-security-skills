# =============================================================================
# Makefile — Hermes Security Skills (task harian developer)
#
# Konvensi docker: build context = ROOT repo (titik "."), Dockerfile per
# image di runtimes/docker/images/<name>/Dockerfile (§13).
# Catatan: lab environment dihapus pasca-benchmark (keputusan owner, §42) —
# kebutuhan lab mendatang memakai repo terpisah.
# =============================================================================

SHELL := /bin/bash

# Nama direktori image (bukan nama image final — lihat image-manifest.yaml)
IMAGE_NAMES := http-validator json-validator openapi-validator python-validator proxy tool-nuclei

.PHONY: help go-build go-test go-vet lint-skills docker-build

help: ## Tampilkan daftar target
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

go-build: ## Build semua package Go (control plane)
	go build ./...

go-test: ## Jalankan semua test Go
	go test ./...

go-vet: ## go vet untuk semua package Go
	go vet ./...

lint-skills: ## Validasi skills/ dengan skill-linter (§7.1)
	python tools/skill-linter/lint.py skills/

docker-build: ## Build semua image secara lokal (context = root repo)
	@set -e; for name in $(IMAGE_NAMES); do \
		echo "==> docker build -f runtimes/docker/images/$$name/Dockerfile -t hermes/$$name:dev ."; \
		docker build -f runtimes/docker/images/$$name/Dockerfile -t hermes/$$name:dev . ; \
	done
