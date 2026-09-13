---
name: skill-bad-credential
description: >
  Fixture invalid untuk test skill-linter: seluruh section wajib ada, tetapi
  di dalamnya tersembunyi satu credential literal yang harus tertangkap
  aturan credential-literal.
version: 0.1.0
risk: low
---

# Skill Bad Credential

## Purpose

- Fixture ini lengkap secara struktur, tetapi mengandung satu credential literal.
- Linter harus menandainya sebagai credential-literal, dan hanya itu.

## When To Use

- Hanya dipakai oleh test suite skill-linter.

## When Not To Use

- Jangan pernah dijadikan contoh penulisan yang benar.

## Authorization Preconditions

- Tidak ada operasi; fixture murni untuk test aturan credential.

## Required Context

- Tidak ada konteks engagement; hanya test pola.

## Required Capabilities

Tidak ada. Fixture ini tidak meminta capability apa pun ke control plane.

## Core Concepts

- Kredensial disimpan di credential store dan hanya dirujuk sebagai reference (ROADMAP §23).

## Reasoning Workflow

1. Jalankan linter terhadap fixture ini.
2. Pastikan aturan credential-literal terpicu pada baris yang menyematkan literal.

## Allowed Operations

- Membaca file fixture ini di dalam test.

## Approval Requirements

- Tidak ada operasi yang membutuhkan approval.

## Forbidden Operations

- Menyalin pola penulisan di fixture ini ke skill sungguhan.

## Evidence Requirements

- Artifact wajib disanitasi sebelum dipersist.
- Contoh penulisan yang SALAH dan harus tertangkap linter:

  ```
  api_key = "sk-live-9f8e7d6c5b4a3210"
  ```

## False Positive Checks

- Nilai di atas bukan placeholder seperti contoh-value, jadi tidak boleh terlewat.

## Severity Guidance

- Tidak ada severity; fixture tidak menghasilkan finding.

## Stop Conditions

- Linter gagal menandai literal di atas berarti ada bug pada aturan credential-literal.

## Output Format

- Pesan linter menyebut key dan nomor baris tanpa menampilkan nilainya.

## Related Skills

- Tidak ada.
