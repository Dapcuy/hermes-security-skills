---
name: skill-bad-sections
description: >
  Fixture invalid untuk test skill-linter: beberapa section H2 wajib
  sengaja dihilangkan sehingga linter harus gagal dengan aturan
  missing-section.
version: 0.1.0
risk: low
---

# Skill Bad Sections

## Purpose

- Fixture ini sengaja tidak lengkap: section "Stop Conditions" dan "False Positive Checks" dihilangkan.
- Linter harus menandai keduanya sebagai missing-section, dan hanya itu.

## When To Use

- Hanya dipakai oleh test suite skill-linter.

## When Not To Use

- Jangan pernah dijadikan contoh format skill yang benar.

## Authorization Preconditions

- Tidak ada operasi; fixture murni untuk test format.

## Required Context

- Tidak ada konteks engagement; hanya test struktur.

## Required Capabilities

Tidak ada. Fixture ini tidak meminta capability apa pun ke control plane.

## Core Concepts

- Daftar section wajib tetap berlaku meski fixture ini menghilangkan sebagian.

## Reasoning Workflow

1. Jalankan linter terhadap fixture ini.
2. Pastikan aturan missing-section terpicu untuk kedua section yang hilang.

## Allowed Operations

- Membaca file fixture ini di dalam test.

## Approval Requirements

- Tidak ada operasi yang membutuhkan approval.

## Forbidden Operations

- Menyalin struktur ini sebagai skill sungguhan.

## Evidence Requirements

- Tidak ada evidence; fixture bukan bagian dari engagement.

## Severity Guidance

- Tidak ada severity; fixture tidak menghasilkan finding.

## Output Format

- Pesan linter berisi daftar section yang hilang.

## Related Skills

- Tidak ada.
