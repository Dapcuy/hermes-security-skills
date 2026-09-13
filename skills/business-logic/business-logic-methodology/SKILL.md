---
name: business-logic-methodology
description: >
  Use when testing shifts to business logic flaws that signature-based
  scanners cannot see: map the application's state, workflows, transactions,
  replay surfaces, concurrency, and tenant boundaries, then route each
  hypothesis to the specific business-logic skill that can validate it.
version: 0.1.0
risk: medium
---

# Business Logic Methodology

## Purpose

- Menyediakan peta metodologi pengujian business logic: state, workflow, transaksi, replay/duplicate, race condition, dan tenant isolation (ROADMAP §6 Tier 6, §40).
- Memodelkan perilaku bisnis yang "benar" terlebih dahulu, agar pelanggaran bisa dirumuskan sebagai hypothesis yang falsifiable.
- Merutekan setiap hypothesis ke skill spesifik yang tepat, bukan menguji semuanya di satu tempat.

## When To Use

- Awal pengujian pada aplikasi dengan alur bisnis nyata: pemesanan, pembayaran, kuota, approval, atau multi-tenancy.
- Scanner dan checklist generik tidak menemukan apa pun, tetapi permukaan bisnis kompleks.
- Beberapa observation kecil terlihat "aneh" secara bisnis dan perlu diklasifikasikan sebelum divalidasi.

## When Not To Use

- Target tidak punya alur bisnis yang bermakna (mis. halaman statis) — metodologi ini akan menghasilkan hipotesis kosong.
- Hypothesis sudah spesifik dan tahu jalurnya — langsung ke skill spesifik (workflow-state-analysis, transaction-analysis, dan lainnya).
- Sebagai pengganti authorization testing dasar — cek dulu idor-and-bola/bfla sebelum berasumsi logika bisnisnya yang bermasalah.

## Authorization Preconditions

- Authorization `granted` atau `offline-lab` untuk seluruh alur yang akan dimodelkan dan diuji.
- Pemetaan alur boleh berjalan dari data terekam dan spesifikasi tanpa operasi aktif; eksekusi pengujian selalu lewat skill spesifik dengan approvalnya sendiri.
- Alur yang menyentuh uang, kuota nyata, atau data lintas tenant dianggap rawan dampak dan diperlakukan konservatif sejak awal.
- Test account multi-peran hanya dipakai melalui credential reference yang sah (ROADMAP §23).

## Required Context

- Pemahaman domain: fungsi bisnis utama, aktor, dan objek bernilai (pesanan, saldo, voucher, kuota, approval).
- Spesifikasi API atau traffic terekam yang menggambarkan alur normal (happy path) dan state-nya.
- Aturan bisnis yang eksplisit maupun tersirat: batasan urutan, kewajiban langkah, batas jumlah, dan kondisi kegagalan.
- Test account yang tersedia beserta perannya, dirujuk sebagai reference (ROADMAP §23).

## Required Capabilities

- `openapi_analysis` — membaca spesifikasi API yang tersedia untuk mengenumerasi endpoint bisnis, parameter state, dan alur yang mungkin.
- Capability ini read-only terhadap input analisis dan tidak mengirim traffic ke target.
- Tidak ada operasi aktif di skill peta ini; replay dan perbandingan respons diminta oleh skill spesifik tujuan rute, dengan approval masing-masing.

## Core Concepts

- **Model dulu, uang kemudian**: hypothesis business logic hanya bermakna bila perilaku normal sudah dimodelkan; tanpa model, "aneh" tidak bisa dibedakan dari "memang begini".
- **Enam permukaan utama**: state machine (urutan/lewati langkah), transaksi finansial, aksi duplikat/replay, concurrency, batas tenant, dan anomali pasif.
- **Rute, bukan monolit**: tiap permukaan punya skill validasinya sendiri dengan profil risk dan approval yang berbeda.
- **Signature-blind**: business logic flaws jarang punya signature — nilainya ada pada reasoning dan evidence kontekstual (ROADMAP §40).
- **Konservatif pada nilai nyata**: alur uang dan data lintas akun diperlakukan sebagai area approval tinggi sejak pemetaan.

## Reasoning Workflow

1. Enumerasi fungsi bisnis dari spesifikasi dan traffic terekam; daftarkan objek bernilai dan aktornya.
2. Modelkan alur normal per fungsi: langkah, urutan, state, dan batasannya — tuliskan sebagai state machine sederhana.
3. Untuk tiap alur, rumuskan kelas pelanggaran yang mungkin: langkah dilewati, urutan dibalik, aksi diulang, nilai dimanipulasi, batas lintas tenant.
4. Prioritaskan hypothesis berdasarkan dampak bisnis dan keterjangkauan pengujian yang aman.
5. Rutekan tiap hypothesis ke skill spesifik: workflow ke workflow-state-analysis, uang ke transaction-analysis, duplikat ke replay-and-duplicate-action-analysis, concurrency ke race-condition-analysis, batas tenant ke multi-tenant-isolation.
6. Observation pasif tanpa jalur aktif dianalisis lewat behavioral-anomaly-analysis; kombinasi temuan kecil dikawinkan lewat vulnerability-chaining.

## Allowed Operations

- Analisis spesifikasi dan traffic terekam untuk membangun model alur bisnis.
- Pembuatan dan pemeringkatan hypothesis business logic di hypothesis-management.
- Rekomendasi rute pengujian beserta estimasi risk dan budget per rute.

## Approval Requirements

- Skill ini tidak mengeksekusi replay; approval diurus skill tujuan rute sesuai risk-nya (ROADMAP §8, §9).
- Rute ke transaction-analysis dan race-condition-analysis selalu disifatkan HIGH: approval eksplisit wajib dan tidak pernah automatic.
- Estimasi budget per rute dituliskan sejak routing agar approval yang diajukan realistis dan terbatas.

## Forbidden Operations

- Mengeksekusi replay bisnis langsung dari skill peta ini tanpa lewat skill spesifik.
- Memodelkan dengan menguji: jangan "coba-coba" untuk memahami alur — gunakan data terekam dan spesifikasi.
- Mengabaikan preconditions authorization karena "hanya memetakan".
- Menyimpulkan business logic flaw dari satu respons aneh tanpa model perilaku normal.

## Evidence Requirements

- Model alur bisnis yang ditulis eksplisit (langkah, state, batasan) beserta sumber datanya (spesifikasi, request terekam).
- Daftar hypothesis yang dihasilkan: id, kelas pelanggaran, rute skill, estimasi risk dan budget.
- Keputusan prioritas beserta alasannya, agar audit bisa menelusuri mengapa satu alur diuji lebih dulu.

## False Positive Checks

- Apakah "pelanggaran" yang dimodelkan sebenarnya perilaku yang memang didesain begitu (mis. langkah opsional)?
- Apakah model alur sudah usang dibanding aplikasi sekarang (fitur berubah)?
- Apakah hypothesis bisa dijelaskan oleh masalah infrastruktur (cache, queue, eventual consistency)?
- Apakah dua observation yang terlihat berhubungan sebenarnya independen — jangan memaksa chain sejak tahap routing?

## Severity Guidance

- Pemetaan tidak menetapkan severity; severity lahir dari validasi dampak di skill tujuan rute.
- Alur yang menyentuh uang, kuota, atau data lintas akun diduga berdampak tinggi bila terbukti — tuliskan sebagai prioritas, bukan sebagai klaim severity.
- Rute yang tidak bisa diuji dengan aman tidak dipaksa; tandai sebagai gap dan pertahankan klaim dampak pada level argumentasi.

## Stop Conditions

- Tidak ada spesifikasi maupun traffic yang cukup untuk memodelkan satu alur pun → laporkan gap konteks, jangan menebak model.
- Authorization tidak mencakup alur bernilai tinggi → catat sebagai area yang tidak teruji, bukan area aman.
- Model menunjukkan alur yang tidak boleh diuji sama sekali (mis. pembayaran nyata non-sandbox) → tandai out-of-bounds dan hentikan rutenya (ROADMAP §10).

## Output Format

- Business logic map: daftar fungsi bisnis, model alur per fungsi, objek bernilai, dan aktor.
- Routing table: hypothesis id, kelas pelanggaran, skill tujuan, risk, estimasi budget, dan prioritas.
- Daftar gap: alur yang tidak bisa dimodelkan atau tidak boleh diuji beserta alasannya.

## Related Skills

- `workflow-state-analysis` — rute untuk pelanggaran state machine dan urutan langkah.
- `transaction-analysis` — rute untuk alur finansial dengan approval ketat.
- `replay-and-duplicate-action-analysis` — rute untuk aksi duplikat dan idempotency.
- `race-condition-analysis` — rute untuk concurrency terkontrol.
- `multi-tenant-isolation` — rute untuk batas antar tenant.
- `behavioral-anomaly-analysis` — analisis pasif atas anomali dari history.
- `vulnerability-chaining` — penggabungan temuan kecil menjadi chain berdampak.
