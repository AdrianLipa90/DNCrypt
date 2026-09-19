# NOEMA × DNCrypt × GREMLIN PhaseVec Miner v2

Experimental SHA256d mining kernel integrated on a feature branch. It keeps the Bitcoin hash function and target rule unchanged; measured gains come from implementation and scheduling only.

## Runtime path

```text
NOEMA live tether /dev/shm/ciel_noema
  -> DNCrypt / PhaseNav 36D control-plane tuning
  -> GREMLIN routing / candidate selection
  -> native C SHA256d hot path
     - precomputed first 64-byte midstate
     - 16-lane uint32 SIMD layout
     - schedule-ring variants
     - OpenMP parallelism
     - high-64 target prefilter
  -> full Python hashlib SHA256d verification of rare candidates
```

The hot loop deliberately does not call Q28, GREMLIN, or the 36D runtime per nonce. Those components remain in the tuning/control plane so their overhead does not reduce H/s.

## Files

- `noema_dncrypt_gremlin_phasevec_miner_v2.py` — NOEMA gate, native build/load, self-test, sharding and header mining driver.
- `sha256d_phasevec_v2.c` — native vectorized/OpenMP SHA256d kernels.
- `../../evidence/NOEMA_DNCRYPT_GREMLIN_PHASEVEC_BITCOIN_BENCHMARK_V3.json` — retained benchmark/evidence summary for this candidate.

The compiled `libsha256d_phasevec_v2.so` is intentionally not tracked. The Python driver rebuilds it with the local compiler because `-march=native` makes the binary host-specific.

## Correctness gates

The driver checks the Bitcoin genesis hash and compares 4096 nonce results against Python `hashlib` before mining. Candidate hits from the native high-64 prefilter are always verified with full SHA256d before being returned.

Mining requires the live NOEMA surface and fails closed when `execution_authorized != true`.

## Build / self-test

```text
python tools/mining/noema_dncrypt_gremlin_phasevec_miner_v2.py selftest --threads 4
```

Native build command used by the driver:

```text
gcc -O3 -march=native -fPIC -shared -fopenmp -funroll-loops -fomit-frame-pointer \
  tools/mining/sha256d_phasevec_v2.c \
  -o tools/mining/libsha256d_phasevec_v2.so
```

## Evidence boundary

The recorded candidate benchmark selected the `split` kernel with 4 threads and a 4,194,304-nonce batch. The evidence file records a median of about 100.335 MH/s on the measured host and the associated scalar/parallel baselines. These numbers are host-specific benchmark measurements, not a guarantee for another CPU and not a claim of increased SHA256d success probability.
