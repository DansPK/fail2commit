# SPEC-012 — Resource measurements

NFR-012 · TC-012 · Owner paths: benchmarks and verification reports.

Run scans and sandbox workers on demand. No Linux daemon or idle sandbox. One active sandbox build per user by default. Bound input bytes, graph traversal, advisory/cache footprint, process output and job duration. Where backend primitives support it, cap memory, processes and CPU. Report exact configured limits and distinguish incomplete scans from clean results. Benchmark release binary size, CLI startup, tray idle RAM, cold/warm scan overhead, cache size and peak memory of a native build separately. Record host spec, OS, tool versions and fixture; choose defaults from evidence and document them.
