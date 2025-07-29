# To run the tests 

1. Clear the Test Cache (optional, to ensure fresh results):

```bash
go clean -testcache
```

2. Run Unit Tests to Populate vectorsoutput.txt:

This runs init and TestVectors, writing:"Using opcode: SphinxHash=0x10" and inputLen: <length>, hash: <hash> from init.
"Using opcode: SphinxHash=0x10 (cached)" and test vector lines from TestVectors.


```bash
go test -v
```

3. Run Benchmarks to Append Benchmark Results:
This runs BenchmarkSpxHash, appending to vectorsoutput.txt:"Using opcode: SphinxHash=0x10 (cached)" for each input length.
Benchmark results (e.g., BenchmarkSpxHash/inputLen=0-8 1000 1203456 ns/op).
Header (=== RUN   BenchmarkSpxHash) and footer (--- PASS: BenchmarkSpxHash).


```bash
go test -bench=.
```

4. Run Both Tests and Benchmarks Together (recommended):
This runs both TestVectors and BenchmarkSpxHash, ensuring all output is written to vectorsoutput.txt in a single run.


```bash
go test -v -bench=.
```

5. Save Terminal Output (Optional):
To capture all terminal output for reference:


```bash
go test -v -bench=. > all_output.txt
```

6. Profiling for Performance:
If benchmark results show high ns/op values, profile the code:
This will identify bottlenecks in common.SpxHash (e.g., Argon2 or excessive rounds).

```bash
go test -bench=. -cpuprofile=cpu.prof
go tool pprof cpu.prof
```

6. nconsistent Benchmark Iteration Counts:

The BenchmarkSpxHash results show multiple runs for each input length with varying b.N values (e.g., 1, 100, 10000, 130010, 166723 for inputLen=0). This is normal for Go benchmarks as the testing framework increases b.N to stabilize measurements, but the output includes redundant runs.
Impact: The multiple runs clutter the output and vectorsoutput.txt, making it harder to analyze the most stable results (typically those with higher b.N).
Fix: Use the -benchtime flag to control benchmark duration and stabilize b.N. For example:

This runs each benchmark for 3 seconds, producing more consistent b.N values. Alternatively, modify the benchmark to log only the final result with the highest b.N.

```bash
go test -v -bench=. -benchtime=3s -cpuprofile=cpu.prof
go tool pprof cpu.prof
```

7. Issues in the OutputMultiple Benchmark Runs per Input Length:

Each input length has multiple benchmark results with varying b.N (e.g., inputLen=0 for SpxHash has b.N=1, 100, 10000, 845132). This is normal for Go benchmarks but clutters the output and makes it harder to identify the most stable results.
Impact: The single-iteration runs (b.N=1) are unreliable (e.g., 7986 ns/op for inputLen=0 vs. 4909.421180 ns/op for b.N=845132), as they are affected by system noise.
Fix: Use -benchtime to increase benchmark duration and stabilize b.N:

```bash
go test -v -bench=. -benchtime=5s -cpuprofile=cpu.prof
go tool pprof cpu.prof
```
