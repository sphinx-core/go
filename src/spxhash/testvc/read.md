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