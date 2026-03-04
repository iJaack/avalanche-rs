package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Equivalent types to avalanche-rs for fair comparison
type ID [32]byte

type Block struct {
	ID        ID     `json:"id"`
	ParentID  ID     `json:"parent_id"`
	Height    uint64 `json:"height"`
	Timestamp uint64 `json:"timestamp"`
	StateRoot ID     `json:"state_root"`
}

func hashID(data []byte) ID {
	return sha256.Sum256(data)
}

func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
}

func benchSHA256(n int) time.Duration {
	start := time.Now()
	for i := 0; i < n; i++ {
		_ = sha256.Sum256(uint64ToBytes(uint64(i)))
	}
	return time.Since(start)
}

func benchBlockChain(n int) time.Duration {
	start := time.Now()
	var parent ID
	for i := uint64(1); i <= uint64(n); i++ {
		id := hashID(uint64ToBytes(i))
		_ = Block{
			ID:        id,
			ParentID:  parent,
			Height:    i,
			Timestamp: i * 6,
			StateRoot: ID{},
		}
		parent = id
	}
	return time.Since(start)
}

func benchJSONRoundtrip(n int) time.Duration {
	block := Block{
		ID:        hashID([]byte("bench")),
		ParentID:  ID{},
		Height:    999,
		Timestamp: 12345,
		StateRoot: ID{},
	}

	start := time.Now()
	for i := 0; i < n; i++ {
		data, _ := json.Marshal(&block)
		var b Block
		_ = json.Unmarshal(data, &b)
	}
	return time.Since(start)
}

func benchHexRoundtrip(n int) time.Duration {
	var id ID
	for i := range id {
		id[i] = 0xAB
	}

	start := time.Now()
	for i := 0; i < n; i++ {
		h := hex.EncodeToString(id[:])
		_, _ = hex.DecodeString(h)
	}
	return time.Since(start)
}

func benchHashMap(n int) time.Duration {
	start := time.Now()
	m := make(map[ID]uint32, n)
	for i := uint32(0); i < uint32(n); i++ {
		id := hashID(uint64ToBytes(uint64(i)))
		m[id] = i
	}
	for i := uint32(0); i < uint32(n); i++ {
		id := hashID(uint64ToBytes(uint64(i)))
		_ = m[id]
	}
	return time.Since(start)
}

func report(name string, n int, elapsed time.Duration) {
	perOp := float64(elapsed.Nanoseconds()) / float64(n)
	throughput := float64(n) / elapsed.Seconds() / 1_000_000
	fmt.Printf("  %-40s total %8s  per-op %6.0f ns  throughput %8.1f M/s\n",
		fmt.Sprintf("%s (x%d)", name, n), elapsed.Round(time.Microsecond*100), perOp, throughput)
}

func main() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║          AvalancheGo (Go 1.25) — Local Benchmark Suite                  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Warmup
	_ = benchSHA256(10000)
	_ = benchBlockChain(10000)

	report("SHA-256 hash", 1_000_000, benchSHA256(1_000_000))
	report("Block chain build", 100_000, benchBlockChain(100_000))
	report("JSON roundtrip", 100_000, benchJSONRoundtrip(100_000))
	report("Hex roundtrip", 1_000_000, benchHexRoundtrip(1_000_000))
	report("HashMap stress", 200_000, benchHashMap(100_000))

	fmt.Println()
}
