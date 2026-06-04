package main

import (
	"fmt"
	"math/rand"
	"runtime"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Benchmark Configuration
const NumRuns = 5

const FixedDBSizeNetworkScaling = 1000000

var NetworkScalingParticipants = []int{2, 3, 5, 10, 20, 30, 50}

const FixedParticipantsDataScaling = 10

var DataScalingDBSizes = []int{10000, 100000, 1000000, 10000000}

// Core Structures

type BenchmarkMetrics struct {
	KeyGenTime time.Duration
	EncTime    time.Duration
	AggTime    time.Duration
	ShareTime  time.Duration
	ResTime    time.Duration

	UploadBytes int
	BcastBytes  int
	ShareBytes  int

	PeakMemory uint64
}

type Participant struct {
	ID        int
	SecretKey *rlwe.SecretKey
	PublicKey *rlwe.PublicKey
	Encoder   *bgv.Encoder
	Encryptor *rlwe.Encryptor
	LocalSet  []bool
}

type SystemContext struct {
	Params bgv.Parameters
}

// Cryptographic Functions

func InitSystemContext() *SystemContext {
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{54, 54, 54},
		LogP:             []int{54},
		PlaintextModulus: 65537,
	})
	if err != nil {
		panic(fmt.Errorf("failed to initialize parameters: %v", err))
	}
	return &SystemContext{Params: params}
}

func NewParticipant(id int, sys *SystemContext, localData []bool) (*Participant, []*rlwe.Ciphertext, time.Duration, time.Duration, int) {
	startKeyGen := time.Now()
	kgen := rlwe.NewKeyGenerator(sys.Params)
	sk, pk := kgen.GenKeyPairNew()
	keyGenTime := time.Since(startKeyGen)

	encoder := bgv.NewEncoder(sys.Params)
	encryptor := rlwe.NewEncryptor(sys.Params, pk)

	p := &Participant{ID: id, SecretKey: sk, PublicKey: pk, Encoder: encoder, Encryptor: encryptor, LocalSet: localData}

	startEnc := time.Now()
	maxSlots := sys.Params.MaxSlots()
	numChunks := (len(localData) + maxSlots - 1) / maxSlots
	cts := make([]*rlwe.Ciphertext, numChunks)
	uploadSizeBytes := 0

	for c := 0; c < numChunks; c++ {
		startIdx := c * maxSlots
		endIdx := startIdx + maxSlots
		if endIdx > len(localData) {
			endIdx = len(localData)
		}

		values := make([]uint64, maxSlots)
		for i := startIdx; i < endIdx; i++ {
			if localData[i] {
				values[i-startIdx] = 1
			}
		}

		pt := bgv.NewPlaintext(sys.Params, sys.Params.MaxLevel())
		encoder.Encode(values, pt)
		ct, _ := encryptor.EncryptNew(pt)
		cts[c] = ct

		b, _ := ct.MarshalBinary()
		uploadSizeBytes += len(b)
	}
	return p, cts, keyGenTime, time.Since(startEnc), uploadSizeBytes
}

func LeaderAggregateAndMask(sys *SystemContext, participantCts [][]*rlwe.Ciphertext, numParticipants int) ([]*rlwe.Ciphertext, int) {
	evaluator := bgv.NewEvaluator(sys.Params, nil, true)
	encoder := bgv.NewEncoder(sys.Params)
	t := sys.Params.PlaintextModulus()
	numChunks := len(participantCts[0])
	mkCts := make([]*rlwe.Ciphertext, numChunks)
	broadcastSizeBytes := 0

	for c := 0; c < numChunks; c++ {
		level := participantCts[0][c].Level()
		valuesR := make([]uint64, sys.Params.MaxSlots())
		valuesN := make([]uint64, sys.Params.MaxSlots())

		for i := 0; i < sys.Params.MaxSlots(); i++ {
			valuesR[i] = uint64(rand.Intn(int(t)-1) + 1)
			valuesN[i] = uint64(numParticipants)
		}

		ptR := bgv.NewPlaintext(sys.Params, level)
		encoder.Encode(valuesR, ptR)
		ptN := bgv.NewPlaintext(sys.Params, level)
		encoder.Encode(valuesN, ptN)

		c0MinusN, _ := evaluator.SubNew(participantCts[0][c], ptN)
		maskedCts := make([]*rlwe.Ciphertext, numParticipants)
		maskedCts[0], _ = evaluator.MulNew(c0MinusN, ptR)

		for i := 1; i < numParticipants; i++ {
			maskedCts[i], _ = evaluator.MulNew(participantCts[i][c], ptR)
		}

		mkCt := maskedCts[0].CopyNew()
		ringQ := sys.Params.RingQ().AtLevel(level)

		for i := 1; i < numParticipants; i++ {
			mkCt.Value = append(mkCt.Value, ring.NewPoly(sys.Params.N(), level))
		}
		for i := 1; i < numParticipants; i++ {
			ringQ.Add(mkCt.Value[0], maskedCts[i].Value[0], mkCt.Value[0])
			(&mkCt.Value[i+1]).Copy(maskedCts[i].Value[1])
		}
		mkCts[c] = mkCt

		b, _ := mkCt.MarshalBinary()
		broadcastSizeBytes += len(b)
	}
	return mkCts, broadcastSizeBytes
}

func (p *Participant) GenerateDecryptionShares(sys *SystemContext, mkCts []*rlwe.Ciphertext, idx int) ([]ring.Poly, int) {
	shares := make([]ring.Poly, len(mkCts))
	shareBytes := 0

	for c, mkCt := range mkCts {
		level := mkCt.Level()
		ringQ := sys.Params.RingQ().AtLevel(level)
		c_i := mkCt.Value[idx+1]
		cNtt := ring.NewPoly(sys.Params.N(), level)
		shareNtt := ring.NewPoly(sys.Params.N(), level)
		shareOut := ring.NewPoly(sys.Params.N(), level)

		if mkCt.IsNTT {
			(&cNtt).Copy(c_i)
		} else {
			ringQ.NTT(c_i, cNtt)
		}
		ringQ.MulCoeffsMontgomery(cNtt, p.SecretKey.Value.Q, shareNtt)

		if mkCt.IsNTT {
			(&shareOut).Copy(shareNtt)
		} else {
			ringQ.INTT(shareNtt, shareOut)
		}
		shares[c] = shareOut

		b, _ := shareOut.MarshalBinary()
		shareBytes += len(b)
	}
	return shares, shareBytes
}

func LeaderAggregateAndResolve(sys *SystemContext, mkCts []*rlwe.Ciphertext, participantShares [][]ring.Poly, dbSize int) {
	numChunks := len(mkCts)
	numParticipants := len(participantShares)
	dummySk := rlwe.NewSecretKey(sys.Params)
	decryptor := bgv.NewDecryptor(sys.Params, dummySk)
	encoder := bgv.NewEncoder(sys.Params)

	for c := 0; c < numChunks; c++ {
		mkCt := mkCts[c]
		level := mkCt.Level()
		ringQ := sys.Params.RingQ().AtLevel(level)
		phase := ring.NewPoly(sys.Params.N(), level)
		(&phase).Copy(mkCt.Value[0])

		for p := 0; p < numParticipants; p++ {
			ringQ.Add(phase, participantShares[p][c], phase)
		}
		zeroPoly := ring.NewPoly(sys.Params.N(), level)
		collapsedCt := mkCt.CopyNew()
		collapsedCt.Value = collapsedCt.Value[:2]
		collapsedCt.Value[0] = phase
		collapsedCt.Value[1] = zeroPoly

		ptFinal := bgv.NewPlaintext(sys.Params, level)
		decryptor.Decrypt(collapsedCt, ptFinal)
		chunkValues := make([]uint64, sys.Params.MaxSlots())
		encoder.Decode(ptFinal, chunkValues)
	}
}

// Orchestrator Engine

func RunIteration(sys *SystemContext, n int, d int) BenchmarkMetrics {
	m := BenchmarkMetrics{}
	participants := make([]*Participant, n)
	cts := make([][]*rlwe.Ciphertext, n)

	for i := 0; i < n; i++ {
		localData := make([]bool, d)
		localData[0] = true
		p, pCts, kg, enc, upBytes := NewParticipant(i, sys, localData)
		participants[i] = p
		cts[i] = pCts
		m.KeyGenTime += kg
		m.EncTime += enc
		m.UploadBytes += upBytes
	}
	m.KeyGenTime /= time.Duration(n)
	m.EncTime /= time.Duration(n)
	m.UploadBytes /= n

	startAgg := time.Now()
	mkCts, bcastBytes := LeaderAggregateAndMask(sys, cts, n)
	m.AggTime = time.Since(startAgg)
	m.BcastBytes = bcastBytes

	shares := make([][]ring.Poly, n)
	for i := 0; i < n; i++ {
		startSh := time.Now()
		sh, shBytes := participants[i].GenerateDecryptionShares(sys, mkCts, i)
		m.ShareTime += time.Since(startSh)
		m.ShareBytes += shBytes
		shares[i] = sh
	}
	m.ShareTime /= time.Duration(n)
	m.ShareBytes /= n

	startRes := time.Now()
	LeaderAggregateAndResolve(sys, mkCts, shares, d)
	m.ResTime = time.Since(startRes)

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	m.PeakMemory = mem.Sys

	// Force garbage collection to maintain consistent memory profiling
	runtime.GC()
	return m
}

func formatTime(d time.Duration) string { return fmt.Sprintf("%.2fs", d.Seconds()) }
func formatBytes(b int) string          { return fmt.Sprintf("%.2f MB", float64(b)/(1024*1024)) }

func main() {
	rand.Seed(time.Now().UnixNano())
	sys := InitSystemContext()

	fmt.Println("Starting MP-PSI Benchmark Suite")
	fmt.Printf("Iterations per configuration: %d\n\n", NumRuns)

	var absolutePeakMemory uint64 = 0

	// Test Group 1: Network Scalability
	t1Results := make(map[int]BenchmarkMetrics)

	fmt.Printf("[+] Evaluating Network Scalability (Fixed |D| = %d)\n", FixedDBSizeNetworkScaling)
	for _, n := range NetworkScalingParticipants {
		var avg BenchmarkMetrics
		for r := 0; r < NumRuns; r++ {
			fmt.Printf("    - Benchmarking n=%d (Iteration %d/%d)...\n", n, r+1, NumRuns)
			res := RunIteration(sys, n, FixedDBSizeNetworkScaling)
			avg.KeyGenTime += res.KeyGenTime
			avg.EncTime += res.EncTime
			avg.AggTime += res.AggTime
			avg.ShareTime += res.ShareTime
			avg.ResTime += res.ResTime
			if res.PeakMemory > absolutePeakMemory {
				absolutePeakMemory = res.PeakMemory
			}
		}

		avg.KeyGenTime /= time.Duration(NumRuns)
		avg.EncTime /= time.Duration(NumRuns)
		avg.AggTime /= time.Duration(NumRuns)
		avg.ShareTime /= time.Duration(NumRuns)
		avg.ResTime /= time.Duration(NumRuns)
		t1Results[n] = avg
	}

	// Test Group 2: Database Scalability
	t2Results := make(map[int]BenchmarkMetrics)

	fmt.Printf("\n[+] Evaluating Database Scalability (Fixed n = %d)\n", FixedParticipantsDataScaling)
	for _, d := range DataScalingDBSizes {
		var avg BenchmarkMetrics
		for r := 0; r < NumRuns; r++ {
			fmt.Printf("    - Benchmarking |D|=%d (Iteration %d/%d)...\n", d, r+1, NumRuns)
			res := RunIteration(sys, FixedParticipantsDataScaling, d)
			avg.UploadBytes += res.UploadBytes
			avg.BcastBytes += res.BcastBytes
			avg.ShareBytes += res.ShareBytes
			if res.PeakMemory > absolutePeakMemory {
				absolutePeakMemory = res.PeakMemory
			}
		}

		avg.UploadBytes /= NumRuns
		avg.BcastBytes /= NumRuns
		avg.ShareBytes /= NumRuns
		t2Results[d] = avg
	}

	// Output Formatting
	fmt.Println("\n---------------------------------------------------------")
	fmt.Println("Benchmark Results (LaTeX format)")
	fmt.Println("---------------------------------------------------------\n")

	fmt.Printf("System Peak Memory Usage: %s\n\n", formatBytes(int(absolutePeakMemory)))

	fmt.Println("\\begin{table}[h]")
	fmt.Printf("\\caption{Computational Overhead (Time). Fixed $|\\mathcal{D}| = %d$.}\\label{tab:time_benchmarks}\n", FixedDBSizeNetworkScaling)
	fmt.Println("\\centering")
	fmt.Println("\\begin{tabular}{|c|c|c|c|c|}")
	fmt.Println("\\hline")
	fmt.Println("$n$ & KeyGen + Encrypt ($P_i$) & Agg. \\& Mask (Leader) & Share Gen ($P_i$) & Resolution (Leader) \\\\ \\hline")
	for _, n := range NetworkScalingParticipants {
		m := t1Results[n]
		kgEnc := formatTime(m.KeyGenTime + m.EncTime)
		fmt.Printf("%d & %s & %s & %s & %s \\\\ \\hline\n", n, kgEnc, formatTime(m.AggTime), formatTime(m.ShareTime), formatTime(m.ResTime))
	}
	fmt.Println("\\end{tabular}")
	fmt.Println("\\end{table}")

	fmt.Println("\n\\vspace{0.5cm}\n")

	fmt.Println("\\begin{table}[h]")
	fmt.Printf("\\caption{Communication Complexity (Bandwidth). Fixed $n = %d$.}\\label{tab:bw_benchmarks}\n", FixedParticipantsDataScaling)
	fmt.Println("\\centering")
	fmt.Println("\\begin{tabular}{|c|c|c|c|c|}")
	fmt.Println("\\hline")
	fmt.Println("$|\\mathcal{D}|$ & Chunks & Upload $C_i$ ($P_i$) & Broadcast $C_{masked}$ & Decrypt Share ($P_i$) \\\\ \\hline")
	for _, d := range DataScalingDBSizes {
		m := t2Results[d]
		chunks := (d + sys.Params.MaxSlots() - 1) / sys.Params.MaxSlots()
		fmt.Printf("%d & %d & %s & %s & %s \\\\ \\hline\n", d, chunks, formatBytes(m.UploadBytes), formatBytes(m.BcastBytes), formatBytes(m.ShareBytes))
	}
	fmt.Println("\\end{tabular}")
	fmt.Println("\\end{table}")
}
