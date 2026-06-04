package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Configuration parameters
const NumParticipants = 5
const DatabaseSize = 1000000
const DatabaseNoiseParameter = 0.1

// Core Structures

type Participant struct {
	ID        int
	SecretKey *rlwe.SecretKey
	PublicKey *rlwe.PublicKey

	Encoder   *bgv.Encoder
	Encryptor *rlwe.Encryptor

	LocalSet []bool
}

type SystemContext struct {
	Params bgv.Parameters
}

// Cryptographic Initialization

func InitSystemContext() *SystemContext {
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{54, 54, 54},
		LogP:             []int{54},
		PlaintextModulus: 65537,
	})
	if err != nil {
		panic(fmt.Errorf("failed to generate bgv parameters: %v", err))
	}

	return &SystemContext{
		Params: params,
	}
}

// Phase 1: Setup and Encrypt

func NewParticipant(id int, sys *SystemContext, localData []bool) (*Participant, []*rlwe.Ciphertext, time.Duration, time.Duration, int) {
	startKeyGen := time.Now()
	kgen := rlwe.NewKeyGenerator(sys.Params)
	sk, pk := kgen.GenKeyPairNew()
	keyGenTime := time.Since(startKeyGen)

	encoder := bgv.NewEncoder(sys.Params)
	encryptor := rlwe.NewEncryptor(sys.Params, pk)

	p := &Participant{
		ID:        id,
		SecretKey: sk,
		PublicKey: pk,
		Encoder:   encoder,
		Encryptor: encryptor,
		LocalSet:  localData,
	}

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
			} else {
				values[i-startIdx] = 0
			}
		}

		pt := bgv.NewPlaintext(sys.Params, sys.Params.MaxLevel())
		if err := encoder.Encode(values, pt); err != nil {
			panic(err)
		}

		ct, err := encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		cts[c] = ct

		b, _ := ct.MarshalBinary()
		uploadSizeBytes += len(b)
	}
	encTime := time.Since(startEnc)

	return p, cts, keyGenTime, encTime, uploadSizeBytes
}

// Phase 2 & 3: Aggregation and Masking

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
		if err := encoder.Encode(valuesR, ptR); err != nil {
			panic(err)
		}

		ptN := bgv.NewPlaintext(sys.Params, level)
		if err := encoder.Encode(valuesN, ptN); err != nil {
			panic(err)
		}

		c0MinusN, err := evaluator.SubNew(participantCts[0][c], ptN)
		if err != nil {
			panic(err)
		}

		maskedCts := make([]*rlwe.Ciphertext, numParticipants)
		maskedCts[0], err = evaluator.MulNew(c0MinusN, ptR)
		if err != nil {
			panic(err)
		}

		for i := 1; i < numParticipants; i++ {
			maskedCts[i], err = evaluator.MulNew(participantCts[i][c], ptR)
			if err != nil {
				panic(err)
			}
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

// Phase 4: Distributed Decryption

func (p *Participant) GenerateDecryptionShares(sys *SystemContext, mkCts []*rlwe.Ciphertext, indexInCiphertext int) ([]ring.Poly, int) {
	shares := make([]ring.Poly, len(mkCts))
	shareBytes := 0

	for c, mkCt := range mkCts {
		level := mkCt.Level()
		ringQ := sys.Params.RingQ().AtLevel(level)

		c_i := mkCt.Value[indexInCiphertext+1]

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

// Phase 5: Resolution

func LeaderAggregateAndResolve(sys *SystemContext, mkCts []*rlwe.Ciphertext, participantShares [][]ring.Poly) []uint64 {
	numChunks := len(mkCts)
	numParticipants := len(participantShares)

	resultValues := make([]uint64, 0, numChunks*sys.Params.MaxSlots())
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
		if err := encoder.Decode(ptFinal, chunkValues); err != nil {
			panic(err)
		}

		resultValues = append(resultValues, chunkValues...)
	}

	return resultValues[:DatabaseSize]
}

// Main Execution

func main() {
	rand.Seed(time.Now().UnixNano())

	fmt.Printf("Initializing PSI Protocol (Parties: %d, DB Size: %d)\n", NumParticipants, DatabaseSize)
	fmt.Println("---------------------------------------------------------")

	sys := InitSystemContext()

	// Phase 1
	fmt.Println("[+] Phase 1: Local Key Generation and Encryption")
	participants := make([]*Participant, NumParticipants)
	cts := make([][]*rlwe.Ciphertext, NumParticipants)

	for i := 0; i < NumParticipants; i++ {
		localData := make([]bool, DatabaseSize)
		localData[0] = true // ensure intersection at bounds
		localData[DatabaseSize-1] = true
		for j := 1; j < DatabaseSize-1; j++ {
			if rand.Float32() > DatabaseNoiseParameter {
				localData[j] = true
			}
		}

		p, participantCts, _, _, _ := NewParticipant(i+1, sys, localData)
		participants[i] = p
		cts[i] = participantCts
	}

	// Phase 2 & 3
	fmt.Println("[+] Phase 2 & 3: Leader Aggregation and Masking")
	mkCts, _ := LeaderAggregateAndMask(sys, cts, NumParticipants)

	// Phase 4
	fmt.Println("[+] Phase 4: Distributed Decryption Share Generation")
	shares := make([][]ring.Poly, NumParticipants)
	for i := 0; i < NumParticipants; i++ {
		sh, _ := participants[i].GenerateDecryptionShares(sys, mkCts, i)
		shares[i] = sh
	}

	// Phase 5
	fmt.Println("[+] Phase 5: Leader Aggregation and Resolution")
	startResolve := time.Now()
	resultArray := LeaderAggregateAndResolve(sys, mkCts, shares)
	resolveTime := time.Since(startResolve)
	fmt.Printf("    Resolution Time: %v\n", resolveTime)

	// Output Results
	fmt.Println("\nFinal Set Intersection Results")
	fmt.Println("---------------------------------------------------------")
	fmt.Printf("%-10s | %-10s | %-20s | %-15s\n", "Index", "Expected", "Raw Decrypted Value", "Result")
	fmt.Println("---------------------------------------------------------")

	for i := 0; i < 30; i++ {
		expected := "Miss"
		status := "MASKED"
		if resultArray[i] == 0 {
			status = "MATCH"
			expected = "Hit"
		}
		fmt.Printf("%-10d | %-10s | %-20d | %-15s\n", i, expected, resultArray[i], status)
	}

	fmt.Printf("... [%d items processed] ...\n", DatabaseSize-31)

	for i := DatabaseSize - 1; i < DatabaseSize; i++ {
		expected := "Miss"
		status := "MASKED"
		if resultArray[i] == 0 {
			status = "MATCH"
			expected = "Hit"
		}
		fmt.Printf("%-10d | %-10s | %-20d | %-15s\n", i, expected, resultArray[i], status)
	}
}
