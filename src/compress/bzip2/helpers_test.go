// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bzip2

import (
	"bytes"
	"runtime"
)

// A bitWriter writes bits most-significant first, as bzip2 streams hold them.
type bitWriter struct {
	buf  []byte
	n    byte
	bits uint
}

func (w *bitWriter) write(v uint64, bits uint) {
	for bits > 0 {
		bits--
		w.n = w.n<<1 | byte(v>>bits&1)
		w.bits++
		if w.bits == 8 {
			w.buf = append(w.buf, w.n)
			w.n, w.bits = 0, 0
		}
	}
}

// bytes returns the bits written, padded with zeros to a whole byte.
func (w *bitWriter) bytes() []byte {
	for w.bits != 0 {
		w.write(0, 1)
	}
	return w.buf
}

// runStream returns a stream with the given compression level and a block
// for each of runs, as written by writeRunBlock with numTrees trees.
func runStream(level, numTrees int, runs ...int) []byte {
	var w bitWriter
	w.write(bzip2FileMagic<<16|'h'<<8|uint64('0'+level), 32)
	var crc uint32
	for _, run := range runs {
		crc = (crc<<1 | crc>>31) ^ writeRunBlock(&w, run, numTrees)
	}
	w.write(bzip2FinalMagic, 48)
	w.write(uint64(crc), 32)
	return w.bytes()
}

// writeRunBlock writes a block that decodes to run bytes of value 1, using
// numTrees Huffman trees, and returns the block's CRC.
func writeRunBlock(w *bitWriter, run, numTrees int) uint32 {
	crc := updateCRC(0, bytes.Repeat([]byte{1}, run))
	w.write(bzip2BlockMagic, 48)
	w.write(uint64(crc), 32)
	w.write(0, 1)       // not randomized
	w.write(0, 24)      // origPtr
	w.write(0x8000, 16) // symbols 0-15 are used...
	w.write(0x4000, 16) // ...but only symbol 1

	// Undoing the initial run-length encoding of run 1s gives run 1s, so the
	// block is a run of the first symbol. Its length is coded as RUNA (1) and
	// RUNB (2) digits, least significant first, followed by end of block.
	const runA, runB, endOfBlock = 0, 1, 2
	var syms []int
	for n := run; n > 0; {
		d := 2 - n%2
		syms = append(syms, d-1)
		n = (n - d) / 2
	}
	syms = append(syms, endOfBlock)

	w.write(uint64(numTrees), 3)
	numSelectors := (len(syms) + 49) / 50
	w.write(uint64(numSelectors), 15)
	for range numSelectors {
		w.write(0, 1) // tree 0
	}
	// Every tree gives RUNA, RUNB and end of block code lengths 1, 2 and 2,
	// so their codes are 0, 10 and 11.
	for range numTrees {
		w.write(1, 5)
		w.write(0b01000, 5)
	}
	codes := [...]struct {
		code uint64
		bits uint
	}{runA: {0b0, 1}, runB: {0b10, 2}, endOfBlock: {0b11, 2}}
	for _, s := range syms {
		w.write(codes[s].code, codes[s].bits)
	}
	return crc
}

// allocated returns the number of bytes f allocates.
func allocated(f func()) int64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return int64(after.TotalAlloc - before.TotalAlloc)
}
