// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bzip2

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"internal/obscuretestdata"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustLoadFile(f string) []byte {
	if strings.HasSuffix(f, ".base64") {
		b, err := obscuretestdata.ReadFile(f)
		if err != nil {
			panic(fmt.Sprintf("obscuretestdata.ReadFile(%s): %v", f, err))
		}
		return b
	}

	b, err := os.ReadFile(f)
	if err != nil {
		panic(err)
	}
	return b
}

func trim(b []byte) string {
	const limit = 1024
	if len(b) < limit {
		return fmt.Sprintf("%q", b)
	}
	return fmt.Sprintf("%q...", b[:limit])
}

var zeros1MiB = mustDecodeHex("" +
	"425a683931415926535938571ce50008084000c0040008200030cc0529a60806" +
	"c4201e2ee48a70a12070ae39ca",
)

func TestReader(t *testing.T) {
	var vectors = []struct {
		desc   string
		input  []byte
		output []byte
		fail   bool
	}{{
		desc: "hello world",
		input: mustDecodeHex("" +
			"425a68393141592653594eece83600000251800010400006449080200031064c" +
			"4101a7a9a580bb9431f8bb9229c28482776741b0",
		),
		output: []byte("hello world\n"),
	}, {
		desc: "concatenated files",
		input: mustDecodeHex("" +
			"425a68393141592653594eece83600000251800010400006449080200031064c" +
			"4101a7a9a580bb9431f8bb9229c28482776741b0425a68393141592653594eec" +
			"e83600000251800010400006449080200031064c4101a7a9a580bb9431f8bb92" +
			"29c28482776741b0",
		),
		output: []byte("hello world\nhello world\n"),
	}, {
		desc: "32B zeros",
		input: mustDecodeHex("" +
			"425a6839314159265359b5aa5098000000600040000004200021008283177245" +
			"385090b5aa5098",
		),
		output: make([]byte, 32),
	}, {
		desc:   "1MiB zeros",
		input:  zeros1MiB,
		output: make([]byte, 1<<20),
	}, {
		desc:   "random data",
		input:  mustLoadFile("testdata/pass-random1.bz2"),
		output: mustLoadFile("testdata/pass-random1.bin"),
	}, {
		desc:   "random data - full symbol range",
		input:  mustLoadFile("testdata/pass-random2.bz2"),
		output: mustLoadFile("testdata/pass-random2.bin"),
	}, {
		desc: "random data - uses RLE1 stage",
		input: mustDecodeHex("" +
			"425a6839314159265359d992d0f60000137dfe84020310091c1e280e100e0428" +
			"01099210094806c0110002e70806402000546034000034000000f28300000320" +
			"00d3403264049270eb7a9280d308ca06ad28f6981bee1bf8160727c7364510d7" +
			"3a1e123083421b63f031f63993a0f40051fbf177245385090d992d0f60",
		),
		output: mustDecodeHex("" +
			"92d5652616ac444a4a04af1a8a3964aca0450d43d6cf233bd03233f4ba92f871" +
			"9e6c2a2bd4f5f88db07ecd0da3a33b263483db9b2c158786ad6363be35d17335" +
			"ba",
		),
	}, {
		desc:  "1MiB sawtooth",
		input: mustLoadFile("testdata/pass-sawtooth.bz2"),
		output: func() []byte {
			b := make([]byte, 1<<20)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(),
	}, {
		desc:  "RLE2 buffer overrun - issue 5747",
		input: mustLoadFile("testdata/fail-issue5747.bz2.base64"),
		fail:  true,
	}, {
		desc: "out-of-range selector - issue 8363",
		input: mustDecodeHex("" +
			"425a68393141592653594eece83600000251800010400006449080200031064c" +
			"4101a7a9a580bb943117724538509000000000",
		),
		fail: true,
	}, {
		desc: "bad block size - issue 13941",
		input: mustDecodeHex("" +
			"425a683131415926535936dc55330063ffc0006000200020a40830008b0008b8" +
			"bb9229c28481b6e2a998",
		),
		fail: true,
	}, {
		desc: "bad huffman delta",
		input: mustDecodeHex("" +
			"425a6836314159265359b1f7404b000000400040002000217d184682ee48a70a" +
			"12163ee80960",
		),
		fail: true,
	}}

	for i, v := range vectors {
		rd := NewReader(bytes.NewReader(v.input))
		buf, err := io.ReadAll(rd)

		if fail := bool(err != nil); fail != v.fail {
			if fail {
				t.Errorf("test %d (%s), unexpected failure: %v", i, v.desc, err)
			} else {
				t.Errorf("test %d (%s), unexpected success", i, v.desc)
			}
		}
		if !v.fail && !bytes.Equal(buf, v.output) {
			t.Errorf("test %d (%s), output mismatch:\ngot  %s\nwant %s", i, v.desc, trim(buf), trim(v.output))
		}
	}
}

func TestBitReader(t *testing.T) {
	var vectors = []struct {
		nbits uint // Number of bits to read
		value int  // Expected output value (0 for error)
		fail  bool // Expected operation failure?
	}{
		{nbits: 1, value: 1},
		{nbits: 1, value: 0},
		{nbits: 1, value: 1},
		{nbits: 5, value: 11},
		{nbits: 32, value: 0x12345678},
		{nbits: 15, value: 14495},
		{nbits: 3, value: 6},
		{nbits: 6, value: 13},
		{nbits: 1, fail: true},
	}

	rd := bytes.NewReader([]byte{0xab, 0x12, 0x34, 0x56, 0x78, 0x71, 0x3f, 0x8d})
	br := newBitReader(rd)
	for i, v := range vectors {
		val := br.ReadBits(v.nbits)
		if fail := bool(br.err != nil); fail != v.fail {
			if fail {
				t.Errorf("test %d, unexpected failure: ReadBits(%d) = %v", i, v.nbits, br.err)
			} else {
				t.Errorf("test %d, unexpected success: ReadBits(%d) = nil", i, v.nbits)
			}
		}
		if !v.fail && val != v.value {
			t.Errorf("test %d, mismatching value: ReadBits(%d) = %d, want %d", i, v.nbits, val, v.value)
		}
	}
}

func TestMTF(t *testing.T) {
	var vectors = []struct {
		idx int   // Input index
		sym uint8 // Expected output symbol
	}{
		{idx: 1, sym: 1}, // [1 0 2 3 4]
		{idx: 0, sym: 1}, // [1 0 2 3 4]
		{idx: 1, sym: 0}, // [0 1 2 3 4]
		{idx: 4, sym: 4}, // [4 0 1 2 3]
		{idx: 1, sym: 0}, // [0 4 1 2 3]
	}

	mtf := newMTFDecoderWithRange(5)
	for i, v := range vectors {
		sym := mtf.Decode(v.idx)
		t.Log(mtf)
		if sym != v.sym {
			t.Errorf("test %d, symbol mismatch: Decode(%d) = %d, want %d", i, v.idx, sym, v.sym)
		}
	}
}

// The block and stream CRCs check the output.
func TestReaderReadSizes(t *testing.T) {
	inputs := map[string][]byte{
		"digits":   digits,
		"newton":   newton,
		"random":   random,
		"sawtooth": mustLoadFile("testdata/pass-sawtooth.bz2"),
		"zeros":    zeros1MiB,
	}
	for name, input := range inputs {
		for _, size := range []int{1, 4097, 64 << 10} {
			r := NewReader(bytes.NewReader(input))
			buf := make([]byte, size)
			var err error
			for err == nil {
				_, err = r.Read(buf)
			}
			if err != io.EOF {
				t.Errorf("%s, reading %d bytes at a time: %v", name, size, err)
			}
		}
	}
}

// A stream whose blocks keep growing mustn't make the decoder reallocate
// for each block.
func TestDecodeGrowingBlocksAllocations(t *testing.T) {
	var runs []int
	for i := range 16 {
		runs = append(runs, 6000*(i+1))
	}
	decode := func(runs ...int) int64 {
		var n int64
		var err error
		input := runStream(1, 2, runs...)
		a := allocated(func() { n, err = io.Copy(io.Discard, NewReader(bytes.NewReader(input))) })
		want := 0
		for _, run := range runs {
			want += run
		}
		if err != nil || n != int64(want) {
			t.Fatalf("decoding blocks of %v bytes: got %d bytes, %v", runs, n, err)
		}
		return a
	}
	all, largest := decode(runs...), decode(runs[len(runs)-1])
	if all > 2*largest {
		t.Errorf("decoding growing blocks allocated %d bytes, more than twice the %d for the largest block alone", all, largest)
	}
}

// back grows geometrically, but never beyond the block size.
func TestBackWithinBlockSize(t *testing.T) {
	r := NewReader(bytes.NewReader(runStream(1, 2, 60000, 61000))).(*reader)
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatal(err)
	}
	if len(r.back) > r.blockSize {
		t.Errorf("len(back) = %d, more than the block size, %d", len(r.back), r.blockSize)
	}
}

// walkBlock must give the same bytes as a single forward walk, even for a
// corrupt block whose links form several cycles, so that the two chains don't
// meet.
func TestWalkBlock(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for range 1000 {
		n := 1 + rng.IntN(100)
		// Random links, with random bytes, and the inverse links.
		tt, back := make([]uint32, n), make([]uint32, n)
		for i, p := range rng.Perm(n) {
			tt[i] = uint32(p)<<8 | uint32(rng.IntN(256))
		}
		for i, e := range tt {
			back[e>>8] = uint32(i)<<8 | e&0xff
		}
		origPtr := uint(rng.IntN(n))

		want := make([]byte, n)
		p := tt[origPtr] >> 8
		for i := range want {
			want[i] = byte(tt[p])
			p = tt[p] >> 8
		}
		got := make([]byte, n)
		walkBlock(tt, back, origPtr, got)
		if !bytes.Equal(got, want) {
			t.Fatalf("walkBlock(%x, origPtr %d) = %x, want %x", tt, origPtr, got, want)
		}
	}
}

func TestZeroRead(t *testing.T) {
	b := mustDecodeHex("425a6839314159265359b5aa5098000000600040000004200021008283177245385090b5aa5098")
	r := NewReader(bytes.NewReader(b))
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
}

var (
	digits = mustLoadFile("testdata/e.txt.bz2")
	newton = mustLoadFile("testdata/Isaac.Newton-Opticks.txt.bz2")
	random = mustLoadFile("testdata/random.data.bz2")
)

func benchmarkDecode(b *testing.B, compressed []byte) {
	// Determine the uncompressed size of testfile.
	uncompressedSize, err := io.Copy(io.Discard, NewReader(bytes.NewReader(compressed)))
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(uncompressedSize)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(compressed)
		io.Copy(io.Discard, NewReader(r))
	}
}

func BenchmarkDecodeDigits(b *testing.B) { benchmarkDecode(b, digits) }
func BenchmarkDecodeNewton(b *testing.B) { benchmarkDecode(b, newton) }
func BenchmarkDecodeRand(b *testing.B)   { benchmarkDecode(b, random) }
