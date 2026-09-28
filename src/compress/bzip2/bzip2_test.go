// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bzip2

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"internal/obscuretestdata"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

// readerSources wrap a non-ByteReader to exercise each input path.
var readerSources = []struct {
	name string
	wrap func(io.Reader) io.Reader
}{
	{"io.Reader", func(r io.Reader) io.Reader { return r }},
	{"io.ByteReader", func(r io.Reader) io.Reader { return byteReader{r} }},
	{"bufio.Reader", func(r io.Reader) io.Reader { return bufio.NewReader(r) }},
	{"bufio.Reader/16", func(r io.Reader) io.Reader { return bufio.NewReaderSize(r, 16) }},
	{"bufio.Reader/OneByteReader", func(r io.Reader) io.Reader { return bufio.NewReader(iotest.OneByteReader(r)) }},
}

func plainReader(b []byte) io.Reader {
	return struct{ io.Reader }{bytes.NewReader(b)}
}

// byteReader is an unbuffered io.ByteReader.
type byteReader struct{ r io.Reader }

func (br byteReader) Read(p []byte) (int, error) { return br.r.Read(p) }

func (br byteReader) ReadByte() (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(br.r, b[:])
	return b[0], err
}

var helloWorld = mustDecodeHex("" +
	"425a68393141592653594eece83600000251800010400006449080200031064c" +
	"4101a7a9a580bb9431f8bb9229c28482776741b0",
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

func TestReader(t *testing.T) {
	var vectors = []struct {
		desc   string
		input  []byte
		output []byte
		fail   bool
	}{{
		desc:   "hello world",
		input:  helloWorld,
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
		desc: "1MiB zeros",
		input: mustDecodeHex("" +
			"425a683931415926535938571ce50008084000c0040008200030cc0529a60806" +
			"c4201e2ee48a70a12070ae39ca",
		),
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
		for _, src := range readerSources {
			rd := NewReader(src.wrap(plainReader(v.input)))
			buf, err := io.ReadAll(rd)

			if fail := bool(err != nil); fail != v.fail {
				if fail {
					t.Errorf("test %d (%s), %s: unexpected failure: %v", i, v.desc, src.name, err)
				} else {
					t.Errorf("test %d (%s), %s: unexpected success", i, v.desc, src.name)
				}
			}
			if !v.fail && !bytes.Equal(buf, v.output) {
				t.Errorf("test %d (%s), %s: output mismatch:\ngot  %s\nwant %s", i, v.desc, src.name, trim(buf), trim(v.output))
			}
		}
	}
}

func TestReaderTruncated(t *testing.T) {
	for n := range len(helloWorld) {
		for _, src := range readerSources {
			_, err := io.ReadAll(NewReader(src.wrap(plainReader(helloWorld[:n]))))
			if err != io.ErrUnexpectedEOF {
				t.Errorf("%s: stream truncated to %d bytes: got error %v, want %v", src.name, n, err, io.ErrUnexpectedEOF)
			}
		}
	}
}

// errOnceReader returns err once and then io.EOF, like a *bufio.Reader.
type errOnceReader struct{ err error }

func (r *errOnceReader) Read([]byte) (int, error) {
	err := r.err
	if err == nil {
		return 0, io.EOF
	}
	r.err = nil
	return 0, err
}

func TestReaderReadError(t *testing.T) {
	errRead := errors.New("read error")
	for n := range len(helloWorld) + 1 {
		for _, src := range readerSources {
			r := io.MultiReader(bytes.NewReader(helloWorld[:n]), &errOnceReader{errRead})
			_, err := io.ReadAll(NewReader(src.wrap(r)))
			if err != errRead {
				t.Errorf("%s: read error after %d bytes: got error %v, want %v", src.name, n, err, errRead)
			}
		}
	}
}

func TestReaderStopsAtEndOfStream(t *testing.T) {
	input := append(bytes.Clone(helloWorld), "not bzip2"...)
	for _, src := range readerSources {
		r := src.wrap(plainReader(input))
		if _, ok := r.(io.ByteReader); !ok {
			continue // NewReader may read ahead from other readers.
		}
		if _, err := io.ReadAll(NewReader(r)); err == nil {
			t.Fatalf("%s: unexpected success decoding stream with trailing garbage", src.name)
		}
		rest, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		// The decoder reads two bytes looking for another stream.
		if string(rest) != "t bzip2" {
			t.Errorf("%s: remaining input = %q, want %q", src.name, rest, "t bzip2")
		}
	}
}

func TestReaderErrorsAreSticky(t *testing.T) {
	badStreamCRC := bytes.Clone(helloWorld)
	badStreamCRC[len(badStreamCRC)-2] ^= 1

	// A block with 7 Huffman trees, which is invalid, before a valid one.
	var w bitWriter
	w.write(bzip2FileMagic<<16|'h'<<8|'1', 32)
	writeRunBlock(&w, 10, 2)
	w.write(bzip2BlockMagic, 48)
	w.write(0, 32+1+24) // CRC, randomized and origPtr
	w.write(0x8000, 16)
	w.write(0x4000, 16)
	w.write(7, 3)
	writeRunBlock(&w, 10, 2)
	w.write(bzip2FinalMagic, 48)
	w.write(0, 32) // never checked
	badBlock := w.bytes()

	for _, input := range [][]byte{badStreamCRC, badBlock} {
		r := NewReader(bytes.NewReader(input))
		_, err := io.ReadAll(r)
		if err == nil {
			t.Fatalf("decoding %x: unexpected success", input)
		}
		for range 3 {
			if n, err2 := r.Read(make([]byte, 100)); n != 0 || err2 != err {
				t.Errorf("decoding %x: Read after error %v = %d, %v; want 0, %v", input, err, n, err2, err)
			}
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

	for _, src := range readerSources {
		rd := src.wrap(plainReader([]byte{0xab, 0x12, 0x34, 0x56, 0x78, 0x71, 0x3f, 0x8d}))
		br := newBitReader(rd)
		for i, v := range vectors {
			val := br.ReadBits(v.nbits)
			if fail := bool(br.err != nil); fail != v.fail {
				if fail {
					t.Errorf("%s: test %d, unexpected failure: ReadBits(%d) = %v", src.name, i, v.nbits, br.err)
				} else {
					t.Errorf("%s: test %d, unexpected success: ReadBits(%d) = nil", src.name, i, v.nbits)
				}
			}
			if !v.fail && val != v.value {
				t.Errorf("%s: test %d, mismatching value: ReadBits(%d) = %d, want %d", src.name, i, v.nbits, val, v.value)
			}
		}
	}
}

func TestBitReaderFill(t *testing.T) {
	input := []byte{0xab, 0x12, 0x34, 0x56, 0x78, 0x71, 0x3f, 0x8d, 0x01, 0x02}
	var vectors = []struct {
		desc   string
		input  []byte
		before uint     // bits to read before fill
		after  []uint   // bits to read after fill
		values []uint64 // expected values of the reads after fill
		rest   string   // input fill should leave unread
	}{{
		desc:   "empty buffer",
		input:  input,
		after:  []uint{32, 32},
		values: []uint64{0xab123456, 0x78713f8d},
		rest:   "\x01\x02",
	}, {
		desc:   "partial byte buffered",
		input:  input,
		before: 3,
		after:  []uint{29, 32},
		values: []uint64{0x0b123456, 0x78713f8d},
		rest:   "\x01\x02",
	}, {
		desc:   "short input",
		input:  input[:2],
		after:  []uint{16},
		values: []uint64{0xab12},
		rest:   "",
	}}

	for _, v := range vectors {
		for _, src := range readerSources {
			r := src.wrap(plainReader(v.input))
			if _, ok := r.(io.ByteReader); !ok {
				continue // NewReader may read ahead from other readers.
			}
			br := newBitReader(r)
			br.ReadBits64(v.before)
			br.fill()
			br.commit()
			if br.err != nil {
				t.Errorf("%s (%s): fill failed: %v", v.desc, src.name, br.err)
			}

			rest, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if string(rest) != v.rest {
				t.Errorf("%s (%s): fill left %q unread, want %q", v.desc, src.name, rest, v.rest)
			}
			for i, bits := range v.after {
				if val := br.ReadBits64(bits); val != v.values[i] || br.err != nil {
					t.Errorf("%s (%s): ReadBits64(%d) = %#x, %v; want %#x, nil", v.desc, src.name, bits, val, br.err, v.values[i])
				}
			}
			if br.ReadBits64(1); br.err != io.ErrUnexpectedEOF {
				t.Errorf("%s (%s): reading past the input: got error %v, want %v", v.desc, src.name, br.err, io.ErrUnexpectedEOF)
			}
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

func benchmarkDecode(b *testing.B, compressed []byte, newSource func([]byte) io.Reader) {
	// Determine the uncompressed size of testfile.
	uncompressedSize, err := io.Copy(io.Discard, NewReader(bytes.NewReader(compressed)))
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(uncompressedSize)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		io.Copy(io.Discard, NewReader(newSource(compressed)))
	}
}

func newBytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func BenchmarkDecodeDigits(b *testing.B) { benchmarkDecode(b, digits, newBytesReader) }
func BenchmarkDecodeNewton(b *testing.B) { benchmarkDecode(b, newton, newBytesReader) }
func BenchmarkDecodeRand(b *testing.B)   { benchmarkDecode(b, random, newBytesReader) }

// The Reader benchmarks decode from a non-ByteReader, like an *os.File.
func BenchmarkDecodeReaderDigits(b *testing.B) { benchmarkDecode(b, digits, plainReader) }
func BenchmarkDecodeReaderNewton(b *testing.B) { benchmarkDecode(b, newton, plainReader) }
func BenchmarkDecodeReaderRand(b *testing.B)   { benchmarkDecode(b, random, plainReader) }
