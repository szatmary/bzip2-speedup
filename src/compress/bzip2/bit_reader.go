// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bzip2

import (
	"bufio"
	"encoding/binary"
	"io"
)

// bitReader wraps an io.Reader and provides the ability to read values,
// bit-by-bit, from it. Its Read* methods don't return the usual error
// because the error handling was verbose. Instead, any error is kept and can
// be checked afterwards.
type bitReader struct {
	r   io.ByteReader
	buf *bufio.Reader // r, if it is a *bufio.Reader

	// window holds bytes peeked from buf, the first pos of which are consumed.
	window []byte
	pos    int

	n       uint64
	bits    uint
	err     error
	readErr error // the first error from r
}

// newBitReader returns a new bitReader reading from r. If r is not
// already an io.ByteReader, it will be converted via a bufio.Reader.
func newBitReader(r io.Reader) bitReader {
	byter, ok := r.(io.ByteReader)
	if !ok {
		byter = bufio.NewReader(r)
	}
	buf, _ := byter.(*bufio.Reader)
	return bitReader{r: byter, buf: buf}
}

func (br *bitReader) readByte() (byte, error) {
	if br.readErr != nil {
		return 0, br.readErr
	}
	if br.buf == nil {
		b, err := br.r.ReadByte()
		br.readErr = err
		return b, err
	}
	if br.pos == len(br.window) {
		if err := br.peek(); err != nil {
			br.readErr = err
			return 0, err
		}
	}
	b := br.window[br.pos]
	br.pos++
	return b, nil
}

// peek replaces the window with the bytes buffered in buf, blocking only if
// there are none.
func (br *bitReader) peek() error {
	br.commit()
	if br.buf.Buffered() == 0 {
		if _, err := br.buf.Peek(1); err != nil {
			return err
		}
	}
	br.window, _ = br.buf.Peek(br.buf.Buffered())
	return nil
}

// commit discards the consumed bytes of the window from buf.
func (br *bitReader) commit() {
	if br.buf == nil {
		return
	}
	br.buf.Discard(br.pos)
	br.window, br.pos = nil, 0
}

// fill reads whole bytes until more than 56 bits are buffered. It is only
// called while decoding a Huffman symbol, which is always followed by at
// least 80 bits (a magic number and a CRC), so it never reads past the end
// of a valid stream.
func (br *bitReader) fill() {
	if len(br.window)-br.pos >= 8 {
		v := binary.BigEndian.Uint64(br.window[br.pos:])
		k := (64 - br.bits) / 8
		br.n = br.n<<(8*k) | v>>(64-8*k)
		br.bits += 8 * k
		br.pos += int(k)
		return
	}
	for br.bits <= 56 {
		b, err := br.readByte()
		if err != nil {
			return
		}
		br.n = br.n<<8 | uint64(b)
		br.bits += 8
	}
}

// consume discards n bits, failing if fill ran out of input.
func (br *bitReader) consume(n uint) {
	if n > br.bits {
		br.missingBits()
		return
	}
	br.bits -= n
}

// missingBits reports that fill ran out of input before a whole code was
// buffered. Codes are at most maxCodeLength bits, so otherwise it's a bug.
func (br *bitReader) missingBits() {
	if br.readErr == nil {
		panic("bzip2: code longer than maxCodeLength")
	}
	br.bits = 0
	br.readFailed(br.readErr)
}

func (br *bitReader) readFailed(err error) {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	br.err = err
}

// ReadBits64 reads the given number of bits and returns them in the
// least-significant part of a uint64. In the event of an error, it returns 0
// and the error can be obtained by calling bitReader.Err().
func (br *bitReader) ReadBits64(bits uint) (n uint64) {
	for bits > br.bits {
		b, err := br.readByte()
		if err != nil {
			br.readFailed(err)
			return 0
		}
		br.n <<= 8
		br.n |= uint64(b)
		br.bits += 8
	}

	// br.n looks like this (assuming that br.bits = 14 and bits = 6):
	// Bit: 111111
	//      5432109876543210
	//
	//         (6 bits, the desired output)
	//        |-----|
	//        V     V
	//      0101101101001110
	//        ^            ^
	//        |------------|
	//           br.bits (num valid bits)
	//
	// The next line right shifts the desired bits into the
	// least-significant places and masks off anything above.
	n = (br.n >> (br.bits - bits)) & ((1 << bits) - 1)
	br.bits -= bits
	return
}

func (br *bitReader) ReadBits(bits uint) (n int) {
	n64 := br.ReadBits64(bits)
	return int(n64)
}

func (br *bitReader) ReadBit() bool {
	n := br.ReadBits(1)
	return n != 0
}

func (br *bitReader) Err() error {
	return br.err
}
