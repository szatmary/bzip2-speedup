// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bzip2

import (
	"cmp"
	"slices"
)

// A huffmanTree is a binary tree which is navigated, bit-by-bit to reach a
// symbol.
type huffmanTree struct {
	// table maps the next tableBits bits of input to the code they begin
	// with, as symbol<<5 | length, or, for a longer code, to the node they
	// reach, as nodeIndex<<5. tableBits is at most huffmanTableBits, but no
	// more than the longest code, so that the table for a small tree is
	// cheap to fill: otherwise a stream of many tiny blocks could make the
	// decoder spend most of its time filling tables.
	table     [1 << huffmanTableBits]uint16
	tableBits uint

	// nodes contains all the non-leaf nodes in the tree. nodes[0] is the
	// root of the tree and nextNode contains the index of the next element
	// of nodes to use when the tree is being constructed.
	nodes    []huffmanNode
	nextNode int
}

// A huffmanNode is a node in the tree. left and right contain indexes into the
// nodes slice of the tree. If left or right is invalidNodeValue then the child
// is a left node and its value is in leftValue/rightValue.
//
// The symbols are uint16s because bzip2 encodes not only MTF indexes in the
// tree, but also two magic values for run-length encoding and an EOF symbol.
// Thus there are more than 256 possible symbols.
type huffmanNode struct {
	left, right           uint16
	leftValue, rightValue uint16
}

// invalidNodeValue is an invalid index which marks a leaf node in the tree.
const invalidNodeValue = 0xffff

// maxCodeLength is the maximum length of a Huffman code, in bits.
const maxCodeLength = 20

// huffmanTableBits is the most bits of input that index a table.
const huffmanTableBits = 10

// maxHuffmanTrees is the most Huffman trees a block can use.
const maxHuffmanTrees = 6

// Decode reads bits from the given bitReader and navigates the tree until a
// symbol is found.
func (t *huffmanTree) Decode(br *bitReader) (v uint16) {
	if br.bits < maxCodeLength {
		br.fill()
	}

	// The buffered bits, padded with zeros if the input ended early.
	w := br.n << (64 - br.bits)
	e := t.table[w>>(64-t.tableBits)]
	if n := uint(e & 31); n != 0 {
		br.consume(n)
		return e >> 5
	}
	return t.walk(br, e>>5, t.tableBits, w<<t.tableBits)
}

// walk navigates the tree from nodeIndex, depth bits from the root, using the
// bits of w.
func (t *huffmanTree) walk(br *bitReader, nodeIndex uint16, depth uint, w uint64) (v uint16) {
	for {
		node := &t.nodes[nodeIndex]

		bit := uint16(w >> 63)
		w <<= 1
		depth++

		// Trick a compiler into generating conditional move instead of branch,
		// by making both loads unconditional.
		l, r := node.left, node.right

		if bit == 1 {
			nodeIndex = l
		} else {
			nodeIndex = r
		}

		if nodeIndex == invalidNodeValue {
			// We found a leaf. Use the value of bit to decide
			// whether is a left or a right value.
			l, r := node.leftValue, node.rightValue
			if bit == 1 {
				v = l
			} else {
				v = r
			}
			br.consume(depth)
			return
		}
	}
}

// fillTable fills the table entries for the inputs that begin with prefix,
// the depth-bit path from the root to nodeIndex.
func (t *huffmanTree) fillTable(nodeIndex uint16, prefix, depth uint) {
	node := &t.nodes[nodeIndex]
	children := [2]struct{ index, value uint16 }{
		{node.right, node.rightValue}, // bit 0
		{node.left, node.leftValue},   // bit 1
	}
	for bit, child := range children {
		p, d := prefix<<1|uint(bit), depth+1
		switch {
		case child.index == invalidNodeValue:
			shift := t.tableBits - d
			for i := p << shift; i < (p+1)<<shift; i++ {
				t.table[i] = child.value<<5 | uint16(d)
			}
		case d == t.tableBits:
			t.table[p] = child.index << 5
		default:
			t.fillTable(child.index, p, d)
		}
	}
}

// build builds the Huffman tree, in place, from a slice containing the code
// lengths of each symbol. The maximum code length is maxCodeLength bits.
func (t *huffmanTree) build(lengths []uint8) error {
	// There are many possible trees that assign the same code length to
	// each symbol (consider reflecting a tree down the middle, for
	// example). Since the code length assignments determine the
	// efficiency of the tree, each of these trees is equally good. In
	// order to minimize the amount of information needed to build a tree
	// bzip2 uses a canonical tree so that it can be reconstructed given
	// only the code length assignments.

	if len(lengths) < 2 {
		panic("huffmanTree.build: too few symbols")
	}
	maxLength := slices.Max(lengths)
	if maxLength > maxCodeLength {
		panic("huffmanTree.build: code too long")
	}

	// First we sort the code length assignments by ascending code length,
	// using the symbol value to break ties.
	pairs := make([]huffmanSymbolLengthPair, len(lengths))
	for i, length := range lengths {
		pairs[i].value = uint16(i)
		pairs[i].length = length
	}

	slices.SortFunc(pairs, func(a, b huffmanSymbolLengthPair) int {
		if c := cmp.Compare(a.length, b.length); c != 0 {
			return c
		}
		return cmp.Compare(a.value, b.value)
	})

	// Now we assign codes to the symbols, starting with the longest code.
	// We keep the codes packed into a uint32, at the most-significant end.
	// So branches are taken from the MSB downwards. This makes it easy to
	// sort them later.
	code := uint32(0)
	length := uint8(32)

	codes := make([]huffmanCode, len(lengths))
	for i := len(pairs) - 1; i >= 0; i-- {
		if length > pairs[i].length {
			length = pairs[i].length
		}
		codes[i].code = code
		codes[i].codeLen = length
		codes[i].value = pairs[i].value
		// We need to 'increment' the code, which means treating |code|
		// like a |length| bit number.
		code += 1 << (32 - length)
	}

	// Now we can sort by the code so that the left half of each branch are
	// grouped together, recursively.
	slices.SortFunc(codes, func(a, b huffmanCode) int {
		return cmp.Compare(a.code, b.code)
	})

	t.nodes = make([]huffmanNode, len(codes))
	t.nextNode = 0
	if _, err := buildHuffmanNode(t, codes, 0); err != nil {
		return err
	}
	t.tableBits = min(huffmanTableBits, uint(maxLength))
	t.fillTable(0, 0, 0)
	return nil
}

// huffmanSymbolLengthPair contains a symbol and its code length.
type huffmanSymbolLengthPair struct {
	value  uint16
	length uint8
}

// huffmanCode contains a symbol, its code and code length.
type huffmanCode struct {
	code    uint32
	codeLen uint8
	value   uint16
}

// buildHuffmanNode takes a slice of sorted huffmanCodes and builds a node in
// the Huffman tree at the given level. It returns the index of the newly
// constructed node.
func buildHuffmanNode(t *huffmanTree, codes []huffmanCode, level uint32) (nodeIndex uint16, err error) {
	test := uint32(1) << (31 - level)

	// We have to search the list of codes to find the divide between the left and right sides.
	firstRightIndex := len(codes)
	for i, code := range codes {
		if code.code&test != 0 {
			firstRightIndex = i
			break
		}
	}

	left := codes[:firstRightIndex]
	right := codes[firstRightIndex:]

	if len(left) == 0 || len(right) == 0 {
		// There is a superfluous level in the Huffman tree indicating
		// a bug in the encoder. However, this bug has been observed in
		// the wild so we handle it.

		// If this function was called recursively then we know that
		// len(codes) >= 2 because, otherwise, we would have hit the
		// "leaf node" case, below, and not recurred.
		//
		// However, for the initial call it's possible that len(codes)
		// is zero or one. Both cases are invalid because a zero length
		// tree cannot encode anything and a length-1 tree can only
		// encode EOF and so is superfluous. We reject both.
		if len(codes) < 2 {
			return 0, StructuralError("empty Huffman tree")
		}

		// In this case the recursion doesn't always reduce the length
		// of codes so we need to ensure termination via another
		// mechanism.
		if level == 31 {
			// Since len(codes) >= 2 the only way that the values
			// can match at all 32 bits is if they are equal, which
			// is invalid. This ensures that we never enter
			// infinite recursion.
			return 0, StructuralError("equal symbols in Huffman tree")
		}

		if len(left) == 0 {
			return buildHuffmanNode(t, right, level+1)
		}
		return buildHuffmanNode(t, left, level+1)
	}

	nodeIndex = uint16(t.nextNode)
	node := &t.nodes[t.nextNode]
	t.nextNode++

	if len(left) == 1 {
		// leaf node
		node.left = invalidNodeValue
		node.leftValue = left[0].value
	} else {
		node.left, err = buildHuffmanNode(t, left, level+1)
	}

	if err != nil {
		return
	}

	if len(right) == 1 {
		// leaf node
		node.right = invalidNodeValue
		node.rightValue = right[0].value
	} else {
		node.right, err = buildHuffmanNode(t, right, level+1)
	}

	return
}
