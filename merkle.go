package iavl

import (
	"bytes"

	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/crypto/tmhash"
	cmn "github.com/tendermint/tendermint/libs/common"
)

// HashConcat

type HashConcatNode struct {
	Prefix []byte `json:"prefix"`
	Suffix []byte `json:"suffix"`
}

func (node HashConcatNode) Hash(leaf []byte) []byte {
	hasher := tmhash.New()
	buf := new(bytes.Buffer)
	buf.Write(node.Prefix)
	buf.Write(leaf)
	buf.Write(node.Suffix)
	hasher.Write(buf.Bytes())
	return hasher.Sum(nil)
}

type HashConcatOp struct {
	Key   []byte
	Nodes []HashConcatNode
}

// XXX: pointerify
var _ merkle.ProofOperator = HashConcatOp{}

func (op HashConcatOp) Run(values [][]byte) ([][]byte, error) {
	if len(values) != 1 {
		return nil, cmn.NewError("aaaa")
	}
	buf := new(bytes.Buffer)
	buf.Write(op.Key)
	buf.Write(values[0])
	leaf := buf.Bytes()
	for _, node := range op.Nodes {
		leaf = node.Hash(leaf)
	}
	return [][]byte{leaf}, nil
}

func (op HashConcatOp) GetKey() []byte {
	return op.Key
}

func (op HashConcatOp) ProofOp() merkle.ProofOp {
	return merkle.ProofOp{} // XXX
}

// HashValue

type HashValueOp struct{}

var _ merkle.ProofOperator = HashValueOp{}

func (op HashValueOp) Run(values [][]byte) ([][]byte, error) {
	if len(values) != 1 {
		return nil, cmn.NewError("bbb")
	}
	hasher := tmhash.New()
	hasher.Write(values[0])
	return [][]byte{hasher.Sum(nil)}, nil
}

func (op HashValueOp) GetKey() []byte {
	return nil
}

func (op HashValueOp) ProofOp() merkle.ProofOp {
	return merkle.ProofOp{} // XXX
}

// AssertValues
type AssertValuesOp struct {
	Values [][]byte
}

var _ merkle.ProofOperator = AssertValuesOp{}

// [][]byte{...} -> check if the input is a subset of op.Values
// nil           -> proceed with op.Values
func (op AssertValuesOp) Run(values [][]byte) ([][]byte, error) {
	if values == nil {
		return op.Values, nil
	}

	accepted := make(map[string]struct{})
	for _, v := range op.Values {
		accepted[string(v)] = struct{}{}
	}
	for _, v := range values {
		if _, ok := accepted[string(v)]; !ok {
			return nil, cmn.NewError("ttt")
		}
	}
	return values, nil
}

func (op AssertValuesOp) GetKey() []byte {
	return nil
}

func (op AssertValuesOp) ProofOp() merkle.ProofOp {
	return merkle.ProofOp{} // XXX
}
