package iavl

/*
THIS FILE WILL BE MOVED INTO CRYPTO/MERKLE
*/

import (
	"bytes"

	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/crypto/tmhash"
	cmn "github.com/tendermint/tendermint/libs/common"
)

func RunOps(input []byte, opss ...[]merkle.ProofOperator) []byte {
	var values [][]byte
	if input != nil {
		values = append(values, input)
	}
	for _, ops := range opss {
		for _, op := range ops {
			var err error
			values, err = op.Run(values)
			if err != nil {
				panic(err)
			}
		}
	}
	return values[0]
}

// HashConcat

type HashConcatOp struct {
	Key    []byte `json:"key"`
	Prefix []byte `json:"prefix"`
	Suffix []byte `json:"suffix"`
}

var _ merkle.ProofOperator = HashConcatOp{}

func (op HashConcatOp) hash(leaf []byte) []byte {
	hasher := tmhash.New()
	buf := new(bytes.Buffer)
	buf.Write(op.Prefix)
	buf.Write(leaf)
	buf.Write(op.Suffix)
	hasher.Write(buf.Bytes())
	return hasher.Sum(nil)
}

func (op HashConcatOp) Run(values [][]byte) ([][]byte, error) {
	if len(values) != 1 {
		return nil, cmn.NewError("aaaa")
	}
	buf := new(bytes.Buffer)
	if op.Key != nil {
		amino.EncodeByteSlice(buf, op.Key)
	}
	buf.Write(values[0])
	res := op.hash(buf.Bytes())
	return [][]byte{res}, nil
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

// PrependLength

type PrependLengthOp struct{}

var _ merkle.ProofOperator = PrependLengthOp{}

func (op PrependLengthOp) Run(values [][]byte) ([][]byte, error) {
	res := make([][]byte, len(values))
	for i, v := range values {
		buf := new(bytes.Buffer)
		amino.EncodeByteSlice(buf, v)
		res[i] = buf.Bytes()
	}
	return res, nil
}

func (op PrependLengthOp) GetKey() []byte {
	return nil
}

func (op PrependLengthOp) ProofOp() merkle.ProofOp {
	return merkle.ProofOp{}
}
