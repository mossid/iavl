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

// Concat

type AppendOp struct {
	Key    []byte `json:"key"`
	Prefix []byte `json:"prefix"`
	Suffix []byte `json:"suffix"`
}

var _ merkle.ProofOperator = AppendOp{}

func (op AppendOp) concat(leaf []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write(op.Prefix)
	buf.Write(leaf)
	buf.Write(op.Suffix)
	return buf.Bytes()
}

func (op AppendOp) Run(values [][]byte) ([][]byte, error) {
	if len(values) < 1 {
		return nil, cmn.NewError("aaaa")
	}
	buf := new(bytes.Buffer)
	if op.Key != nil {
		amino.EncodeByteSlice(buf, op.Key)
	}
	buf.Write(values[0])
	res := op.concat(buf.Bytes())
	return [][]byte{res}, nil
}

func (op AppendOp) GetKey() []byte {
	return op.Key
}

func (op AppendOp) ProofOp() merkle.ProofOp {
	buf := new(bytes.Buffer)
	err := amino.EncodeByteSlice(buf, op.Prefix)
	if err == nil {
		amino.EncodeByteSlice(buf, op.Suffix)
	}
	if err != nil {
		panic(err)
	}

	return merkle.ProofOp{
		Type: "concat",
		Key:  op.Key,
		Data: buf.Bytes(),
	}
}

// SHA256

type SHA256Op struct{}

var _ merkle.ProofOperator = SHA256Op{}

func (op SHA256Op) Run(values [][]byte) ([][]byte, error) {
	if len(values) < 1 {
		return nil, cmn.NewError("bbb")
	}
	hasher := tmhash.New()
	hasher.Write(values[0])
	return [][]byte{hasher.Sum(nil)}, nil
}

func (op SHA256Op) GetKey() []byte {
	return nil
}

func (op SHA256Op) ProofOp() merkle.ProofOp {
	return merkle.ProofOp{
		Type: "sha256",
		Key:  nil,
		Data: nil,
	}
}

// Concat

type ConcatOp struct{}

var _ merkle.ProofOperator = ConcatOp{}

func (op ConcatOp) Run(values [][]byte) ([][]byte, error) {
	buf := new(bytes.Buffer)
	for _, v := range values {
		buf.Write(v)
	}
	return [][]byte{buf.Bytes()}, nil
}

func (op ConcatOp) GetKey() []byte {
	return nil
}

func (op ConcatOp) ProofOp() merkle.ProofOp {
	return merkle.ProofOp{
		Type: "concat",
		Key:  nil,
		Data: nil,
	}
}

// AssertValues
// XXX: I'm not sure do we need this
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
	return merkle.ProofOp{
		Type: "prepend_length",
		Key:  nil,
		Data: nil,
	}
}

// Apply

type ApplyOp struct {
	Ops   [][]merkle.ProofOperator
	Argns []int
}

func (op ApplyOp) Run(values [][]byte) (res [][]byte, err error) {
	var input [][]byte
	for i, iops := range op.Ops {
		ix := op.Argns[i]
		if len(values) < ix {
			return nil, cmn.NewError("fdsafs")
		}
		input, values = values[:ix], values[ix:]
		for _, iop := range iops {
			input, err = iop.Run(input)
			if err != nil {
				return nil, err
			}
		}
		res = append(res, input...)
	}
	return res, nil
}

func (op ApplyOp) GetKey() []byte {
	return nil
}

func (op ApplyOp) ProofOp() merkle.ProofOp {
	// XXX: todo
	return merkle.ProofOp{}
	/*
		buf := new(bytes.Buffer)
		for _, iop := range op.Ops {
			pop := iop.ProofOp()
			out, err := proto.Marshal(pop)
			if err != nil {
				panic(err)
			}
			amino.EncodeByteSlice(buf, out)
		}
		for _, ix := range op.Argns {

		}
	*/
}
