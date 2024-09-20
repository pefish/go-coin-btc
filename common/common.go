package common

import (
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
)

const (
	MaxStandardTxWeight = blockchain.MaxBlockWeight / 10
	DefaultSequenceNum  = wire.MaxTxInSequenceNum - 10
	MinDustValue        = int64(546)
	MinDustValueBtc     = 0.00000546
)
