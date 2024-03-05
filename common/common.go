package common

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/wire"
	btc_rpc_client "github.com/pefish/go-coin-btc/remote"
	"github.com/pkg/errors"
)

const (
	DefaultSequenceNum = wire.MaxTxInSequenceNum - 10
	MinDustValue       = int64(546)
)

func GetTxOutByOutPoint(rpcClient *btc_rpc_client.BtcRpcClient, outPoint *wire.OutPoint) (
	txOut *wire.TxOut,
	err error,
) {
	tx, err := rpcClient.GetRawTransaction(outPoint.Hash.String())
	if err != nil {
		return nil, err
	}
	if int(outPoint.Index) >= len(tx.Vout) {
		return nil, errors.New("err out point")
	}
	pkScriptBytes, err := hex.DecodeString(tx.Vout[outPoint.Index].ScriptPubKey.Hex)
	if err != nil {
		return nil, err
	}

	return wire.NewTxOut(int64(tx.Vout[outPoint.Index].Value*100000000), pkScriptBytes), nil
}
