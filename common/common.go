package common

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/wire"
	btc_rpc_client "github.com/pefish/go-coin-btc/remote"
	go_decimal "github.com/pefish/go-decimal"
	"github.com/pkg/errors"
)

const (
	DefaultSequenceNum = wire.MaxTxInSequenceNum - 10
	MinDustValue       = int64(546)
)

func GetTxOutByOutPoint(rpcClient *btc_rpc_client.BtcRpcClient, outPoint *wire.OutPoint) (*wire.TxOut, error) {
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

	return wire.NewTxOut(go_decimal.Decimal.MustStart(tx.Vout[outPoint.Index].Value).MustShiftedBy(8).MustEndForInt64(), pkScriptBytes), nil
}
