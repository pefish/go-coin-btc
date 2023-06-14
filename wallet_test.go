package go_coin_btc

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	go_logger "github.com/pefish/go-logger"
	"testing"
)

func TestWallet_BuildTx(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	w.InitRpcClient(&RpcServerConfig{
		Url:      "",
		Username: "",
		Password: "",
	})
	revealTxHash, err := chainhash.NewHashFromStr("")
	if err != nil {
		go_logger.Logger.Error(err)
		return
	}
	privateKeyBytes, err := hex.DecodeString("")
	if err != nil {
		go_logger.Logger.Error(err)
		return
	}
	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	tx, err := w.BuildTx(
		[]*OutPointWithPriv{
			{
				OutPoint: &wire.OutPoint{
					Hash:  *revealTxHash,
					Index: 0,
				},
				Priv: privateKey,
			},
		},
		"",
		"",
		546,
		10,
	)
	if err != nil {
		go_logger.Logger.Error(err)
		return
	}
	go_logger.Logger.Info(w.GetTxHex(tx))
}
