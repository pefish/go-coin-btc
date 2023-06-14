package go_coin_btc

import (
	"encoding/hex"
	"fmt"
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

func TestWallet_DecodeInscriptionScript(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)

	contentType, bodyHexString, err := w.DecodeInscriptionScript("2039dabf79817e71dd1d5c6be69ccf5fb2915af2ce8e99d0a702b2809ea771114dac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d38004c5c7b2270223a226272632d3230222c226f70223a227472616e73666572222c227469636b223a22222c22616d74223a22267b7b252173282a6269672e496e743d267b66616c7365205b5d7d292025217328696e7433323d30297d7d227d68")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(contentType)

	body, err := hex.DecodeString(bodyHexString)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(string(body))
}
