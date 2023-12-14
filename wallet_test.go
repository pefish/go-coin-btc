package go_coin_btc

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	go_logger "github.com/pefish/go-logger"
	"github.com/pefish/go-test"
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

func TestWallet_SeedHexByMnemonic(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	seedHex := w.SeedHexByMnemonic("test", "test")
	go_test_.Equal(t, "da2a48a1b9fbade07552281143814b3cd7ba4b53a7de5241439417b9bb540e229c45a30b0ce32174aaccc80072df7cbdff24f0c0ae327cd5170d1f276b890173", seedHex)
}

func TestWallet_MasterKeyBySeed(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	masterKey, err := w.MasterKeyBySeed("da2a48a1b9fbade07552281143814b3cd7ba4b53a7de5241439417b9bb540e229c45a30b0ce32174aaccc80072df7cbdff24f0c0ae327cd5170d1f276b890173")
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "xprv9s21ZrQH143K4NSncMZfe2TMny1RNgsm3FC8iK3de44ppftiDUGAmkQGQLmdSDK64zXwSMGPkY1eUzKcSgBrq67Lt7jDvefVmDYy1Xb167R", masterKey.XPriv)
	go_test_.Equal(t, "xpub661MyMwAqRbcGrXFiP6g1AQ6Lzqun9bcQU7jWhTFCPbohUDrm1aRKYikFcvFarQDuGhofh8kFDbGBvJYXGLiZSShpf6azvb2jHfHWYUQUoi", masterKey.XPub)
	go_test_.Equal(t, "793462b45d13b5cf6eef57bc62a6334960e90236e40bc1a1621a6f633b79847c", masterKey.PrivKey)
	go_test_.Equal(t, "030c786d673e1a8ca0121c6da7c6c05260528df80fa8de2a503603be7dd78fce8c", masterKey.PubKey)
	go_test_.Equal(t, "L1HKL85ZpMvYfcSsHUXGpjSpZ5wWAw4e3bp5ro2RUcsKQxMRWUSN", masterKey.Wif)
}

func TestWallet_DeriveByXprivPath(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	info, err := w.DeriveByXprivPath("xprv9s21ZrQH143K4NSncMZfe2TMny1RNgsm3FC8iK3de44ppftiDUGAmkQGQLmdSDK64zXwSMGPkY1eUzKcSgBrq67Lt7jDvefVmDYy1Xb167R", "m/86'/0'/0'/0/1")
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "xprvA41tKCw5HRJ5Edbsce6zKbqwuDWA9br8nTeJk89iHcQBqthXAukGiiukgWD8dVgmYsoGAoZrA6HsAEy9ZcK73FJEmMLXAp7qptauuq5Fban", info.XPriv)
	go_test_.Equal(t, "xpub6H1EiiTy7nrNT7gLifdzgjngTFLeZ4Zz9gZuYWZKqwwAih2fiT4XGXEEXmktDcULf4bAQEb3JDwNyNS43RnnFbhszpjX9Z7U3hhmtDQbqWT", info.XPub)
	go_test_.Equal(t, "133df64b90c1c03c8b3ee8baca02e7961b0611c81f2381a64588484fc8fef0dc", info.PrivKey)
	go_test_.Equal(t, "025753c8d80dc0e6f35b79fa45eef59d2610fae76c59754ebecff43781eac55ed2", info.PubKey)
	go_test_.Equal(t, "Kws7ckMngrpmRXXSrL7X3MhiK5X5FXTUzT4w8DjhVEM7V8qNTbDR", info.Wif)
}

func TestWallet_AddressFromPubKey(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	address1, err := w.AddressFromPubKey("025753c8d80dc0e6f35b79fa45eef59d2610fae76c59754ebecff43781eac55ed2", ADDRESS_TYPE_P2PKH)
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "1KdcmxmhJsVixw2yT25iDnHbQsnVLDg4rk", address1)

	address2, err := w.AddressFromPubKey("025753c8d80dc0e6f35b79fa45eef59d2610fae76c59754ebecff43781eac55ed2", ADDRESS_TYPE_P2SH)
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "32QVedbD5AibggWC8ZTtF7grjwLZE3JS1J", address2)

	address3, err := w.AddressFromPubKey("025753c8d80dc0e6f35b79fa45eef59d2610fae76c59754ebecff43781eac55ed2", ADDRESS_TYPE_P2WPKH)
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "bc1qe3035dykr9fu40exrrkz0dkur4jff7y6k2qxgu", address3)

	address4, err := w.AddressFromPubKey("025753c8d80dc0e6f35b79fa45eef59d2610fae76c59754ebecff43781eac55ed2", ADDRESS_TYPE_P2TR)
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "bc1psqehlepa3u0ahz32y0phhvljxt8tdj2h0jdnwz6yvkz6akpsmwcqruy6qn", address4)
}
