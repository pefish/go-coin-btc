package go_coin_btc

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	go_logger "github.com/pefish/go-logger"
	go_test_ "github.com/pefish/go-test"
)

func TestWallet_BuildTx(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	w.InitRpcClient(&RpcServerConfig{
		Url:      "https://bitcoin-mainnet-archive.allthatnode.com",
		Username: "",
		Password: "",
	}, 5*time.Second)

	tx, _, _, err := w.BuildTx(
		[]*UTXOWithPriv{
			{
				Utxo: UTXO{
					TxId:  "",
					Index: 0,
				},
				Priv: "",
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
	go_logger.Logger.Info(w.MsgTxToHex(tx))
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

func TestWallet_KeyInfoFromWif(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	keyInfo, err := w.KeyInfoFromWif("Kws7ckMngrpmRXXSrL7X3MhiK5X5FXTUzT4w8DjhVEM7V8qNTbDR")
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "025753c8d80dc0e6f35b79fa45eef59d2610fae76c59754ebecff43781eac55ed2", keyInfo.PubKey)
	go_test_.Equal(t, "133df64b90c1c03c8b3ee8baca02e7961b0611c81f2381a64588484fc8fef0dc", keyInfo.PrivKey)
}

func TestWallet_SignMessageByWif(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	r, err := w.SignMessageByWif("Kws7ckMngrpmRXXSrL7X3MhiK5X5FXTUzT4w8DjhVEM7V8qNTbDR", "hello")
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "H16PHcVJyvDsMje9z21Z3KFyezncQCc7dAq50L57qEWkPHJ4jXkrIBxmCRohIwBFMpKhFSaObTpXwnapf2LXks4=", r)
}

func TestWallet_GetAddressType(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	r, err := w.GetAddressType("bc1qe3035dykr9fu40exrrkz0dkur4jff7y6k2qxgu", &chaincfg.MainNetParams)
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, ADDRESS_TYPE_P2WPKH, r)
}

func TestWallet_VerifySignature(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	r, err := w.VerifySignature(SignedMessage{
		Address:   "bc1psqehlepa3u0ahz32y0phhvljxt8tdj2h0jdnwz6yvkz6akpsmwcqruy6qn",
		Message:   "hello",
		Signature: "H16PHcVJyvDsMje9z21Z3KFyezncQCc7dAq50L57qEWkPHJ4jXkrIBxmCRohIwBFMpKhFSaObTpXwnapf2LXks4=",
	}, &chaincfg.MainNetParams)
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, true, r)

}

func TestWallet_SignMessageByPriv(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	r, err := w.SignMessageByPriv("133df64b90c1c03c8b3ee8baca02e7961b0611c81f2381a64588484fc8fef0dc", "hello")
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "H16PHcVJyvDsMje9z21Z3KFyezncQCc7dAq50L57qEWkPHJ4jXkrIBxmCRohIwBFMpKhFSaObTpXwnapf2LXks4=", r)
}

func TestWallet_GetTxVirtualSize(t *testing.T) {
	w := NewWallet(&chaincfg.MainNetParams)
	msgTx, err := w.MsgTxFromHex("0100000000010ab74f408688a65f949ada50d9a70f9d7c3e221146b03253ae27669c12682860bc0200000000f5ffffff91d34b409eea25ce217520a8712707167366f9a19413b0c552d37d3e537e17650200000000f5ffffff9b41852a2a216e23c5cd6f055e166c8a0da2b7e2c246fa4822dc56f1aa99cd2f0200000000f5ffffffcd2a5077dfaa642cf620eee5709a3d8066165f794ce53a95733879823e0cb5890200000000f5ffffffbb3fd9cd0aac1c339649ccef7afaaf2bf1df760e01a3d14ddbc53aa4c5a54e4a0200000000f5ffffff5cfa610601ea6eb71faf5d16ec776bdcc8f4c5bc6d2bfa67490ba118e19daced0200000000f5ffffffd9eb14d7118c62165c2bb7543b1e4d52c78d45afcd021ebb1cb81a06fa90c0b60200000000f5ffffff8938c183291787734739e855ac08dcbab746edc27f44c5a5e4fdbe40100259990200000000f5ffffff9831e5a7dcc8ef11c3464b282738865d4537c162c518432c34993829dff754fa0200000000f5ffffffa94b362b839dd7d07c7c5cc63e2e366b6d31e4968c0b2d82e2716f862981271a0200000000f5ffffff0114fe0900000000002251205fa8855c151380de9b7850fea9992a56b795a7fe19ed94c2c8aa02f2a5e600620140c575a53372762cd3459af86d1c34eec598cd8700103b572ac50277443f2c616b94400c608f86843cc582a6423fcef5385ec78bece0a8d48dc67f3defe4e6ca8901401d65ae08553b9a088e6a3f4ccdaa0ec60a6022365f1eb32dad9dd4c83defe4c6ceb0e9b7974d860b870fc0a82a76a98fe6e0f68c5169c85fb5d039365c95cdf80140ae1e66a37255923db2a2c5a5ae43332591c1ce4fa224059164d35e70d24c721f93777e429aab995635c70da195dde577623e24d44011002784a07264e94edc760140dc590d2693316c917451834aa298840c20978ab2f490b2580b4914ee52a08c8af2b0402bb5a2015332049ea690987cd6c110e7e4d5dd8488d93b190f095e24e901407313ee67a96d48307bdaecc3f847b502dcc2f1e23d903b9f6b4821975672b65e3608197a3dc150ee058c9123558f34d5ddd5e4db4bcecb2bc3057084f3f48932014004f05ebe5d21facd506731e02bff0e1ce470280d90e471e8d876b5d533147f637712feb84be8f44ade93db94effc328730121570aab6041cf0c230330c48c85e01400972f0a1461de58cede34b3683bb0e75fa65d79fcd6e61ef05e3a5b760e72ddb20532617b6c3cbfe65e075d8be23b7dc53794c44b1dff1eeac86d250c4a7d6d2014072bc3555f82be059c41409f703ac7caadbdea57fe8c43a88de0c6a289a61a7dfddb19b364ef049e9483f82eb4fc88ee474607d551e63e289e5d440bdc2415e2601407af5fb9e39bf042c079f122ef02149fd0921d91ea6102c263a973fe312d0fc09c35138d74d47f85b2b59f8d5160ca882bc5090e92ad0982aada1a342ec9c146701406ba188053af66e2abd6548bc95d31c52abfd8eb18a31b088596fe082b35d3ebae5cbd017f511f156fddf75f4f7b993e0cc36a2cd9412f3d4c9fa86fdacfba3ff00000000")
	go_test_.Equal(t, nil, err)
	go_test_.Equal(t, "878a63ff4f0b99258c1b1b5f0221d0c44be59133e0f0c0fc655b20159a84e738", msgTx.TxHash().String())
	r := w.GetTxVirtualSize(msgTx)
	fmt.Println(r)
}
