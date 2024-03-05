package go_coin_btc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/pefish/go-coin-btc/common"
	"github.com/pefish/go-coin-btc/ord"
	btc_rpc_client "github.com/pefish/go-coin-btc/remote"
	go_decimal "github.com/pefish/go-decimal"
	go_logger "github.com/pefish/go-logger"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

type Wallet struct {
	Net       *chaincfg.Params
	RpcClient *btc_rpc_client.BtcRpcClient
}

type RpcServerConfig struct {
	Url      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func NewWallet(net *chaincfg.Params) *Wallet {
	return &Wallet{
		Net: net,
	}
}

func (w *Wallet) SeedHexByMnemonic(mnemonic string, pass string) string {
	return hex.EncodeToString(bip39.NewSeed(mnemonic, pass))
}

type KeyInfo struct {
	XPriv   string
	XPub    string
	PrivKey string
	PubKey  string
	Wif     string
}

type AddressType int

const (
	ADDRESS_TYPE_P2PKH AddressType = iota
	ADDRESS_TYPE_P2SH
	ADDRESS_TYPE_P2WPKH
	ADDRESS_TYPE_P2TR
)

func (w *Wallet) AddressFromPubKey(pubKey string, addressType AddressType) (
	addr string,
	err error,
) {
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return "", err
	}
	pubKeyHash := btcutil.Hash160(pubKeyBytes)

	if addressType == ADDRESS_TYPE_P2PKH { // pubkeyhash
		addrObj, err := btcutil.NewAddressPubKeyHash(pubKeyHash, w.Net)
		if err != nil {
			return "", err
		}
		return addrObj.String(), nil
	}
	if addressType == ADDRESS_TYPE_P2SH { // scripthash
		scriptSig, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(pubKeyHash).Script()
		if err != nil {
			return "", err
		}
		addrObj, err := btcutil.NewAddressScriptHash(scriptSig, w.Net)
		if err != nil {
			return "", err
		}
		return addrObj.String(), nil
	}
	if addressType == ADDRESS_TYPE_P2WPKH { // witness_v0_keyhash
		addrObj, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, w.Net)
		if err != nil {
			return "", err
		}
		return addrObj.String(), nil
	}
	if addressType == ADDRESS_TYPE_P2TR { // witness_v1_taproot
		pubKeyObj, err := btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			return "", err
		}
		addrObj, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(pubKeyObj)), w.Net)
		if err != nil {
			return "", err
		}
		return addrObj.String(), nil
	}
	return "", fmt.Errorf("address type error")
}

func (w *Wallet) KeyInfoFromWif(wif string) (
	keyInfo *KeyInfo,
	err error,
) {
	wifInfo, err := btcutil.DecodeWIF(wif)
	if err != nil {
		return nil, err
	}
	privK := wifInfo.PrivKey
	pubK := privK.PubKey()

	return &KeyInfo{
		Wif:     wif,
		PubKey:  hex.EncodeToString(pubK.SerializeCompressed()),
		PrivKey: hex.EncodeToString(privK.Serialize()),
	}, nil
}

func (w *Wallet) DeriveBySeedPath(seedHex string, path string) (
	keyInfo *KeyInfo,
	err error,
) {
	keyInfo, err = w.MasterKeyBySeed(seedHex)
	if err != nil {
		return nil, err
	}
	return w.DeriveByXprivPath(keyInfo.XPriv, path)
}

func (w *Wallet) DeriveByXprivPath(xpriv string, path string) (
	keyInfo *KeyInfo,
	err error,
) {
	masterKey, err := bip32.B58Deserialize(xpriv)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(path, "/")
	if parts[0] == path {
		return nil, fmt.Errorf("path '%s' doesn't contain '/' separators", path)
	}
	if strings.TrimSpace(parts[0]) == "m" {
		parts = parts[1:]
	}

	key := masterKey
	for i, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("path %q with split element #%d is an empty string", part, i)
		}
		isHarden := part[len(part)-1:] == "'"
		if isHarden {
			part = part[:len(part)-1]
		}

		idx, err := strconv.ParseUint(part, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("invalid BIP 32 path %s: %w", path, err)
		}
		if isHarden {
			idx |= 0x80000000
		}
		key, err = key.NewChildKey(uint32(idx))
		if err != nil {
			return nil, fmt.Errorf("derive index %d error: %w", idx, err)
		}
	}
	return w.keyInfoOfKey(key)
}

func (w *Wallet) keyInfoOfKey(key *bip32.Key) (
	keyInfo *KeyInfo,
	err error,
) {
	privKey, pubK := btcec.PrivKeyFromBytes(key.Key)
	wifObj, err := btcutil.NewWIF(privKey, w.Net, true)
	if err != nil {
		return nil, err
	}
	return &KeyInfo{
		XPriv:   key.B58Serialize(),
		XPub:    key.PublicKey().B58Serialize(),
		PrivKey: hex.EncodeToString(key.Key),
		PubKey:  hex.EncodeToString(pubK.SerializeCompressed()),
		Wif:     wifObj.String(),
	}, nil
}

func (w *Wallet) MasterKeyBySeed(seedHex string) (
	keyInfo *KeyInfo,
	err error,
) {
	seedBytes, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	masterKey, err := bip32.NewMasterKey(seedBytes)
	if err != nil {
		return nil, err
	}
	return w.keyInfoOfKey(masterKey)
}

func (w *Wallet) InitRpcClient(rpcServerConfig *RpcServerConfig) *Wallet {
	w.RpcClient = btc_rpc_client.NewBtcRpcClient(
		go_logger.Logger,
		3*time.Second,
		rpcServerConfig.Url,
		rpcServerConfig.Username,
		rpcServerConfig.Password,
	)
	return w
}

func (w *Wallet) GetInscriptionTool(request *ord.InscriptionRequest) (
	inscriptionTool *ord.InscriptionTool,
	err error,
) {
	return ord.NewInscriptionTool(w.Net, w.RpcClient, request)
}

func (w *Wallet) MsgTxToHex(tx *wire.MsgTx) (
	txHex string,
	err error,
) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func (w *Wallet) PayToAddrScript(address string) (
	script []byte,
	err error,
) {
	targetAddressObj, err := btcutil.DecodeAddress(address, w.Net)
	if err != nil {
		return nil, err
	}
	targetScriptPubKey, err := txscript.PayToAddrScript(targetAddressObj)
	if err != nil {
		return nil, err
	}
	return targetScriptPubKey, nil
}

type UTXO struct {
	Address string
	Hash    string
	Index   uint64
}

type UTXOWithPriv struct {
	Utxo UTXO
	Priv string
}

func (w *Wallet) BuildTx(
	utxoWithPrivs []*UTXOWithPriv,
	changeAddress string,
	targetAddress string,
	targetValueBtc float64,
	feeRate float64,
) (
	msgTx *wire.MsgTx,
	newUtxos []*UTXO,
	err error,
) {
	targetValue := btcutil.Amount(go_decimal.Decimal.MustStart(targetValueBtc).MustShiftedBy(8).MustEndForInt64())

	totalSenderAmount := btcutil.Amount(0)
	msgTx = wire.NewMsgTx(wire.TxVersion)

	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)
	for _, utxoWithPriv := range utxoWithPrivs {
		hash, err := chainhash.NewHashFromStr(utxoWithPriv.Utxo.Hash)
		if err != nil {
			return nil, nil, err
		}
		outPoint := wire.OutPoint{
			Hash:  *hash,
			Index: uint32(utxoWithPriv.Utxo.Index),
		}
		txOut, err := common.GetTxOutByOutPoint(w.RpcClient, &outPoint)
		if err != nil {
			return nil, nil, err
		}
		prevOutputFetcher.AddPrevOut(outPoint, txOut)

		in := wire.NewTxIn(&outPoint, nil, nil)
		in.Sequence = common.DefaultSequenceNum
		msgTx.AddTxIn(in)

		totalSenderAmount += btcutil.Amount(txOut.Value)
	}

	targetScriptPubKey, err := w.PayToAddrScript(targetAddress)
	if err != nil {
		return nil, nil, err
	}

	msgTx.AddTxOut(wire.NewTxOut(int64(targetValue), targetScriptPubKey))
	newUtxos = append(newUtxos, &UTXO{
		Address: targetAddress,
		Index:   uint64(len(newUtxos)),
	})
	if changeAddress != "" {
		changeScriptPubKey, err := w.PayToAddrScript(changeAddress)
		if err != nil {
			return nil, nil, err
		}
		msgTx.AddTxOut(wire.NewTxOut(0, changeScriptPubKey))
		newUtxos = append(newUtxos, &UTXO{
			Address: changeAddress,
			Index:   uint64(len(newUtxos)),
		})

		feeFloat := feeRate * float64(mempool.GetTxVirtualSize(btcutil.NewTx(msgTx)))
		fee := btcutil.Amount(go_decimal.Decimal.MustStart(feeFloat).RoundUp(0).MustEndForInt64())
		changeAmount := totalSenderAmount - targetValue - fee
		if changeAmount > 0 {
			msgTx.TxOut[len(msgTx.TxOut)-1].Value = int64(changeAmount)
		} else {
			msgTx.TxOut = msgTx.TxOut[:len(msgTx.TxOut)-1]
			if changeAmount < 0 {
				feeWithoutChange := btcutil.Amount(mempool.GetTxVirtualSize(btcutil.NewTx(msgTx))) * btcutil.Amount(feeRate)
				if totalSenderAmount-targetValue-feeWithoutChange < 0 {
					return nil, nil, fmt.Errorf("Insufficient balance. totalSenderAmount: %s, targetValue: %f, fee: %s", totalSenderAmount.String(), targetValueBtc, fee.String())
				}
			}
		}
	} else {
		feeFloat := feeRate * float64(mempool.GetTxVirtualSize(btcutil.NewTx(msgTx)))
		fee := btcutil.Amount(go_decimal.Decimal.MustStart(feeFloat).RoundUp(0).MustEndForInt64())
		if totalSenderAmount-targetValue-fee < 0 {
			return nil, nil, fmt.Errorf("Insufficient balance. totalSenderAmount: %s, targetValue: %f, fee: %s", totalSenderAmount.String(), targetValueBtc, fee.String())
		}
	}

	// sign
	for i, txIn := range msgTx.TxIn {
		privBytes, err := hex.DecodeString(utxoWithPrivs[i].Priv)
		if err != nil {
			return nil, nil, err
		}
		privObj, _ := btcec.PrivKeyFromBytes(privBytes)

		txOut := prevOutputFetcher.FetchPrevOutput(txIn.PreviousOutPoint)

		scriptType, _, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, w.Net)
		if err != nil {
			return nil, nil, err
		}
		switch scriptType {
		case txscript.WitnessV0PubKeyHashTy:
			witness, err := txscript.WitnessSignature(
				msgTx,
				txscript.NewTxSigHashes(msgTx, prevOutputFetcher),
				i,
				txOut.Value,
				txOut.PkScript,
				txscript.SigHashAll,
				privObj,
				true,
			)
			if err != nil {
				return nil, nil, err
			}
			txIn.Witness = witness
		case txscript.WitnessV1TaprootTy:
			witness, err := txscript.TaprootWitnessSignature(
				msgTx,
				txscript.NewTxSigHashes(msgTx, prevOutputFetcher),
				i,
				txOut.Value,
				txOut.PkScript,
				txscript.SigHashDefault,
				privObj,
			)
			if err != nil {
				return nil, nil, err
			}
			txIn.Witness = witness
		default:
			return nil, nil, fmt.Errorf("script type not be supported")
		}
	}

	for i := range newUtxos {
		newUtxos[i].Hash = msgTx.TxHash().String()
	}

	return msgTx, newUtxos, nil
}

func (w *Wallet) DecodeInscriptionScript(witness1Str string) (
	contentType string,
	bodyHexString string,
	err error,
) {
	bytes, err := hex.DecodeString(witness1Str)
	if err != nil {
		return "", "", err
	}

	asmStr, err := txscript.DisasmString(bytes)
	if err != nil {
		return "", "", err
	}
	asmArr := strings.Split(asmStr, " ")

	if len(asmArr) < 8 {
		return "", "", fmt.Errorf("inscription format error")
	}

	if asmArr[len(asmArr)-1] != "OP_ENDIF" {
		return "", "", fmt.Errorf("inscription format error")
	}
	asmArr = asmArr[:len(asmArr)-1]
	bodyArr := make([]string, 0)
	for i := len(asmArr) - 1; i < len(asmArr); i-- {
		if asmArr[i] == "0" {
			break
		}
		bodyArr = append([]string{asmArr[i]}, bodyArr...)
	}

	bodyHexString = strings.Join(bodyArr, "")

	asmArr = asmArr[:len(asmArr)-1-len(bodyArr)]

	contentTypeB, err := hex.DecodeString(asmArr[len(asmArr)-1])
	if err != nil {
		return "", "", err
	}
	contentType = string(contentTypeB)
	if asmArr[len(asmArr)-2] != "01" {
		return "", "", fmt.Errorf("inscription format error")
	}
	if asmArr[len(asmArr)-3] != "6f7264" {
		return "", "", fmt.Errorf("inscription format error")
	}
	if asmArr[len(asmArr)-4] != "OP_IF" {
		return "", "", fmt.Errorf("inscription format error")
	}

	return contentType, bodyHexString, nil
}
