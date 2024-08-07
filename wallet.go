package go_coin_btc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
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

type AddressType string

const (
	ADDRESS_TYPE_P2PKH   AddressType = "P2PKH"
	ADDRESS_TYPE_P2SH    AddressType = "P2SH"
	ADDRESS_TYPE_P2WPKH  AddressType = "P2WPKH"
	ADDRESS_TYPE_P2TR    AddressType = "P2TR"
	ADDRESS_TYPE_UNKNOWN AddressType = "UNKNOWN"
)

type SignedMessage struct {
	Address   string
	Message   string
	Signature string
}

func (w *Wallet) CreateMagicMessage(message string) string {
	buffer := bytes.Buffer{}
	buffer.Grow(wire.VarIntSerializeSize(uint64(len(message))))

	// If we cannot write the VarInt, just panic since that should never happen
	if err := wire.WriteVarInt(&buffer, 0, uint64(len(message))); err != nil {
		panic(err)
	}

	return "\x18Bitcoin Signed Message:\n" + buffer.String() + message
}

func (w *Wallet) VerifySignature(signedMessage SignedMessage, net *chaincfg.Params) (bool, error) {
	// Decode the signature
	signatureEncoded, err := base64.StdEncoding.DecodeString(signedMessage.Signature)
	if err != nil {
		return false, err
	}

	// Ensure signature has proper length
	if len(signatureEncoded) != 65 {
		return false, fmt.Errorf("wrong signature length: %d instead of 65", len(signatureEncoded))
	}

	// Ensure signature has proper recovery flag
	recoveryFlag := int(signatureEncoded[0])
	if !slices.Contains([]int{27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42}, recoveryFlag) {
		return false, fmt.Errorf("invalid recovery flag: %d", recoveryFlag)
	}

	// Make the magic message
	magicMessage := w.CreateMagicMessage(signedMessage.Message)

	// Hash the message
	messageHash := chainhash.DoubleHashB([]byte(magicMessage))

	// 从签名中取出公钥
	publicKeyObj, _, err := ecdsa.RecoverCompact(signatureEncoded, messageHash)
	if err != nil {
		return false, fmt.Errorf("could not recover pubkey: %w", err)
	}

	if publicKeyObj == nil || !publicKeyObj.IsOnCurve() {
		return false, errors.New("public key was not correctly instantiated")
	}

	// 校验公钥和地址的匹配
	addressType, err := w.GetAddressType(signedMessage.Address, net)
	if err != nil {
		return false, err
	}
	addr, err := w.AddressFromPubKey(hex.EncodeToString(publicKeyObj.SerializeCompressed()), addressType)
	if err != nil {
		return false, err
	}
	if !strings.EqualFold(signedMessage.Address, addr) {
		return false, nil
	}

	return true, nil
}

func (w *Wallet) SignMessageByWif(wif string, msg string) (string, error) {
	wifInfo, err := btcutil.DecodeWIF(wif)
	if err != nil {
		return "", err
	}
	return w.signMessage(wifInfo.PrivKey, msg)
}

func (w *Wallet) SignMessageByPriv(priv string, msg string) (string, error) {
	privBytes, err := hex.DecodeString(priv)
	if err != nil {
		return "", err
	}
	privObj, _ := btcec.PrivKeyFromBytes(privBytes)

	return w.signMessage(privObj, msg)
}

func (w *Wallet) signMessage(privObj *btcec.PrivateKey, msg string) (string, error) {
	magicMessage := w.CreateMagicMessage(msg)
	messageHash := chainhash.DoubleHashB([]byte(magicMessage))
	signature, err := ecdsa.SignCompact(privObj, messageHash, true)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (w *Wallet) GetAddressType(address string, net *chaincfg.Params) (AddressType, error) {
	addressObj, err := btcutil.DecodeAddress(address, net)
	if err != nil {
		return ADDRESS_TYPE_UNKNOWN, fmt.Errorf("could not decode address: %w", err)
	}
	_, ok := addressObj.(*btcutil.AddressPubKeyHash)
	if ok {
		return ADDRESS_TYPE_P2PKH, nil
	}
	_, ok = addressObj.(*btcutil.AddressScriptHash)
	if ok {
		return ADDRESS_TYPE_P2SH, nil
	}
	_, ok = addressObj.(*btcutil.AddressWitnessPubKeyHash)
	if ok {
		return ADDRESS_TYPE_P2WPKH, nil
	}
	_, ok = addressObj.(*btcutil.AddressTaproot)
	if ok {
		return ADDRESS_TYPE_P2TR, nil
	}
	return ADDRESS_TYPE_UNKNOWN, nil
}

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

func (w *Wallet) InitRpcClient(
	rpcServerConfig *RpcServerConfig,
	httpTimeout time.Duration,
) *Wallet {
	w.RpcClient = btc_rpc_client.NewBtcRpcClient(
		go_logger.Logger,
		httpTimeout,
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

func (w *Wallet) MsgTxFromHex(txHex string) (
	msgTx *wire.MsgTx,
	err error,
) {
	b, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, err
	}
	msgTx = wire.NewMsgTx(wire.TxVersion)
	err = msgTx.Deserialize(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return msgTx, nil
}

func (w *Wallet) PayToAddrScript(address string) (
	pkScript []byte,
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

func (w *Wallet) GetTxVirtualSize(msgTx *wire.MsgTx) float64 {
	return float64(mempool.GetTxVirtualSize(btcutil.NewTx(msgTx)))
}

type UTXO struct {
	Address string `json:"address"`
	TxId    string `json:"tx_id"`
	Index   uint64 `json:"index"`

	Value    float64 `json:"value"`
	PkScript string  `json:"pk_script"`
}

type UTXOWithPriv struct {
	Utxo UTXO   `json:"utxo"`
	Priv string `json:"priv"`
}

func (w *Wallet) estimateUnsignedTxFee(
	msgTx *wire.MsgTx,
	prevOutputFetcher *txscript.MultiPrevOutFetcher,
	utxoWithPrivs []*UTXOWithPriv,
	feeRate float64,
) (btcutil.Amount, error) {
	estimateFee := btcutil.Amount(0)
	err := w.signMsgTx(msgTx, prevOutputFetcher, utxoWithPrivs)
	if err != nil {
		return estimateFee, err
	}
	txVirtualSize := mempool.GetTxVirtualSize(btcutil.NewTx(msgTx))
	estimateFee = btcutil.Amount(
		go_decimal.Decimal.MustStart(feeRate).MustMulti(txVirtualSize).RoundUp(0).MustEndForInt64(),
	)
	return estimateFee, nil
}

func (w *Wallet) buildUnsignedMsgTx(
	prevOutputFetcher *txscript.MultiPrevOutFetcher,
	utxoWithPrivs []*UTXOWithPriv,
	changeAddress string,
	targetAddress string,
	targetValueBtc float64,
	feeRate float64,
) (
	msgTx *wire.MsgTx,
	newUtxos []*UTXO,
	realFee float64,
	err error,
) {
	totalSenderAmount := btcutil.Amount(0)

	msgTx = wire.NewMsgTx(wire.TxVersion)
	// 添加所有输入
	for i, utxoWithPriv := range utxoWithPrivs {
		txId, err := chainhash.NewHashFromStr(utxoWithPriv.Utxo.TxId)
		if err != nil {
			return nil, nil, 0, err
		}
		outPoint := wire.OutPoint{
			Hash:  *txId,
			Index: uint32(utxoWithPriv.Utxo.Index),
		}
		var txOut *wire.TxOut
		if utxoWithPriv.Utxo.PkScript == "" {
			txOut, err = common.GetTxOutByOutPoint(w.RpcClient, &outPoint)
			if err != nil {
				return nil, nil, 0, err
			}
			utxoWithPrivs[i].Utxo.Value = go_decimal.Decimal.MustStart(txOut.Value).MustUnShiftedBy(8).MustEndForFloat64()
			utxoWithPrivs[i].Utxo.PkScript = hex.EncodeToString(txOut.PkScript)
		} else {
			pkScriptBytes, err := hex.DecodeString(utxoWithPriv.Utxo.PkScript)
			if err != nil {
				return nil, nil, 0, err
			}

			txOut = wire.NewTxOut(
				go_decimal.Decimal.MustStart(utxoWithPriv.Utxo.Value).MustShiftedBy(8).MustEndForInt64(),
				pkScriptBytes,
			)
		}
		prevOutputFetcher.AddPrevOut(outPoint, txOut)

		in := wire.NewTxIn(&outPoint, nil, nil)
		in.Sequence = common.DefaultSequenceNum
		msgTx.AddTxIn(in)

		totalSenderAmount += btcutil.Amount(txOut.Value)
	}

	// 添加目标地址的输出
	pkScriptBytes, err := w.PayToAddrScript(targetAddress)
	if err != nil {
		return nil, nil, 0, err
	}
	targetValue := btcutil.Amount(0)
	if targetValueBtc == 0 {
		msgTx.AddTxOut(wire.NewTxOut(0, pkScriptBytes))
		// 评估网络费
		estimateFee, err := w.estimateUnsignedTxFee(msgTx, prevOutputFetcher, utxoWithPrivs, feeRate)
		if err != nil {
			return nil, nil, 0, err
		}
		targetValue = totalSenderAmount - estimateFee
		if targetValue < 0 {
			return nil, nil, 0, fmt.Errorf("Insufficient balance. totalSenderAmount: %d, targetValue: %f, fee: %d", totalSenderAmount, targetValueBtc, estimateFee)
		}
		msgTx.TxOut[len(msgTx.TxOut)-1].Value = int64(targetValue)
		newUtxos = append(newUtxos, &UTXO{
			Address:  targetAddress,
			Index:    uint64(len(newUtxos)),
			PkScript: hex.EncodeToString(pkScriptBytes),
			Value:    go_decimal.Decimal.MustStart(targetValue).MustUnShiftedBy(8).MustEndForFloat64(),
		})
		realFee = go_decimal.Decimal.MustStart(estimateFee).MustUnShiftedBy(8).MustEndForFloat64()
		return msgTx, newUtxos, realFee, nil
	}

	targetValue = btcutil.Amount(go_decimal.Decimal.MustStart(targetValueBtc).MustShiftedBy(8).MustEndForInt64())
	msgTx.AddTxOut(wire.NewTxOut(int64(targetValue), pkScriptBytes))
	newUtxos = append(newUtxos, &UTXO{
		Address:  targetAddress,
		Index:    uint64(len(newUtxos)),
		PkScript: hex.EncodeToString(pkScriptBytes),
		Value:    targetValueBtc,
	})

	if changeAddress == "" {
		// 评估网络费
		estimateFee, err := w.estimateUnsignedTxFee(msgTx, prevOutputFetcher, utxoWithPrivs, feeRate)
		if err != nil {
			return nil, nil, 0, err
		}
		if totalSenderAmount-targetValue < estimateFee {
			return nil, nil, 0, fmt.Errorf("Insufficient balance. totalSenderAmount: %d, targetValue: %f, fee: %d", totalSenderAmount, targetValueBtc, estimateFee)
		}
		// 网络费保护
		if totalSenderAmount-targetValue > estimateFee*2 {
			return nil, nil, 0, fmt.Errorf("Fee is too more. real fee: %d, should fee: %d", totalSenderAmount-targetValue, estimateFee)
		}
		realFee = go_decimal.Decimal.MustStart(totalSenderAmount - targetValue).MustUnShiftedBy(8).MustEndForFloat64()
		return msgTx, newUtxos, realFee, nil
	}

	// 添加找零的输出
	pkScriptBytes, err = w.PayToAddrScript(changeAddress)
	if err != nil {
		return nil, nil, 0, err
	}
	msgTx.AddTxOut(wire.NewTxOut(0, pkScriptBytes))
	estimateFee, err := w.estimateUnsignedTxFee(msgTx, prevOutputFetcher, utxoWithPrivs, feeRate)
	if err != nil {
		return nil, nil, 0, err
	}
	changeAmount := totalSenderAmount - targetValue - estimateFee
	if changeAmount > 0 {
		msgTx.TxOut[len(msgTx.TxOut)-1].Value = int64(changeAmount)
		newUtxos = append(newUtxos, &UTXO{
			Address:  changeAddress,
			Index:    uint64(len(newUtxos)),
			PkScript: hex.EncodeToString(pkScriptBytes),
			Value:    go_decimal.Decimal.MustStart(changeAmount).MustUnShiftedBy(8).MustEndForFloat64(),
		})
		realFee = go_decimal.Decimal.MustStart(estimateFee).MustUnShiftedBy(8).MustEndForFloat64()
	} else {
		msgTx.TxOut = msgTx.TxOut[:len(msgTx.TxOut)-1] // 找零数量 <=0 ，去掉找零的输出
		// 重新校验余额
		estimateFee, err := w.estimateUnsignedTxFee(msgTx, prevOutputFetcher, utxoWithPrivs, feeRate)
		if err != nil {
			return nil, nil, 0, err
		}
		if totalSenderAmount-targetValue < estimateFee {
			return nil, nil, 0, fmt.Errorf("Insufficient balance. totalSenderAmount: %d, targetValue: %f, fee: %d", int64(totalSenderAmount), targetValueBtc, estimateFee)
		}
		realFee = go_decimal.Decimal.MustStart(totalSenderAmount - targetValue).MustUnShiftedBy(8).MustEndForFloat64()
	}
	return msgTx, newUtxos, realFee, nil
}

func (w *Wallet) signMsgTx(
	msgTx *wire.MsgTx,
	prevOutputFetcher *txscript.MultiPrevOutFetcher,
	utxoWithPrivs []*UTXOWithPriv,
) error {
	for i, txIn := range msgTx.TxIn {
		privBytes, err := hex.DecodeString(utxoWithPrivs[i].Priv)
		if err != nil {
			return err
		}
		privObj, _ := btcec.PrivKeyFromBytes(privBytes)

		txOut := prevOutputFetcher.FetchPrevOutput(txIn.PreviousOutPoint)

		scriptType, _, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, w.Net)
		if err != nil {
			return err
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
				return err
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
				return err
			}
			txIn.Witness = witness
		default:
			return fmt.Errorf("Script type not be supported.")
		}
	}
	return nil
}

// @param changeAddress 如果是空，则不添加找零输出
// @param targetValueBtc 如果是0，则除了网络费所有余额都给 targetAddress，忽略 changeAddress；
func (w *Wallet) BuildTx(
	utxoWithPrivs []*UTXOWithPriv,
	changeAddress string,
	targetAddress string,
	targetValueBtc float64,
	feeRate float64,
) (
	msgTx *wire.MsgTx,
	newUtxos []*UTXO,
	realFee float64,
	err error,
) {
	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)

	msgTx, newUtxos, realFee, err = w.buildUnsignedMsgTx(
		prevOutputFetcher,
		utxoWithPrivs,
		changeAddress,
		targetAddress,
		targetValueBtc,
		feeRate,
	)
	if err != nil {
		return nil, nil, 0, err
	}

	err = w.signMsgTx(msgTx, prevOutputFetcher, utxoWithPrivs)
	if err != nil {
		return nil, nil, 0, err
	}

	for i := range newUtxos {
		newUtxos[i].TxId = msgTx.TxHash().String()
	}

	return msgTx, newUtxos, realFee, nil
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
