package go_coin_btc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/pefish/go-coin-btc/common"
	"github.com/pefish/go-coin-btc/ord"
	btc_rpc_client "github.com/pefish/go-coin-btc/remote"
	go_logger "github.com/pefish/go-logger"
	"strings"
	"time"
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

func (w *Wallet) InitRpcClient(rpcServerConfig *RpcServerConfig) {
	w.RpcClient = btc_rpc_client.NewBtcRpcClient(
		go_logger.Logger,
		3*time.Second,
		rpcServerConfig.Url,
		rpcServerConfig.Username,
		rpcServerConfig.Password,
	)
}

func (w *Wallet) GetInscriptionTool(request *ord.InscriptionRequest) (*ord.InscriptionTool, error) {
	return ord.NewInscriptionTool(w.Net, w.RpcClient, request)
}

type OutPointWithPriv struct {
	OutPoint *wire.OutPoint
	Priv     *btcec.PrivateKey
}

func (w *Wallet) GetTxHex(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func (w *Wallet) BuildTx(
	outPointList []*OutPointWithPriv,
	changeAddress string,
	targetAddress string,
	targetValue uint64,
	feeRate uint64,
) (*wire.MsgTx, error) {
	totalSenderAmount := btcutil.Amount(0)
	tx := wire.NewMsgTx(wire.TxVersion)

	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)
	for i := range outPointList {
		txOut, err := common.GetTxOutByOutPoint(w.RpcClient, outPointList[i].OutPoint)
		if err != nil {
			return nil, err
		}
		prevOutputFetcher.AddPrevOut(*outPointList[i].OutPoint, txOut)

		in := wire.NewTxIn(outPointList[i].OutPoint, nil, nil)
		in.Sequence = common.DefaultSequenceNum
		tx.AddTxIn(in)

		totalSenderAmount += btcutil.Amount(txOut.Value)
	}

	targetAddressObj, err := btcutil.DecodeAddress(targetAddress, w.Net)
	if err != nil {
		return nil, err
	}
	targetScriptPubKey, err := txscript.PayToAddrScript(targetAddressObj)
	if err != nil {
		return nil, err
	}
	tx.AddTxOut(wire.NewTxOut(int64(targetValue), targetScriptPubKey))
	if changeAddress != "" {
		changeAddressObj, err := btcutil.DecodeAddress(changeAddress, w.Net)
		if err != nil {
			return nil, err
		}
		changeScriptPubKey, err := txscript.PayToAddrScript(changeAddressObj)
		if err != nil {
			return nil, err
		}
		tx.AddTxOut(wire.NewTxOut(0, changeScriptPubKey))
		fee := btcutil.Amount(mempool.GetTxVirtualSize(btcutil.NewTx(tx))) * btcutil.Amount(feeRate)
		targetValueBtc := btcutil.Amount(targetValue)
		changeAmount := totalSenderAmount - targetValueBtc - fee
		if changeAmount > 0 {
			tx.TxOut[len(tx.TxOut)-1].Value = int64(changeAmount)
		} else {
			tx.TxOut = tx.TxOut[:len(tx.TxOut)-1]
			if changeAmount < 0 {
				feeWithoutChange := btcutil.Amount(mempool.GetTxVirtualSize(btcutil.NewTx(tx))) * btcutil.Amount(feeRate)
				if totalSenderAmount-targetValueBtc-feeWithoutChange < 0 {
					return nil, fmt.Errorf("insufficient balance. totalSenderAmount: %s, targetValue: %d, fee: %s", totalSenderAmount.String(), targetValueBtc, fee.String())
				}
			}
		}
	} else {
		fee := btcutil.Amount(mempool.GetTxVirtualSize(btcutil.NewTx(tx))) * btcutil.Amount(feeRate)
		targetValueBtc := btcutil.Amount(targetValue)
		if totalSenderAmount-targetValueBtc-fee < 0 {
			return nil, fmt.Errorf("insufficient balance. totalSenderAmount: %s, targetValue: %d, fee: %s", totalSenderAmount.String(), targetValueBtc, fee.String())
		}
	}

	// sign
	for i, txIn := range tx.TxIn {
		txOut := prevOutputFetcher.FetchPrevOutput(txIn.PreviousOutPoint)

		scriptType, _, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, w.Net)
		if err != nil {
			return nil, err
		}
		switch scriptType {
		case txscript.WitnessV0PubKeyHashTy:
			witness, err := txscript.WitnessSignature(
				tx,
				txscript.NewTxSigHashes(tx, prevOutputFetcher),
				i,
				txOut.Value,
				txOut.PkScript,
				txscript.SigHashAll,
				outPointList[i].Priv,
				true,
			)
			if err != nil {
				return nil, err
			}
			txIn.Witness = witness
		case txscript.WitnessV1TaprootTy:
			witness, err := txscript.TaprootWitnessSignature(
				tx,
				txscript.NewTxSigHashes(tx, prevOutputFetcher),
				i,
				txOut.Value,
				txOut.PkScript,
				txscript.SigHashDefault,
				outPointList[i].Priv,
			)
			if err != nil {
				return nil, err
			}
			txIn.Witness = witness
		default:
			return nil, fmt.Errorf("script type not be supported")
		}
	}

	return tx, nil
}

func (w *Wallet) MsgTxToHex(tx *wire.MsgTx) (string, error) {
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	if err := tx.Serialize(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func (w *Wallet) DecodeInscriptionScript(witness1Str string) (string, string, error) {
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

	bodyHexString := strings.Join(bodyArr, "")

	asmArr = asmArr[:len(asmArr)-1-len(bodyArr)]

	contentTypeB, err := hex.DecodeString(asmArr[len(asmArr)-1])
	if err != nil {
		return "", "", err
	}
	contentType := string(contentTypeB)
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
