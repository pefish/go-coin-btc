package go_coin_btc

import (
	"bytes"
	"encoding/hex"
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
	"github.com/pkg/errors"
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

func (w *Wallet) BuildTx(
	outPointList []*OutPointWithPriv,
	changeAddress string,
	targetAddress string,
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

		// sign
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
		in.Witness = witness

		tx.AddTxIn(in)

		totalSenderAmount += btcutil.Amount(txOut.Value)
	}
	var targetValue int64 = 546

	targetAddressObj, err := btcutil.DecodeAddress(targetAddress, w.Net)
	if err != nil {
		return nil, err
	}
	targetScriptPubKey, err := txscript.PayToAddrScript(targetAddressObj)
	if err != nil {
		return nil, err
	}
	tx.AddTxOut(wire.NewTxOut(targetValue, targetScriptPubKey))
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
	changeAmount := totalSenderAmount - btcutil.Amount(targetValue) - fee
	if changeAmount > 0 {
		tx.TxOut[len(tx.TxOut)-1].Value = int64(changeAmount)
	} else {
		tx.TxOut = tx.TxOut[:len(tx.TxOut)-1]
		if changeAmount < 0 {
			feeWithoutChange := btcutil.Amount(mempool.GetTxVirtualSize(btcutil.NewTx(tx))) * btcutil.Amount(feeRate)
			if totalSenderAmount-btcutil.Amount(targetValue)-feeWithoutChange < 0 {
				return nil, errors.New("insufficient balance")
			}
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
