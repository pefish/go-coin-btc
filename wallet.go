package go_coin_btc

import (
	"bytes"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/wire"
	"github.com/pefish/go-coin-btc/common"
	"github.com/pefish/go-coin-btc/ord"
	btc_rpc_client "github.com/pefish/go-coin-btc/remote"
	go_logger "github.com/pefish/go-logger"
	"github.com/pkg/errors"
	"time"
)

type Wallet struct {
	net             *chaincfg.Params
	RpcClient       *btc_rpc_client.BtcRpcClient
	InscriptionTool *ord.InscriptionTool
}

type RpcServerConfig struct {
	Url      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func NewWallet(net *chaincfg.Params) *Wallet {
	return &Wallet{
		net: net,
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

func (w *Wallet) InitInscriptionTool(request *ord.InscriptionRequest) error {
	inscriptionTool, err := ord.NewInscriptionTool(w.net, w.RpcClient, request)
	if err != nil {
		return err
	}
	w.InscriptionTool = inscriptionTool
	return nil
}

func (w *Wallet) BuildSendInscriptionTx(
	inscriptionOutPoint *wire.OutPoint,
	outPointList []*wire.OutPoint,
	changePkScript []byte,
	targetPkScript []byte,
	feeRate int64,
) (*wire.MsgTx, error) {
	totalSenderAmount := btcutil.Amount(0)
	tx := wire.NewMsgTx(wire.TxVersion)

	tx.AddTxIn(wire.NewTxIn(inscriptionOutPoint, nil, nil))
	for i := range outPointList {
		txOut, err := common.GetTxOutByOutPoint(w.RpcClient, outPointList[i])
		if err != nil {
			return nil, err
		}
		in := wire.NewTxIn(outPointList[i], nil, nil)
		in.Sequence = common.DefaultSequenceNum
		tx.AddTxIn(in)

		totalSenderAmount += btcutil.Amount(txOut.Value)
	}
	var targetValue int64 = 546
	tx.AddTxOut(wire.NewTxOut(targetValue, targetPkScript))
	tx.AddTxOut(wire.NewTxOut(0, changePkScript))
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
