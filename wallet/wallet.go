package wallet

import (
	"bytes"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/wire"
	btc_rpc_client "github.com/pefish/go-btc-rpc-client"
	"github.com/pefish/go-coin-btc/common"
	go_logger "github.com/pefish/go-logger"
	"github.com/pkg/errors"
	"time"
)

type Wallet struct {
	rpcClient *btc_rpc_client.BtcRpcClient
}

type RpcServerConfig struct {
	Url      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func NewWallet(rpcServerConfig *RpcServerConfig) *Wallet {
	wallet := &Wallet{}
	if rpcServerConfig != nil {
		wallet.rpcClient = btc_rpc_client.NewBtcRpcClient(
			go_logger.Logger,
			3*time.Second,
			rpcServerConfig.Url,
			rpcServerConfig.Username,
			rpcServerConfig.Password,
		)
	}

	return wallet
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
		txOut, err := common.GetTxOutByOutPoint(w.rpcClient, outPointList[i])
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

func (w *Wallet) SendRawTransaction(tx *wire.MsgTx) (string, error) {
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	if err := tx.Serialize(buf); err != nil {
		return "", err
	}
	return w.rpcClient.SendRawTransaction(hex.EncodeToString(buf.Bytes()))
}
