package btc_rpc_client

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/wire"
	go_http "github.com/pefish/go-http"
	i_logger "github.com/pefish/go-interface/i-logger"
)

type BtcRpcClient struct {
	timeout  time.Duration
	logger   i_logger.ILogger
	baseUrl  string
	username string
	password string
}

func NewBtcRpcClient(
	logger i_logger.ILogger,
	httpTimeout time.Duration,
	baseUrl string,
	username string,
	password string,
) *BtcRpcClient {
	return &BtcRpcClient{
		timeout:  httpTimeout,
		logger:   logger,
		baseUrl:  baseUrl,
		username: username,
		password: password,
	}
}

type VinStruct struct {
	TxId        string   `json:"txid"`
	Vout        uint64   `json:"vout"`
	TxInWitness []string `json:"txinwitness"`
	Sequence    uint64   `json:"sequence"`
}

type ScriptPubKeyStruct struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Hex     string `json:"hex"`
}

type VoutStruct struct {
	Value        float64            `json:"value"`
	N            uint64             `json:"n"`
	ScriptPubKey ScriptPubKeyStruct `json:"scriptPubKey"`
}

type GetRawTransactionResult struct {
	Vin           []VinStruct  `json:"vin"`
	Vout          []VoutStruct `json:"vout"`
	Confirmations uint64       `json:"confirmations,omitempty"`
	TxId          string       `json:"txid"`
}

func (brc *BtcRpcClient) GetRawTransaction(txId string) (
	getRawTransactionResult *GetRawTransactionResult,
	err error,
) {
	var result struct {
		Result *GetRawTransactionResult `json:"result"`
		Error  *string                  `json:"error"`
	}
	_, _, err = go_http.NewHttpRequester(
		go_http.WithTimeout(brc.timeout),
		go_http.WithLogger(brc.logger),
	).PostForStruct(&go_http.RequestParams{
		Url: brc.baseUrl,
		Params: map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "getrawtransaction",
			"params": []interface{}{
				txId,
				1,
			},
			"id": 1,
		},
		BasicAuth: &go_http.BasicAuth{
			Username: brc.username,
			Password: brc.password,
		},
	}, &result)
	if err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf(*result.Error)
	}
	return result.Result, nil
}

type ListTransactionsResult struct {
	TxId string `json:"txid"`
}

func (brc *BtcRpcClient) ListTransactions(index uint64, address string) (
	transactions []ListTransactionsResult,
	err error,
) {
	var result struct {
		Result []ListTransactionsResult `json:"result"`
		Error  *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_, _, err = go_http.NewHttpRequester(
		go_http.WithTimeout(brc.timeout),
		go_http.WithLogger(brc.logger),
	).PostForStruct(&go_http.RequestParams{
		Url: brc.baseUrl,
		Params: map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "listtransactions",
			"params": []interface{}{
				address,
				10,
				index,
				true,
			},
			"id": 1,
		},
		BasicAuth: &go_http.BasicAuth{
			Username: brc.username,
			Password: brc.password,
		},
	}, &result)
	if err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf((*result.Error).Message)
	}
	return result.Result, nil
}

// return sats/vb
func (brc *BtcRpcClient) EstimateSmartFee() (
	feeRate float64,
	err error,
) {
	var result struct {
		Result struct {
			Feerate float64 `json:"feerate"`
		} `json:"result"`
		Error *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_, _, err = go_http.NewHttpRequester(
		go_http.WithTimeout(brc.timeout),
		go_http.WithLogger(brc.logger),
	).PostForStruct(&go_http.RequestParams{
		Url: brc.baseUrl,
		Params: map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "estimatesmartfee",
			"params": []interface{}{
				10,
			},
			"id": 1,
		},
		BasicAuth: &go_http.BasicAuth{
			Username: brc.username,
			Password: brc.password,
		},
	}, &result)
	if err != nil {
		return 0, err
	}
	if result.Error != nil {
		return 0, fmt.Errorf((*result.Error).Message)
	}
	return result.Result.Feerate * 100000, nil
}

func (brc *BtcRpcClient) SendRawTransaction(txHex string) (
	txId string,
	err error,
) {
	var result struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_, _, err = go_http.NewHttpRequester(
		go_http.WithTimeout(brc.timeout),
		go_http.WithLogger(brc.logger),
	).PostForStruct(&go_http.RequestParams{
		Url: brc.baseUrl,
		Params: map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "sendrawtransaction",
			"params": []interface{}{
				txHex,
			},
			"id": 1,
		},
		BasicAuth: &go_http.BasicAuth{
			Username: brc.username,
			Password: brc.password,
		},
	}, &result)
	if err != nil {
		return "", err
	}
	if result.Error != nil {
		return "", fmt.Errorf((*result.Error).Message)
	}
	return result.Result, nil
}

func (brc *BtcRpcClient) SendMsgTx(tx *wire.MsgTx) (
	txId string,
	err error,
) {
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	if err := tx.Serialize(buf); err != nil {
		return "", err
	}
	return brc.SendRawTransaction(hex.EncodeToString(buf.Bytes()))
}
