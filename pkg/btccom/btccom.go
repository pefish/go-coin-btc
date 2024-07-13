package btccom

import (
	"fmt"
	"time"

	go_http "github.com/pefish/go-http"
	go_logger "github.com/pefish/go-logger"
)

type BtcComClient struct {
	timeout time.Duration
	logger  go_logger.InterfaceLogger
	baseUrl string
	key     string
}

func NewBtcComClient(
	logger go_logger.InterfaceLogger,
	httpTimeout time.Duration,
	key string,
) *BtcComClient {
	return &BtcComClient{
		timeout: httpTimeout,
		logger:  logger,
		baseUrl: "https://chain.api.btc.com",
		key:     key,
	}
}

type ListTransactionsResult struct {
	TxId        string `json:"hash"`
	BlockNumber int64  `json:"block_height"`
	Inputs      []struct {
		PrevHash    string   `json:"prev_tx_hash"`
		OutputIndex uint64   `json:"prev_position"`
		Addresses   []string `json:"prev_addresses"`
	} `json:"inputs"`
	Outputs []struct {
		Value     uint64   `json:"value"`
		Addresses []string `json:"addresses"`
	} `json:"outputs"`
	Confirmations uint64 `json:"confirmations"`
}

func (bc *BtcComClient) ListTransactions(page uint64, address string) (
	transactions []ListTransactionsResult,
	err error,
) {
	if page == 0 {
		return nil, fmt.Errorf("page can not be 0")
	}

	var httpResult struct {
		Data struct {
			List       []ListTransactionsResult `json:"list"`
			TotalCount uint64                   `json:"total_count"`
			PageTotal  uint64                   `json:"page_total"`
		} `json:"data"`
		Message string `json:"message"`
		Status  string `json:"status"`
	}
	_, _, err = go_http.NewHttpRequester(
		go_http.WithTimeout(bc.timeout),
		go_http.WithLogger(bc.logger),
	).GetForStruct(&go_http.RequestParams{
		Url: fmt.Sprintf("%s/v3/address/%s/tx", bc.baseUrl, address),
		Params: map[string]interface{}{
			"page":     page,
			"pagesize": 50,
		},
	}, &httpResult)
	if err != nil {
		return nil, err
	}
	if httpResult.Status != "success" {
		return nil, fmt.Errorf(httpResult.Message)
	}

	return httpResult.Data.List, nil
}

type ListUnspentResult struct {
	TxHash        string `json:"tx_hash"`
	TxOutputN     uint64 `json:"tx_output_n"`
	Value         uint64 `json:"value"`
	Confirmations uint64 `json:"confirmations"`
}

func (bc *BtcComClient) ListUnspent(address string) (
	listUnspentResult []ListUnspentResult,
	err error,
) {
	results := make([]ListUnspentResult, 0)

	var page uint64 = 1
	for {
		var httpResult struct {
			Data struct {
				List       []ListUnspentResult `json:"list"`
				TotalCount uint64              `json:"total_count"`
				PageTotal  uint64              `json:"page_total"`
			} `json:"data"`
			Message string `json:"message"`
			Status  string `json:"status"`
		}
		_, _, err := go_http.NewHttpRequester(
			go_http.WithTimeout(bc.timeout),
			go_http.WithLogger(bc.logger),
		).GetForStruct(&go_http.RequestParams{
			Url: fmt.Sprintf("%s/v3/address/%s/unspent", bc.baseUrl, address),
			Params: map[string]interface{}{
				"page":     page,
				"pagesize": 50,
			},
		}, &httpResult)
		if err != nil {
			return nil, err
		}
		if httpResult.Status != "success" {
			return nil, fmt.Errorf(httpResult.Message)
		}

		if httpResult.Data.PageTotal == 0 {
			return results, nil
		}

		results = append(results, httpResult.Data.List...)
		if httpResult.Data.PageTotal == page {
			return results, nil
		}
		page++
	}
}

type AddressInfoResult struct {
	Address             string `json:"address"`
	Balance             uint64 `json:"balance"`
	Received            uint64 `json:"received"`
	Sent                uint64 `json:"sent"`
	TxCount             uint64 `json:"tx_count"`
	UnconfirmedReceived uint64 `json:"unconfirmed_received"`
	UnconfirmedSent     uint64 `json:"unconfirmed_sent"`
	UnconfirmedTxCount  uint64 `json:"unconfirmed_tx_count"`
	UnspentTxCount      uint64 `json:"unspent_tx_count"`
	FirstTx             string `json:"first_tx"`
	LastTx              string `json:"last_tx"`
}

func (bc *BtcComClient) AddressInfo(address string) (
	addressInfoResult *AddressInfoResult,
	err error,
) {
	var httpResult struct {
		Data    AddressInfoResult `json:"data"`
		Message string            `json:"message"`
		Status  string            `json:"status"`
	}
	_, _, err = go_http.NewHttpRequester(
		go_http.WithTimeout(bc.timeout),
		go_http.WithLogger(bc.logger),
	).GetForStruct(&go_http.RequestParams{
		Url: fmt.Sprintf("%s/v3/address/%s", bc.baseUrl, address),
	}, &httpResult)
	if err != nil {
		return nil, err
	}
	if httpResult.Status != "success" {
		return nil, fmt.Errorf(httpResult.Message)
	}

	return &httpResult.Data, nil
}
