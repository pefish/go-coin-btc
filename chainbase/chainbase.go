package btccom

import (
	"fmt"
	"time"

	go_http "github.com/pefish/go-http"
	i_logger "github.com/pefish/go-interface/i-logger"
	"github.com/pkg/errors"
)

type ChainBaseClient struct {
	timeout time.Duration
	logger  i_logger.ILogger
	baseUrl string
	key     string
}

func NewChainBaseClient(
	logger i_logger.ILogger,
	httpTimeout time.Duration,
	key string,
) *ChainBaseClient {
	return &ChainBaseClient{
		timeout: httpTimeout,
		logger:  logger,
		baseUrl: "https://api.chainbase.online",
		key:     key,
	}
}

type AddressBrc20TokensResult struct {
	Tick        string `json:"tick"`
	Amount      string `json:"amount"`
	TotalSupply string `json:"total_supply"`
}

func (t *ChainBaseClient) AddressBrc20Tokens(address string) (map[string]*AddressBrc20TokensResult, error) {
	var httpResult struct {
		Data    []AddressBrc20TokensResult `json:"data"`
		Message string                     `json:"message"`
		Code    uint64                     `json:"code"`
	}
	_, _, err := go_http.NewHttpRequester(
		go_http.WithTimeout(t.timeout),
		go_http.WithLogger(t.logger),
	).GetForStruct(&go_http.RequestParams{
		Url: fmt.Sprintf("%s/v1/insc/brc20/account/balance", t.baseUrl),
		Params: map[string]interface{}{
			"address": address,
			"limit":   100,
		},
		Headers: map[string]interface{}{
			"x-api-key": t.key,
		},
	}, &httpResult)
	if err != nil {
		return nil, err
	}
	if httpResult.Code != 0 {
		return nil, errors.Errorf(httpResult.Message)
	}

	results := make(map[string]*AddressBrc20TokensResult, 0)
	for _, tokenData := range httpResult.Data {
		results[tokenData.Tick] = &tokenData
	}
	return results, nil
}
