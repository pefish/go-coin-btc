package btccom

import (
	"fmt"
	"strings"
	"time"

	go_http "github.com/pefish/go-http"
	i_logger "github.com/pefish/go-interface/i-logger"
	"github.com/pkg/errors"
)

type ShortChainType string
type InscriptionProtocol string

const (
	Chain_Bitcoin                 ShortChainType = "BTC"
	Chain_Bitcoin_Cash            ShortChainType = "BCH"
	Chain_Litecoin                ShortChainType = "LTC"
	Chain_Ethereum                ShortChainType = "ETH"
	Chain_Base                    ShortChainType = "BASE"
	Chain_Fractal_Bitcoin_Mainnet ShortChainType = "FRACTAL"

	InscriptionProtocol_Brc20 InscriptionProtocol = "brc20"
	InscriptionProtocol_Runes InscriptionProtocol = "runes"
	InscriptionProtocol_Src20 InscriptionProtocol = "src20"
	InscriptionProtocol_Arc20 InscriptionProtocol = "arc20"
	InscriptionProtocol_Nft   InscriptionProtocol = "ordinals_nft"
)

type OklinkClient struct {
	timeout time.Duration
	logger  i_logger.ILogger
	baseUrl string
	key     string
}

func NewOklinkClient(
	logger i_logger.ILogger,
	httpTimeout time.Duration,
	key string,
) *OklinkClient {
	return &OklinkClient{
		timeout: httpTimeout,
		logger:  logger,
		baseUrl: "https://www.oklink.com",
		key:     key,
	}
}

type GetInscriptionResult struct {
	InscriptionId     string `json:"inscriptionId"`
	InscriptionNumber string `json:"inscriptionNumber"`
	Location          string `json:"location"`
	Token             string `json:"token"`
	State             string `json:"state"`
	Msg               string `json:"msg"`
	TokenType         string `json:"tokenType"`
	ActionType        string `json:"actionType"`
	OwnerAddress      string `json:"ownerAddress"`
	TxId              string `json:"txId"`
	BlockHeight       string `json:"blockHeight"`
	Time              string `json:"time"`
}

func (oc *OklinkClient) GetInscription(inscriptionId string) (
	getInscriptionResult *GetInscriptionResult,
	err error,
) {
	var httpResult struct {
		Data []struct {
			InscriptionsList []GetInscriptionResult `json:"inscriptionsList"`
			Page             string                 `json:"page"`
			Limit            string                 `json:"limit"`
			TotalPage        string                 `json:"totalPage"`
			TotalInscription string                 `json:"totalInscription"`
		} `json:"data"`
		Msg  string `json:"msg"`
		Code string `json:"code"`
	}
	_, _, err = go_http.NewHttpRequester(
		go_http.WithTimeout(oc.timeout),
		go_http.WithLogger(oc.logger),
	).GetForStruct(&go_http.RequestParams{
		Url: fmt.Sprintf("%s/api/v5/explorer/btc/inscriptions-list", oc.baseUrl),
		Params: map[string]interface{}{
			"inscriptionId": inscriptionId,
		},
		Headers: map[string]interface{}{
			"Ok-Access-Key": oc.key,
		},
	}, &httpResult)
	if err != nil {
		return nil, err
	}
	if httpResult.Code != "0" {
		return nil, fmt.Errorf(httpResult.Msg)
	}
	for _, inscription := range httpResult.Data[0].InscriptionsList {
		if strings.HasPrefix(inscriptionId, inscription.TxId) {
			return &inscription, nil
		}
	}
	return nil, fmt.Errorf("inscription %s not found", inscriptionId)
}

type AddressInfoResult struct {
	Address              string `json:"address"`
	Balance              string `json:"balance"`
	TransactionCount     string `json:"transactionCount"`
	SendAmount           string `json:"sendAmount"`
	ReceiveAmount        string `json:"receiveAmount"`
	FirstTransactionTime string `json:"firstTransactionTime"`
	LastTransactionTime  string `json:"lastTransactionTime"`
}

func (oc *OklinkClient) AddressInfo(address string) (
	addressInfoResult *AddressInfoResult,
	err error,
) {
	var httpResult struct {
		Data []AddressInfoResult `json:"data"`
		Msg  string              `json:"msg"`
		Code string              `json:"code"`
	}
	_, _, err = go_http.NewHttpRequester(
		go_http.WithTimeout(oc.timeout),
		go_http.WithLogger(oc.logger),
	).GetForStruct(&go_http.RequestParams{
		Url: fmt.Sprintf("%s/api/v5/explorer/address/address-summary", oc.baseUrl),
		Params: map[string]interface{}{
			"chainShortName": "BTC",
			"address":        address,
		},
		Headers: map[string]interface{}{
			"Ok-Access-Key": oc.key,
		},
	}, &httpResult)
	if err != nil {
		return nil, err
	}
	if httpResult.Code != "0" {
		return nil, fmt.Errorf(httpResult.Msg)
	}
	return &httpResult.Data[0], nil
}

type AddressBrc20TokensResult struct {
	Symbol             string `json:"symbol"`
	TokenInscriptionId string `json:"tokenInscriptionId"`
	HoldingAmount      string `json:"holdingAmount"`
	InscriptionAmount  string `json:"inscriptionAmount"`
	AvailableAmount    string `json:"availableAmount"`
	TransferableAmount string `json:"transferableAmount"`
	InscriptionNumber  string `json:"inscriptionNumber"`
}

func (oc *OklinkClient) AddressBrc20Tokens(chain ShortChainType, address string) (map[string]*AddressBrc20TokensResult, error) {
	var httpResult struct {
		Data []struct {
			TokenList []AddressBrc20TokensResult `json:"tokenList"`
		} `json:"data"`
		Msg  string `json:"msg"`
		Code string `json:"code"`
	}
	_, _, err := go_http.NewHttpRequester(
		go_http.WithTimeout(oc.timeout),
		go_http.WithLogger(oc.logger),
	).GetForStruct(&go_http.RequestParams{
		Url: fmt.Sprintf("%s/api/v5/explorer/inscription/address-token-list", oc.baseUrl),
		Params: map[string]interface{}{
			"chainShortName": chain,
			"address":        address,
			"protocolType":   InscriptionProtocol_Brc20,
			"limit":          100,
		},
		Headers: map[string]interface{}{
			"Ok-Access-Key": oc.key,
		},
	}, &httpResult)
	if err != nil {
		return nil, err
	}
	if httpResult.Code != "0" {
		return nil, errors.Errorf(httpResult.Msg)
	}

	results := make(map[string]*AddressBrc20TokensResult, 0)
	for _, tokenData := range httpResult.Data[0].TokenList {
		results[tokenData.Symbol] = &tokenData
	}
	return results, nil
}
