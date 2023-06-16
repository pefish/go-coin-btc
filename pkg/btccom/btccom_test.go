package btccom

import (
	"fmt"
	go_logger "github.com/pefish/go-logger"
	"testing"
	"time"
)

func TestBtcComClient_ListTransactions(t *testing.T) {
	c := NewBtcComClient(go_logger.Logger, 5*time.Second, "")
	result, err := c.ListUnspent("bc1plk3ujd2xzp5660tpl0llekvkzr0u8knckgauwdde9k5ssl5wa09qvvja8j")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(len(result))
}

func TestBtcComClient_ListTransactions1(t *testing.T) {
	c := NewBtcComClient(go_logger.Logger, 5*time.Second, "")
	result, err := c.ListTransactions(1, "bc1plk3ujd2xzp5660tpl0llekvkzr0u8knckgauwdde9k5ssl5wa09qvvja8j")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(len(result))
}
