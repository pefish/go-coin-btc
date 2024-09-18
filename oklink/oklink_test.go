package btccom

import (
	"fmt"
	"testing"
	"time"

	i_logger "github.com/pefish/go-interface/i-logger"
)

func TestOklinkClient_GetInscription(t *testing.T) {
	c := NewOklinkClient(&i_logger.DefaultLogger, 5*time.Second, "")
	result, err := c.GetInscription("8d818da846fbe14bce45093b3fb776f8382421cb4b8809d8bedcc86c0f00451ei0")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(result)
}

func TestOklinkClient_AddressInfo(t *testing.T) {
	c := NewOklinkClient(&i_logger.DefaultLogger, 5*time.Second, "")
	result, err := c.AddressInfo("bc1plk3ujd2xzp5660tpl0llekvkzr0u8knckgauwdde9k5ssl5wa09qvvja8j")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(result)
}
