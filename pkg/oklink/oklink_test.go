package btccom

import (
	"fmt"
	go_logger "github.com/pefish/go-logger"
	"testing"
	"time"
)

func TestOklinkClient_GetInscription(t *testing.T) {
	c := NewOklinkClient(go_logger.Logger, 5*time.Second, "")
	result, err := c.GetInscription("8d818da846fbe14bce45093b3fb776f8382421cb4b8809d8bedcc86c0f00451ei0")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(result)
}
