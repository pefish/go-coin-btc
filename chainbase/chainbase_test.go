package btccom

import (
	"fmt"
	"testing"
	"time"

	i_logger "github.com/pefish/go-interface/i-logger"
	go_test_ "github.com/pefish/go-test"
)

func TestChainBaseClient_AddressBrc20Tokens(t *testing.T) {
	c := NewChainBaseClient(&i_logger.DefaultLogger, 5*time.Second, "")
	result, err := c.AddressBrc20Tokens("bc1ph30gsrsg65cscvs6jgs0zr6rs49tjjeap36l5ycfymsnx93jzwsshcmc59")
	go_test_.Equal(t, nil, err)
	fmt.Println(result)
}
