package btc_rpc_client

import (
	"fmt"
	go_logger "github.com/pefish/go-logger"
	"testing"
	"time"
)

func TestBtcRpcClient_SendRawTransaction(t *testing.T) {
	c := NewBtcRpcClient(
		go_logger.Logger,
		3*time.Second,
		"",
		"",
		"",
	)

	hash, err := c.SendRawTransaction("01000000000101f8eeba37b0652d87fd51200ed72396175b85892e7bc7269fc53a605bc45248500500000000f5ffffff06a51a0000000000002251205da1adace50179dbce9a4ebebf38a04ba90de8d6f5eb3843094c431d3743bed1a51a00000000000022512071b64dab44a89a1f33b77a278a4826baf0a935209b11a938a4289a28b35ab14ca51a00000000000022512045fe6f3cad1da73fbe25354b99a06c742e69da9bc7ecb9319d85aad034c36e21a51a000000000000225120b03e20833b7c93d82ebaf2721838204e4c5d7cd39cae62032e2bf2e37eec4c71a51a00000000000022512054f314c32fa868efb96d535007bf710a17992d7ede65f41db6d8098baa06bc7d7d0ffd0200000000225120214a83853827463f4b6749905defb3a2337c990b084d8814fac9c3ab4fd790dc0140fa175410e198e56c656916d31b46ae9b778604a7fae9098a9c64da82ddc1f38ee83e6b4803ea15be452d2394a8525edc8a83902f3ab9a0266cbcb3ed654e241200000000")

	fmt.Println(hash, err)
}

func TestBtcRpcClient_GetRawTransaction(t *testing.T) {
	c := NewBtcRpcClient(
		go_logger.Logger,
		3*time.Second,
		"",
		"",
		"",
	)

	data, err := c.GetRawTransaction("30a389943aa9e10430ae7de3796db8714cdb3c7e2b559dba8d715a2437181a5a")

	fmt.Println(data, err)
}
