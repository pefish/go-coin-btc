package go_coin_btc

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/pefish/go-coin-btc/common"
	go_decimal "github.com/pefish/go-decimal"
	go_format "github.com/pefish/go-format"
	"github.com/pkg/errors"
)

type InscribeData struct {
	ContentType string
	Body        []byte
}

type BuildInscribeTxsParams struct {
	OutPoints      []*OutPoint
	FeeRate        int64
	InscribeDatas  []*InscribeData
	ReceiveAddress string
}

type BuildInscribeTxsResult struct {
	CommitTx    *wire.MsgTx
	RevealTxs   []*wire.MsgTx
	OutUTXOs    []*OutPoint
	SpentAmount float64
}

func (w *Wallet) BuildInscribeTxs(
	params *BuildInscribeTxsParams,
) (*BuildInscribeTxsResult, error) {
	return w.buildInscribeTxs(&buildInscribeTxsParams{
		BuildInscribeTxsParams: *params,
		InscriptionOutputValue: common.MinDustValue,
	})
}

type buildInscribeTxsParams struct {
	BuildInscribeTxsParams
	InscriptionOutputValue int64 // 指定每个铭文输出上的 sats 数量
}

func (w *Wallet) buildInscribeTxs(
	params *buildInscribeTxsParams,
) (*BuildInscribeTxsResult, error) {
	if len(params.OutPoints) == 0 {
		return nil, errors.New("Balance not enough.")
	}
	if params.FeeRate == 0 {
		return nil, errors.New("Fee rate must be set.")
	}

	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)
	var feeAddressUnlockScript []byte

	commitTx := wire.NewMsgTx(wire.TxVersion)
	inAmountSum := int64(0)
	outAmountSum := int64(0)
	for i, feeOutPoint := range params.OutPoints {
		txOut, err := w.GetTxOutByOutPoint(feeOutPoint)
		if err != nil {
			return nil, err
		}
		hash, err := chainhash.NewHashFromStr(feeOutPoint.Hash)
		if err != nil {
			return nil, err
		}
		btcdOutPoint := wire.NewOutPoint(hash, uint32(feeOutPoint.Index))
		prevOutputFetcher.AddPrevOut(*btcdOutPoint, txOut)

		if i == 0 {
			feeAddressUnlockScript = txOut.PkScript
		} else {
			if !bytes.EqualFold(txOut.PkScript, feeAddressUnlockScript) {
				return nil, errors.New("Fee utxos are not from unipue address.")
			}
		}

		in := wire.NewTxIn(btcdOutPoint, nil, nil)
		in.Sequence = common.DefaultSequenceNum
		commitTx.AddTxIn(in)
		inAmountSum += txOut.Value
	}

	// 根据解锁脚本计算出锁定脚本
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	controlBlockWitnesses := make([][]byte, 0)
	inscribeScripts := make([][]byte, 0)
	for _, inscribeData := range params.InscribeDatas {
		inscriptionBuilder := txscript.NewScriptBuilder().
			AddData(schnorr.SerializePubKey(privateKey.PubKey())).
			AddOp(txscript.OP_CHECKSIG).
			AddOp(txscript.OP_FALSE).
			AddOp(txscript.OP_IF).
			AddData([]byte("ord")).
			AddOp(txscript.OP_DATA_1).
			AddOp(txscript.OP_DATA_1).
			AddData([]byte(inscribeData.ContentType)).
			AddOp(txscript.OP_0)
		maxChunkSize := 520
		bodySize := len(inscribeData.Body)
		for i := 0; i < bodySize; i += maxChunkSize {
			end := i + maxChunkSize
			if end > bodySize {
				end = bodySize
			}
			inscriptionBuilder.AddFullData(inscribeData.Body[i:end])
		}
		inscribeScript, err := inscriptionBuilder.Script()
		if err != nil {
			return nil, err
		}
		inscribeScript = append(inscribeScript, txscript.OP_ENDIF)

		inscribeScripts = append(inscribeScripts, inscribeScript)

		leafNode := txscript.NewBaseTapLeaf(inscribeScript)
		proof := &txscript.TapscriptProof{
			TapLeaf:  leafNode,
			RootNode: leafNode,
		}
		controlBlock := proof.ToControlBlock(privateKey.PubKey())
		controlBlockWitness, err := controlBlock.ToBytes()
		if err != nil {
			return nil, err
		}
		controlBlockWitnesses = append(controlBlockWitnesses, controlBlockWitness)

		tapHash := proof.RootNode.TapHash()
		// 这里并不是单纯的使用公钥生成锁定脚本，而是包含 tapscript merkle root
		commitTxAddress, err := btcutil.NewAddressTaproot(
			schnorr.SerializePubKey(
				txscript.ComputeTaprootOutputKey(
					privateKey.PubKey(),
					tapHash[:],
				),
			),
			w.Net,
		)
		if err != nil {
			return nil, err
		}
		commitTxAddressPkScript, err := txscript.PayToAddrScript(commitTxAddress)
		if err != nil {
			return nil, err
		}

		dustTxOutValue := params.InscriptionOutputValue
		{
			// 评估 reveal tx 网络费
			commitTxHash := commitTx.TxHash()
			fakeRevealTx := wire.NewMsgTx(wire.TxVersion)
			fakeRevealTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(
				&commitTxHash,
				0,
			), nil, nil))
			fakeRevealTx.AddTxOut(wire.NewTxOut(params.InscriptionOutputValue, feeAddressUnlockScript))
			virtualSize := mempool.GetTxVirtualSize(btcutil.NewTx(fakeRevealTx))
			emptySignature := make([]byte, 64)
			emptyControlBlockWitness := make([]byte, 33)
			virtualSize += int64(wire.TxWitness{
				emptySignature,
				inscribeScript,
				emptyControlBlockWitness,
			}.SerializeSize()+2+3) / 4

			fee := virtualSize * params.FeeRate
			dustTxOutValue += fee
		}
		commitTx.AddTxOut(wire.NewTxOut(dustTxOutValue, commitTxAddressPkScript))

		outAmountSum += dustTxOutValue
	}

	// 评估网络费
	commitTx.AddTxOut(wire.NewTxOut(0, feeAddressUnlockScript))
	virtualSize := mempool.GetTxVirtualSize(btcutil.NewTx(commitTx))
	emptySignature := make([]byte, 64)
	virtualSize += int64(wire.TxWitness{emptySignature}.SerializeSize()+2+3) / 4
	fee := virtualSize * params.FeeRate

	// 找零
	spentAmount := outAmountSum + fee
	changeAmount := inAmountSum - spentAmount
	if changeAmount < 0 {
		return nil, errors.New("Balance not enough in commit tx.")
	}
	commitTx.TxOut[len(commitTx.TxOut)-1].Value = changeAmount
	// 签名
	err = w.SignMsgTx(commitTx, prevOutputFetcher)
	if err != nil {
		return nil, err
	}

	commitTxHash := commitTx.TxHash()
	revealTxs := make([]*wire.MsgTx, 0)
	for i := 0; i < len(params.InscribeDatas); i++ {
		revealTx := wire.NewMsgTx(wire.TxVersion)
		// 输入
		outPoint := wire.NewOutPoint(
			&commitTxHash,
			uint32(i),
		)
		in := wire.NewTxIn(
			outPoint,
			nil,
			nil,
		)
		in.Sequence = common.DefaultSequenceNum
		revealTx.AddTxIn(in)
		prevOutputFetcher.AddPrevOut(*outPoint, commitTx.TxOut[i])

		// 添加铭文接收账户
		receivePkScript := feeAddressUnlockScript
		if params.ReceiveAddress != "" {
			pkScript_, err := w.LockScriptFromAddress(params.ReceiveAddress)
			if err != nil {
				return nil, err
			}
			receivePkScript = pkScript_
		}

		revealTxDustTxOut := wire.NewTxOut(params.InscriptionOutputValue, receivePkScript)
		revealTx.AddTxOut(revealTxDustTxOut)

		// 检查最大 tx weight
		revealWeight := blockchain.GetTransactionWeight(btcutil.NewTx(revealTx))
		if revealWeight > common.MaxStandardTxWeight {
			return nil, errors.Errorf("Reveal transaction weight greater than %d (MAX_STANDARD_TX_WEIGHT): %d", common.MaxStandardTxWeight, revealWeight)
		}

		// 签名
		witnessArray, err := txscript.CalcTapscriptSignaturehash(
			txscript.NewTxSigHashes(revealTx, prevOutputFetcher),
			txscript.SigHashDefault,
			revealTx,
			0,
			prevOutputFetcher,
			txscript.NewBaseTapLeaf(inscribeScripts[i]),
		)
		if err != nil {
			return nil, err
		}
		signature, err := schnorr.Sign(privateKey, witnessArray)
		if err != nil {
			return nil, err
		}
		revealTx.TxIn[0].Witness = wire.TxWitness{
			signature.Serialize(),
			inscribeScripts[i],
			controlBlockWitnesses[i],
		}

		revealTxs = append(revealTxs, revealTx)
	}

	return &BuildInscribeTxsResult{
		CommitTx:  commitTx,
		RevealTxs: revealTxs,
		OutUTXOs: []*OutPoint{
			{
				Hash:  commitTx.TxID(),
				Index: len(commitTx.TxOut) - 1,
			},
		},
		SpentAmount: go_decimal.Decimal.MustStart(spentAmount).MustUnShiftedBy(8).MustEndForFloat64(),
	}, nil
}

type BuildTransferBrc20TxsResult struct {
	BuildInscribeTxsResult
	SendInscriptionTx *wire.MsgTx
}

type BuildTransferBrc20TxsParams struct {
	OutPoints []*OutPoint
	FeeRate   int64
	Symbol    string
	Amount    float64
	Address   string
}

func (w *Wallet) BuildTransferBrc20Txs(
	params *BuildTransferBrc20TxsParams,
) (*BuildTransferBrc20TxsResult, error) {
	// 先将转账铭文铸造给自己（根据 BRC20 协议，转账铭文只能先铸造给自己才能转账给别人），铭文上的 sats 数量应该是 dust+fee（转账铭文需要的 fee）
	inscriptionOutputValue := common.MinDustValue

	{
		fakeRevealTx := wire.NewMsgTx(wire.TxVersion)
		// 随便一个 hash
		hashObj, err := chainhash.NewHashFromStr("07fd9c7003cd5869ec2a7e19f87c22e8faeff70d98973404ad35c6ac9a35d73b")
		if err != nil {
			return nil, err
		}
		fakeRevealTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(
			hashObj,
			0,
		), nil, nil))
		pkScript, err := w.LockScriptFromAddress(params.Address)
		if err != nil {
			return nil, err
		}
		fakeRevealTx.AddTxOut(wire.NewTxOut(inscriptionOutputValue, pkScript))
		virtualSize := mempool.GetTxVirtualSize(btcutil.NewTx(fakeRevealTx))

		emptySignature := make([]byte, 64)
		virtualSize += int64(wire.TxWitness{
			emptySignature,
		}.SerializeSize()+2+3) / 4
		fee := virtualSize * params.FeeRate
		inscriptionOutputValue += fee
	}

	inscribeTxs, err := w.buildInscribeTxs(&buildInscribeTxsParams{
		BuildInscribeTxsParams: BuildInscribeTxsParams{
			OutPoints: params.OutPoints,
			FeeRate:   params.FeeRate,
			InscribeDatas: []*InscribeData{
				{
					ContentType: "text/plain;charset=utf-8",
					Body: []byte(fmt.Sprintf(
						`{"p":"brc-20","op":"transfer","tick":"%s","amt":"%s"}`,
						strings.ToLower(params.Symbol),
						go_format.ToString(params.Amount),
					)),
				},
			},
			ReceiveAddress: "",
		},
		InscriptionOutputValue: inscriptionOutputValue,
	})
	if err != nil {
		return nil, err
	}

	// 开始转账铭文
	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)
	sendInscriptionTx := wire.NewMsgTx(wire.TxVersion)
	inscriptionTxHash := inscribeTxs.RevealTxs[0].TxHash()
	inscriptionTxOutPoint := wire.NewOutPoint(
		&inscriptionTxHash,
		0,
	)
	in := wire.NewTxIn(inscriptionTxOutPoint, nil, nil)
	in.Sequence = common.DefaultSequenceNum
	sendInscriptionTx.AddTxIn(in)
	prevOutputFetcher.AddPrevOut(*inscriptionTxOutPoint, inscribeTxs.RevealTxs[0].TxOut[0])
	pkScript, err := w.LockScriptFromAddress(params.Address)
	if err != nil {
		return nil, err
	}
	sendInscriptionTx.AddTxOut(wire.NewTxOut(common.MinDustValue, pkScript))

	err = w.SignMsgTx(sendInscriptionTx, prevOutputFetcher)
	if err != nil {
		return nil, err
	}

	return &BuildTransferBrc20TxsResult{
		BuildInscribeTxsResult: *inscribeTxs,
		SendInscriptionTx:      sendInscriptionTx,
	}, nil
}
