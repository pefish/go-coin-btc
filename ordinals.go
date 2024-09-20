package go_coin_btc

import (
	"bytes"
	"encoding/hex"
	"math/big"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	go_decimal "github.com/pefish/go-decimal"
	"github.com/pkg/errors"
)

const (
	MaxStandardTxWeight = blockchain.MaxBlockWeight / 10
	DefaultSequenceNum  = wire.MaxTxInSequenceNum - 10
	MinDustValue        = int64(546)
)

type OutPoint struct {
	Hash  string
	Index int
}

type InscribeData struct {
	ContentType string
	Body        []byte
}

type BuildInscribeTxsParams struct {
	OutPoints      []*OutPoint
	FeeRate        uint64
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
	if len(params.OutPoints) == 0 {
		return nil, errors.New("Balance not enough.")
	}
	if params.FeeRate == 0 {
		return nil, errors.New("Fee rate must be set.")
	}

	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)
	var feeAddressUnlockScript []byte

	commitTx := wire.NewMsgTx(wire.TxVersion)
	inAmountSum := big.NewInt(0)
	outAmountSum := big.NewInt(0)
	for i, feeOutPoint := range params.OutPoints {
		txOut, err := w.getTxOutByOutPoint(feeOutPoint)
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
		in.Sequence = DefaultSequenceNum
		commitTx.AddTxIn(in)
		inAmountSum.Add(inAmountSum, big.NewInt(txOut.Value))
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

		dustTxOutValue := big.NewInt(MinDustValue)
		{
			// 评估 reveal tx 网络费
			commitTxHash := commitTx.TxHash()
			fakeRevealTx := wire.NewMsgTx(wire.TxVersion)
			fakeRevealTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(
				&commitTxHash,
				0,
			), nil, nil))
			fakeRevealTx.AddTxOut(wire.NewTxOut(MinDustValue, feeAddressUnlockScript))
			virtualSize := big.NewInt(mempool.GetTxVirtualSize(btcutil.NewTx(fakeRevealTx)))
			emptySignature := make([]byte, 64)
			emptyControlBlockWitness := make([]byte, 33)
			virtualSize.Add(virtualSize, big.NewInt(
				int64(wire.TxWitness{
					emptySignature,
					inscribeScript,
					emptyControlBlockWitness,
				}.SerializeSize()+2+3)/4,
			))

			fee := virtualSize.Mul(virtualSize, big.NewInt(int64(params.FeeRate)))
			dustTxOutValue.Add(dustTxOutValue, fee)
		}
		commitTx.AddTxOut(wire.NewTxOut(dustTxOutValue.Int64(), commitTxAddressPkScript))

		outAmountSum.Add(outAmountSum, dustTxOutValue)
	}

	// 评估网络费
	commitTx.AddTxOut(wire.NewTxOut(0, feeAddressUnlockScript))
	virtualSize := big.NewInt(mempool.GetTxVirtualSize(btcutil.NewTx(commitTx)))
	emptySignature := make([]byte, 64)
	virtualSize.Add(virtualSize, big.NewInt(
		int64(wire.TxWitness{emptySignature}.SerializeSize()+2+3)/4,
	))
	fee := virtualSize.Mul(virtualSize, big.NewInt(int64(params.FeeRate)))

	// 找零
	spentAmount := outAmountSum.Add(outAmountSum, fee)
	changeAmount := inAmountSum.Sub(inAmountSum, spentAmount)
	if changeAmount.Cmp(big.NewInt(0)) < 0 {
		return nil, errors.New("Balance not enough in commit tx.")
	}
	commitTx.TxOut[len(commitTx.TxOut)-1].Value = changeAmount.Int64()
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
		in.Sequence = DefaultSequenceNum
		revealTx.AddTxIn(in)
		prevOutputFetcher.AddPrevOut(*outPoint, commitTx.TxOut[i])

		// 添加铭文接收账户
		pkScript, err := w.LockScriptFromAddress(params.ReceiveAddress)
		if err != nil {
			return nil, err
		}
		revealTxDustTxOut := wire.NewTxOut(MinDustValue, pkScript)
		revealTx.AddTxOut(revealTxDustTxOut)

		// 检查最大 tx weight
		revealWeight := blockchain.GetTransactionWeight(btcutil.NewTx(revealTx))
		if revealWeight > MaxStandardTxWeight {
			return nil, errors.Errorf("Reveal transaction weight greater than %d (MAX_STANDARD_TX_WEIGHT): %d", MaxStandardTxWeight, revealWeight)
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

func (w *Wallet) getTxOutByOutPoint(outPoint *OutPoint) (
	txOut *wire.TxOut,
	err error,
) {
	tx, err := w.RpcClient.GetRawTransaction(outPoint.Hash)
	if err != nil {
		return nil, err
	}
	if int(outPoint.Index) >= len(tx.Vout) {
		return nil, errors.New("err out point")
	}
	pkScriptBytes, err := hex.DecodeString(tx.Vout[outPoint.Index].ScriptPubKey.Hex)
	if err != nil {
		return nil, err
	}

	return wire.NewTxOut(
		go_decimal.Decimal.MustStart(tx.Vout[outPoint.Index].Value).MustShiftedBy(8).MustEndForInt64(),
		pkScriptBytes,
	), nil
}
