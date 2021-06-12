package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/neutrino"
)

type walletRouter func(json.RawMessage) (string, error)

func encode(thing interface{}) (string, error) {
	b, err := json.Marshal(thing)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func serializeMsgTx(tx *wire.MsgTx) ([]byte, error) {
	var buf bytes.Buffer
	err := tx.Serialize(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func convertByteSliceSlice(inB [][]byte) []Bytes {
	outB := make([]Bytes, 0, len(inB))
	for _, b := range inB {
		outB = append(outB, b)
	}
	return outB
}

func convertAmounts(inAmts []btcutil.Amount) []int64 {
	outAmts := make([]int64, 0, len(inAmts))
	for _, amt := range inAmts {
		outAmts = append(outAmts, int64(amt))
	}
	return outAmts
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func outpointFromJSON(raw json.RawMessage) (*wire.OutPoint, error) {
	var op hashIndex
	err := json.Unmarshal(raw, &op)
	if err != nil {
		return nil, err
	}

	h := chainhash.Hash{}
	err = h.SetBytes(op.Hash)
	if err != nil {
		return nil, err
	}
	return wire.NewOutPoint(&h, uint32(op.Index)), nil
}

func parseNet(netName string) (*chaincfg.Params, error) {
	switch netName {
	case chaincfg.MainNetParams.Name:
		return &chaincfg.MainNetParams, nil
	case chaincfg.TestNet3Params.Name:
		return &chaincfg.TestNet3Params, nil
	case chaincfg.SimNetParams.Name:
		return &chaincfg.SimNetParams, nil
	case chaincfg.RegressionNetParams.Name:
		return &chaincfg.RegressionNetParams, nil
	}
	return nil, fmt.Errorf("net %s not known", netName)
}

type walletSpecs struct {
	Net string `json:"net"`
	Dir string `json:"dir"`
}

type walletInitParams struct {
	walletSpecs
	Test         bool     `json:"test"`
	ConnectPeers []string `json:"connectPeers"`
}

// Wallet wraps *wallet.Wallet and translates routed calls.
type Wallet struct {
	btcWallet
	ctx      context.Context
	shutdown context.CancelFunc
	neutrino *neutrino.ChainService
	params   *chaincfg.Params
	handlers map[string]func(json.RawMessage) (string, error)
}

func newWallet(init *walletInitParams) (*Wallet, error) {
	params, err := parseNet(init.Net)
	if err != nil {
		return nil, err
	}

	ctx, shutdown := context.WithCancel(context.Background())

	var wI btcWallet
	var chainService *neutrino.ChainService
	if init.Test {
		wI, err = newTestWallet(init.Dir)
		if err != nil {
			return nil, err
		}
	} else {
		var btcw *wallet.Wallet
		btcw, chainService, err = loadWallet(&walletConfig{
			DBDir:        init.Dir,
			Net:          params,
			ConnectPeers: init.ConnectPeers,
		})
		if err != nil {
			return nil, err
		}

		wI = btcw
		go notesLoop(ctx, btcw)
	}

	w := &Wallet{
		btcWallet: wI,
		ctx:       ctx,
		shutdown:  shutdown,
		neutrino:  chainService,
		params:    params,
	}
	w.prepHandlers()

	return w, nil
}

func (w *Wallet) decodeJSONAddr(raw json.RawMessage) (btcutil.Address, error) {
	var addrStr string
	err := json.Unmarshal(raw, &addrStr)
	if err != nil {
		return nil, err
	}
	return btcutil.DecodeAddress(addrStr, w.params)
}

// func (w *Wallet) MakeMultiSigScript(addrs []btcutil.Address, nRequired int) ([]byte, error)
type makeMultiSigScriptParams struct {
	Addrs     []string `json:"addrs"`
	NRequired int      `json:"nRequired"`
}

func (w *Wallet) makeMultiSigScript(raw json.RawMessage) (string, error) {
	params := new(makeMultiSigScriptParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	addrs := make([]btcutil.Address, 0, len(params.Addrs))
	for _, s := range params.Addrs {
		addr, err := btcutil.DecodeAddress(s, w.params)
		if err != nil {
			return "", err
		}
		addrs = append(addrs, addr)
	}
	script, err := w.MakeMultiSigScript(addrs, params.NRequired)
	if err != nil {
		return "", err
	}
	return encode(hex.EncodeToString(script))
}

// func (w *Wallet) ImportP2SHRedeemScript(script []byte) (*btcutil.AddressScriptHash, error)
func (w *Wallet) importP2SHRedeemScript(scriptHexB json.RawMessage) (string, error) {
	var script Bytes
	err := json.Unmarshal(scriptHexB, &script)
	if err != nil {
		return "", err
	}

	addr, err := w.ImportP2SHRedeemScript(script)
	if err != nil {
		return "", err
	}
	return encode(addr.String())
}

// TODO
// func (w *Wallet) SubmitRescan(job *RescanJob) <-chan error

// TODO
// func (w *Wallet) Rescan(addrs []btcutil.Address, unspent []wtxmgr.Credit) error

// func (w *Wallet) UnspentOutputs(policy OutputSelectionPolicy) ([]*TransactionOutput, error
type outputSelectionPolicy struct {
	Account               uint32 `json:"account"`
	RequiredConfirmations int32  `json:"requiredConfirmations"`
}

type transactionOutput struct {
	OutPoint        hashIndex   `json:"outPoint"`
	Output          scriptValue `json:"output"`
	OutputKind      byte        `json:"outputKind"`
	ContainingBlock hashIndex   `json:"containingBlock"`
	ReceiveTime     int64       `json:"receiveTime"`
}

func (w *Wallet) unspentOutputs(ospB json.RawMessage) (string, error) {
	osp := new(outputSelectionPolicy)
	err := json.Unmarshal(ospB, osp)
	if err != nil {
		return "", nil
	}

	woutputs, err := w.UnspentOutputs(wallet.OutputSelectionPolicy{
		Account:               osp.Account,
		RequiredConfirmations: osp.RequiredConfirmations,
	})

	outputs := make([]*transactionOutput, 0, len(woutputs))
	for _, wto := range woutputs {

		outputs = append(outputs, &transactionOutput{
			OutPoint: hashIndex{
				Hash:  wto.OutPoint.Hash[:],
				Index: int64(wto.OutPoint.Index),
			},
			Output: scriptValue{
				Script: wto.Output.PkScript,
				Value:  int64(wto.Output.Value),
			},
			OutputKind: byte(wto.OutputKind),
			ContainingBlock: hashIndex{
				Hash:  wto.ContainingBlock.Hash[:],
				Index: int64(wto.ContainingBlock.Height),
			},
			ReceiveTime: wto.ReceiveTime.Unix(),
		})
	}

	return encode(outputs)
}

// func (w *Wallet) Start() // called by loader.OpenExistingWallet
func (w *Wallet) start(_ json.RawMessage) (string, error) {
	w.Start()
	return "", nil
}

// INTERNAL USE ONLY
// // SynchronizeRPC docs say the API is unstable, but they still use it and so do
// // we.
// func (w *Wallet) SynchronizeRPC(chainClient chain.Interface)

// INTERNAL USE ONLY
// func (w *Wallet) ChainClient() chain.Interface

// func (w *Wallet) Stop()
func (w *Wallet) stop(_ json.RawMessage) (string, error) {
	w.Stop()
	return "", nil
}

// Stop cancels the context before calling Stop on the embedded wallet.
func (w *Wallet) Stop() {
	w.shutdown()
	w.btcWallet.Stop()
}

// func (w *Wallet) ShuttingDown() bool
func (w *Wallet) shuttingDown(_ json.RawMessage) (string, error) {
	return encode(w.ShuttingDown())
}

// func (w *Wallet) WaitForShutdown()
func (w *Wallet) waitForShutdown(_ json.RawMessage) (string, error) {
	w.WaitForShutdown()
	return "", nil
}

// func (w *Wallet) SynchronizingToNetwork() bool
func (w *Wallet) synchronizingToNetwork(_ json.RawMessage) (string, error) {
	return encode(w.SynchronizingToNetwork())
}

// func (w *Wallet) ChainSynced() bool
func (w *Wallet) chainSynced(_ json.RawMessage) (string, error) {
	return encode(w.ChainSynced())
}

// func (w *Wallet) SetChainSynced(synced bool)
func (w *Wallet) setChainSynced(syncedB json.RawMessage) (string, error) {
	var synced bool
	err := json.Unmarshal(syncedB, &synced)
	if err != nil {
		return "", err
	}
	w.SetChainSynced(synced)
	return "", nil
}

// func (w *Wallet) CreateSimpleTx(account uint32, outputs []*wire.TxOut, minconf int32, satPerKb btcutil.Amount, dryRun bool)(*txauthor.AuthoredTx, error) {
type createSimpleTxParams struct {
	Account   uint32        `json:"account"`
	Outputs   []scriptValue `json:"outputs"`
	MinConf   int32         `json:"minconf"`
	SatsPerKB float64       `json:"satPerKb"`
	DryRun    bool          `json:"dryRun"`
}

type authoredTx struct {
	Tx              Bytes   `json:"tx"`
	PrevScripts     []Bytes `json:"prevScripts"`
	PrevInputValues []int64 `json:"prevInputValues"`
	TotalInput      uint64  `json:"totalInput"`
	ChangeIndex     int     `json:"changeIndex"` // negative if no change
}

func (w *Wallet) createSimpleTx(raw json.RawMessage) (string, error) {
	params := new(createSimpleTxParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	outputs := make([]*wire.TxOut, 0, len(params.Outputs))
	for _, txOut := range params.Outputs {
		outputs = append(outputs, wire.NewTxOut(txOut.Value, txOut.Script))
	}
	satsPerKB, err := btcutil.NewAmount(params.SatsPerKB)
	if err != nil {
		return "", err
	}

	wTx, err := w.CreateSimpleTx(params.Account, outputs, params.MinConf, satsPerKB, params.DryRun)
	if err != nil {
		return "", err
	}

	txB, err := serializeMsgTx(wTx.Tx)
	if err != nil {
		return "", err
	}

	return encode(&authoredTx{
		Tx:              txB,
		PrevScripts:     convertByteSliceSlice(wTx.PrevScripts),
		PrevInputValues: convertAmounts(wTx.PrevInputValues),
		TotalInput:      uint64(int64(wTx.TotalInput)),
		ChangeIndex:     wTx.ChangeIndex,
	})
}

// func (w *Wallet) Unlock(passphrase []byte, lock <-chan time.Time) error
type unlockParams struct {
	Passphrase Bytes `json:"passphrase"`
	Timeout    int64 `json:"timeout"`
}

func (w *Wallet) unlock(raw json.RawMessage) (string, error) {
	params := new(unlockParams)
	defer zero(params.Passphrase)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", nil
	}
	timeout := time.Second * time.Duration(params.Timeout)
	return "", w.Unlock(params.Passphrase, time.After(timeout))

}

// func (w *Wallet) Lock()
func (w *Wallet) lock(_ json.RawMessage) (string, error) {
	w.Lock()
	return "", nil
}

// func (w *Wallet) Locked() bool
func (w *Wallet) locked(_ json.RawMessage) (string, error) {
	return encode(w.Locked())
}

// func (w *Wallet) ChangePrivatePassphrase(old, new []byte) error
type changePassphraseParams struct {
	New Bytes `json:"new"`
	Old Bytes `json:"old"`
}

func (w *Wallet) changePrivatePassphrase(raw json.RawMessage) (string, error) {
	params := new(changePassphraseParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", nil
	}

	defer zero(params.New)
	defer zero(params.Old)

	return "", w.ChangePrivatePassphrase(params.Old, params.New)
}

// func (w *Wallet) ChangePublicPassphrase(old, new []byte) error
func (w *Wallet) changePublicPassphrase(raw json.RawMessage) (string, error) {
	params := new(changePassphraseParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", nil
	}
	defer zero(params.New)
	defer zero(params.Old)
	return "", w.ChangePublicPassphrase(params.Old, params.New)
}

// func (w *Wallet) ChangePassphrases(publicOld, publicNew, privateOld, privateNew []byte) error
type changePassphrasesParams struct {
	Public  changePassphraseParams `json:"public"`
	Private changePassphraseParams `json:"private"`
}

func (w *Wallet) changePassphrases(raw json.RawMessage) (string, error) {
	params := new(changePassphrasesParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", nil
	}
	defer zero(params.Public.New)
	defer zero(params.Public.Old)
	defer zero(params.Private.New)
	defer zero(params.Private.Old)
	return "", w.ChangePassphrases(params.Public.Old, params.Public.New, params.Private.Old, params.Private.New)
}

// func (w *Wallet) AccountAddresses(account uint32) (addrs []btcutil.Address, err error)
func (w *Wallet) accountAddresses(raw json.RawMessage) (string, error) {
	var account uint32
	err := json.Unmarshal(raw, &account)
	if err != nil {
		return "", err
	}
	addrs, err := w.AccountAddresses(account)
	if err != nil {
		return "", err
	}
	addrStrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addrStrs = append(addrStrs, addr.String())
	}
	return encode(addrStrs)
}

// func (w *Wallet) CalculateBalance(confirms int32) (btcutil.Amount, error)
func (w *Wallet) calculateBalance(raw json.RawMessage) (string, error) {
	var confirms int32
	err := json.Unmarshal(raw, &confirms)
	if err != nil {
		return "", err
	}
	amt, err := w.CalculateBalance(confirms)
	if err != nil {
		return "", err
	}
	return encode(int64(amt))
}

// func (w *Wallet) CalculateAccountBalances(account uint32, confirms int32) (Balances, error)
type calculateAccountBalances struct {
	Account  uint32 `json:"account"`
	Confirms int32  `json:"confirms"`
}

type balances struct {
	Total          int64 `json:"total"`
	Spendable      int64 `json:"spendable"`
	ImmatureReward int64 `json:"immatureReward"`
}

func (w *Wallet) calculateAccountBalances(raw json.RawMessage) (string, error) {
	params := new(calculateAccountBalances)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	bals, err := w.CalculateAccountBalances(params.Account, params.Confirms)
	if err != nil {
		return "", err
	}
	return encode(&balances{
		Total:          int64(bals.Total),
		Spendable:      int64(bals.Spendable),
		ImmatureReward: int64(bals.ImmatureReward),
	})
}

// func (w *Wallet) CurrentAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error)
type currentAddressParams struct {
	Account uint32   `json:"account"`
	Scope   keyScope `json:"scope"`
}

type keyScope struct {
	Purpose uint32 `json:"purpose"`
	Coin    uint32 `json:"coin"`
}

func (w *Wallet) currentAddress(raw json.RawMessage) (string, error) {
	params := new(currentAddressParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	addr, err := w.CurrentAddress(params.Account, waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	})
	if err != nil {
		return "", err
	}
	return encode(addr.String())
}

// func (w *Wallet) PubKeyForAddress(a btcutil.Address) (*btcec.PublicKey, error)
func (w *Wallet) pubKeyForAddress(raw json.RawMessage) (string, error) {
	addr, err := w.decodeJSONAddr(raw)
	if err != nil {
		return "", err
	}
	pubKey, err := w.PubKeyForAddress(addr)
	if err != nil {
		return "", err
	}
	return encode(hex.EncodeToString(pubKey.SerializeCompressed()))
}

// func (w *Wallet) LabelTransaction(hash chainhash.Hash, label string, overwrite bool) error
type labelTransactionParams struct {
	Hash      Bytes  `json:"hash"`
	Label     string `json:"label"`
	Overwrite bool   `json:"overwrite"`
}

func (w *Wallet) labelTransaction(raw json.RawMessage) (string, error) {
	params := new(labelTransactionParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	h := chainhash.Hash{}
	err = h.SetBytes(params.Hash)
	if err != nil {
		return "", err
	}
	return "", w.LabelTransaction(h, params.Label, params.Overwrite)
}

// func (w *Wallet) PrivKeyForAddress(a btcutil.Address) (*btcec.PrivateKey, error)
func (w *Wallet) privKeyForAddress(raw json.RawMessage) (string, error) {
	addr, err := w.decodeJSONAddr(raw)
	if err != nil {
		return "", err
	}
	privKey, err := w.PrivKeyForAddress(addr)
	if err != nil {
		return "", err
	}
	return encode(hex.EncodeToString(privKey.Serialize()))
}

// func (w *Wallet) HaveAddress(a btcutil.Address) (bool, error)
func (w *Wallet) haveAddress(raw json.RawMessage) (string, error) {
	addr, err := w.decodeJSONAddr(raw)
	if err != nil {
		return "", err
	}
	has, err := w.HaveAddress(addr)
	if err != nil {
		return "", err
	}
	return encode(has)
}

// func (w *Wallet) AccountOfAddress(a btcutil.Address) (uint32, error)
func (w *Wallet) accountOfAddress(raw json.RawMessage) (string, error) {
	addr, err := w.decodeJSONAddr(raw)
	if err != nil {
		return "", err
	}
	acct, err := w.AccountOfAddress(addr)
	if err != nil {
		return "", err
	}
	return encode(acct)
}

type managedAddress struct {
	Account    uint32 `json:"account"`
	Address    string `json:"address"`
	AddrHash   Bytes  `json:"addrHash"`
	Imported   bool   `json:"imported"`
	Internal   bool   `json:"internal"`
	Compressed bool   `json:"compressed"`
	// Used(ns walletdb.ReadBucket) bool
	AddrType uint8 `json:"addrType"`
}

// func (w *Wallet) AddressInfo(a btcutil.Address) (waddrmgr.ManagedAddress, error)
func (w *Wallet) addressInfo(raw json.RawMessage) (string, error) {
	addr, err := w.decodeJSONAddr(raw)
	if err != nil {
		return "", err
	}
	wAddr, err := w.AddressInfo(addr)
	if err != nil {
		return "", err
	}
	return encode(&managedAddress{
		Account:    wAddr.Account(),
		Address:    wAddr.Address().String(),
		AddrHash:   wAddr.AddrHash(),
		Imported:   wAddr.Imported(),
		Internal:   wAddr.Internal(),
		Compressed: wAddr.Compressed(),
		AddrType:   uint8(wAddr.AddrType()),
	})
}

// func (w *Wallet) AccountNumber(scope waddrmgr.KeyScope, accountName string) (uint32, error)
type accountNumberParams struct {
	Scope       keyScope `json:"scope"`
	AccountName string   `json:"accountName"`
}

func (w *Wallet) accountNumber(raw json.RawMessage) (string, error) {
	params := new(accountNumberParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	acct, err := w.AccountNumber(waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}, params.AccountName)
	if err != nil {
		return "", err
	}
	return encode(acct)
}

// func (w *Wallet) AccountName(scope waddrmgr.KeyScope, accountNumber uint32) (string, error)
type accountNameParams struct {
	Scope         keyScope `json:"scope"`
	AccountNumber uint32   `json:"accountNumber"`
}

func (w *Wallet) accountName(raw json.RawMessage) (string, error) {
	params := new(accountNameParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	acctName, err := w.AccountName(waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}, params.AccountNumber)
	if err != nil {
		return "", err
	}
	return encode(acctName)
}

// func (w *Wallet) AccountProperties(scope waddrmgr.KeyScope, acct uint32) (*waddrmgr.AccountProperties, error)
type accountPropertiesParams accountNameParams

type accountProperties struct {
	AccountNumber    uint32 `json:"accountNumber"`
	AccountName      string `json:"accountName"`
	ExternalKeyCount uint32 `json:"externalKeyCount"`
	InternalKeyCount uint32 `json:"internalKeyCount"`
	ImportedKeyCount uint32 `json:"importedKeyCount"`
}

func (w *Wallet) accountProperties(raw json.RawMessage) (string, error) {
	params := new(accountPropertiesParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	acctProps, err := w.AccountProperties(waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}, params.AccountNumber)
	if err != nil {
		return "", err
	}
	return encode(&accountProperties{
		AccountNumber:    acctProps.AccountNumber,
		AccountName:      acctProps.AccountName,
		ExternalKeyCount: acctProps.ExternalKeyCount,
		InternalKeyCount: acctProps.InternalKeyCount,
		ImportedKeyCount: acctProps.ImportedKeyCount,
	})
}

// func (w *Wallet) RenameAccount(scope waddrmgr.KeyScope, account uint32, newName string) error
type renameAccountParams struct {
	accountNameParams
	NewName string `json:"newName"`
}

func (w *Wallet) renameAccount(raw json.RawMessage) (string, error) {
	params := new(renameAccountParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	err = w.RenameAccount(waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}, params.AccountNumber, params.NewName)
	if err != nil {
		return "", err
	}
	return "", nil
}

// func (w *Wallet) NextAccount(scope waddrmgr.KeyScope, name string) (uint32, error)
type nextAccountParams accountNumberParams

func (w *Wallet) nextAccount(raw json.RawMessage) (string, error) {
	params := new(nextAccountParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	acct, err := w.NextAccount(waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}, params.AccountName)
	if err != nil {
		return "", err
	}
	return encode(acct)
}

// func (w *Wallet) ListSinceBlock(start, end, syncHeight int32) ([]btcjson.ListTransactionsResult, error)
type listSinceBlockParams struct {
	Start      int32 `json:"start"`
	End        int32 `json:"end"`
	SyncHeight int32 `json:"syncHeight"`
}

func (w *Wallet) listSinceBlock(raw json.RawMessage) (string, error) {
	params := new(listSinceBlockParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	txs, err := w.ListSinceBlock(params.Start, params.End, params.SyncHeight)
	if err != nil {
		return "", err
	}
	return encode(txs)
}

// func (w *Wallet) ListTransactions(from, count int) ([]btcjson.ListTransactionsResult, error)
type listTransactionsParams struct {
	From  int `json:"from"`
	Count int `json:"count"`
}

func (w *Wallet) listTransactions(raw json.RawMessage) (string, error) {
	params := new(listTransactionsParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	txs, err := w.ListTransactions(params.From, params.Count)
	if err != nil {
		return "", err
	}
	return encode(txs)
}

// func (w *Wallet) ListAddressTransactions(pkHashes map[string]struct{}) ([]btcjson.ListTransactionsResult, error)
func (w *Wallet) listAddressTransactions(raw json.RawMessage) (string, error) {
	var addresses []string
	err := json.Unmarshal(raw, &addresses)
	if err != nil {
		return "", err
	}
	hash160Map := make(map[string]struct{})
	for _, addrStr := range addresses {
		addr, err := btcutil.DecodeAddress(addrStr, w.params)
		if err != nil {
			return "", err
		}
		hash160Map[string(addr.ScriptAddress())] = struct{}{}
	}
	txs, err := w.ListAddressTransactions(hash160Map)
	if err != nil {
		return "", err
	}
	return encode(txs)
}

// func (w *Wallet) ListAllTransactions() ([]btcjson.ListTransactionsResult, error)
func (w *Wallet) listAllTransactions(_ json.RawMessage) (string, error) {
	txs, err := w.ListAllTransactions()
	if err != nil {
		return "", err
	}
	return encode(txs)
}

// TODO
// func (w *Wallet) GetTransactions(startBlock, endBlock *BlockIdentifier, cancel <-chan struct{}) (*GetTransactionsResult, error)

// func (w *Wallet) Accounts(scope waddrmgr.KeyScope) (*AccountsResult, error)
type accountResult struct {
	accountProperties
	TotalBalance int64 `json:"totalBalance"`
}

type accountsResult struct {
	Accounts           []accountResult `json:"accounts"`
	CurrentBlockHash   Bytes           `json:"currentBlockHash"`
	CurrentBlockHeight int32           `json:"currentBlockHeight"`
}

func (w *Wallet) accounts(raw json.RawMessage) (string, error) {
	scope := new(keyScope)
	err := json.Unmarshal(raw, scope)
	if err != nil {
		return "", err
	}
	res, err := w.Accounts(waddrmgr.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	})
	if err != nil {
		return "", err
	}
	acctsRes := &accountsResult{
		Accounts:           make([]accountResult, 0, len(res.Accounts)),
		CurrentBlockHash:   res.CurrentBlockHash[:],
		CurrentBlockHeight: res.CurrentBlockHeight,
	}
	for _, acctRes := range res.Accounts {
		acctsRes.Accounts = append(acctsRes.Accounts, accountResult{
			accountProperties: accountProperties{
				AccountNumber:    acctRes.AccountNumber,
				AccountName:      acctRes.AccountName,
				ExternalKeyCount: acctRes.ExternalKeyCount,
				InternalKeyCount: acctRes.InternalKeyCount,
				ImportedKeyCount: acctRes.ImportedKeyCount,
			},
			TotalBalance: int64(acctRes.TotalBalance),
		})
	}
	return encode(acctsRes)
}

// func (w *Wallet) AccountBalances(scope waddrmgr.KeyScope, requiredConfs int32) ([]AccountBalanceResult, error)
type accountBalancesParams struct {
	Scope         keyScope `json:"scope"`
	RequiredConfs int32    `json:"requiredConfs"`
}

type accountBalanceResult struct {
	AccountNumber  uint32 `json:"accountNumber"`
	AccountName    string `json:"accountName"`
	AccountBalance int64  `json:"accountBalance"`
}

func (w *Wallet) accountBalances(raw json.RawMessage) (string, error) {
	params := new(accountBalancesParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	balances, err := w.AccountBalances(waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}, params.RequiredConfs)
	if err != nil {
		return "", err
	}
	res := make([]accountBalanceResult, 0, len(balances))
	for _, bal := range balances {
		res = append(res, accountBalanceResult{
			AccountNumber:  bal.AccountNumber,
			AccountName:    bal.AccountName,
			AccountBalance: int64(bal.AccountBalance),
		})
	}
	return encode(res)
}

// func (w *Wallet) ListUnspent(minconf, maxconf int32, addresses map[string]struct{}) ([]*btcjson.ListUnspentResult, error)
type listUnspentParams struct {
	MinConf   int32    `json:"minConf"`
	MaxConf   int32    `json:"maxConf"`
	Addresses []string `json:"addresses"`
}

func (w *Wallet) listUnspent(raw json.RawMessage) (string, error) {
	params := new(listUnspentParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	var addresses map[string]struct{}
	if len(params.Addresses) > 0 {
		addresses = make(map[string]struct{})
		for _, as := range params.Addresses {
			a, err := btcutil.DecodeAddress(as, w.params)
			if err != nil {
				return "", err
			}
			addresses[a.EncodeAddress()] = struct{}{}
		}
	}
	unspents, err := w.ListUnspent(params.MinConf, params.MaxConf, addresses)
	if err != nil {
		return "", err
	}
	return encode(unspents)
}

// func (w *Wallet) DumpPrivKeys() ([]string, error)
func (w *Wallet) dumpPrivKeys(_ json.RawMessage) (string, error) {
	keys, err := w.DumpPrivKeys()
	if err != nil {
		return "", err
	}
	return encode(keys)
}

// func (w *Wallet) DumpWIFPrivateKey(addr btcutil.Address) (string, error)
func (w *Wallet) dumpWIFPrivateKey(raw json.RawMessage) (string, error) {
	addr, err := w.decodeJSONAddr(raw)
	if err != nil {
		return "", err
	}
	priv, err := w.DumpWIFPrivateKey(addr)
	if err != nil {
		return "", err
	}
	return encode(priv)
}

// func (w *Wallet) ImportPrivateKey(scope waddrmgr.KeyScope, wif *btcutil.WIF, bs *waddrmgr.BlockStamp, rescan bool) (string, error)

// WIF is a private key.
type WIF struct {
	PrivKey        Bytes `json:"privKey"`
	CompressPubKey bool  `json:"compressPubKey"`
}

type blockStamp struct {
	Height    int32 `json:"height"`
	Hash      Bytes `json:"hash"`
	Timestamp int64 `json:"timestamp"`
}

type importPrivateKeyParams struct {
	Scope      keyScope   `json:"keyScope"`
	WIF        WIF        `json:"wif"`
	BlockStamp blockStamp `json:"blockStamp"`
	Rescan     bool       `json:"rescan"`
}

func (w *Wallet) importPrivateKey(raw json.RawMessage) (string, error) {
	params := new(importPrivateKeyParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), params.WIF.PrivKey)
	wif, err := btcutil.NewWIF(privKey, w.params, params.WIF.CompressPubKey)
	if err != nil {
		return "", err
	}

	h := chainhash.Hash{}
	err = h.SetBytes(params.BlockStamp.Hash)
	if err != nil {
		return "", err
	}

	blockStamp := &waddrmgr.BlockStamp{
		Height:    params.BlockStamp.Height,
		Hash:      h,
		Timestamp: time.Unix(params.BlockStamp.Timestamp, 0),
	}

	scope := waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}

	res, err := w.ImportPrivateKey(scope, wif, blockStamp, params.Rescan)
	if err != nil {
		return "", err
	}

	return encode(res)
}

// func (w *Wallet) LockedOutpoint(op wire.OutPoint) bool
func (w *Wallet) lockedOutpoint(raw json.RawMessage) (string, error) {
	outPt, err := outpointFromJSON(raw)
	if err != nil {
		return "", err
	}
	return encode(w.LockedOutpoint(*outPt))
}

// func (w *Wallet) LockOutpoint(op wire.OutPoint)
func (w *Wallet) lockOutpoint(raw json.RawMessage) (string, error) {
	outPt, err := outpointFromJSON(raw)
	if err != nil {
		return "", err
	}
	w.LockOutpoint(*outPt)
	return "", nil
}

// func (w *Wallet) UnlockOutpoint(op wire.OutPoint)
func (w *Wallet) unlockOutpoint(raw json.RawMessage) (string, error) {
	outPt, err := outpointFromJSON(raw)
	if err != nil {
		return "", err
	}
	w.UnlockOutpoint(*outPt)
	return "", nil
}

// func (w *Wallet) ResetLockedOutpoints()
func (w *Wallet) resetLockedOutpoints(_ json.RawMessage) (string, error) {
	w.ResetLockedOutpoints()
	return "", nil
}

// func (w *Wallet) LockedOutpoints() []btcjson.TransactionInput
func (w *Wallet) lockedOutpoints(_ json.RawMessage) (string, error) {
	return encode(w.LockedOutpoints())
}

// func (w *Wallet) LeaseOutput(id wtxmgr.LockID, op wire.OutPoint) (time.Time, error)
type leaseOutputParams struct {
	ID       Bytes     `json:"id"`
	OutPoint hashIndex `json:"op"`
}

func parseLeaseOutputParams(raw json.RawMessage) (wtxmgr.LockID, *wire.OutPoint, error) {
	params := new(leaseOutputParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return wtxmgr.LockID{}, nil, err
	}

	var lockID wtxmgr.LockID // [32]byte
	copy(lockID[:], params.ID)

	h := chainhash.Hash{}
	err = h.SetBytes(params.OutPoint.Hash)
	if err != nil {
		return wtxmgr.LockID{}, nil, err
	}

	return lockID, wire.NewOutPoint(&h, uint32(params.OutPoint.Index)), nil
}

func (w *Wallet) leaseOutput(raw json.RawMessage) (string, error) {
	lockID, outPt, err := parseLeaseOutputParams(raw)
	if err != nil {
		return "", err
	}

	t, err := w.LeaseOutput(lockID, *outPt)
	if err != nil {
		return "", err
	}
	return encode(t.Unix())
}

// func (w *Wallet) ReleaseOutput(id wtxmgr.LockID, op wire.OutPoint) error
func (w *Wallet) releaseOutput(raw json.RawMessage) (string, error) {
	lockID, outPt, err := parseLeaseOutputParams(raw)
	if err != nil {
		return "", err
	}
	err = w.ReleaseOutput(lockID, *outPt)
	if err != nil {
		return "", err
	}
	return "", nil
}

// func (w *Wallet) SortedActivePaymentAddresses() ([]string, error)
func (w *Wallet) sortedActivePaymentAddresses(_ json.RawMessage) (string, error) {
	addrs, err := w.SortedActivePaymentAddresses()
	if err != nil {
		return "", err
	}
	return encode(addrs)
}

// func (w *Wallet) NewAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error)
func (w *Wallet) newAddress(raw json.RawMessage) (string, error) {
	params := new(currentAddressParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}

	addr, err := w.NewAddress(params.Account, waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	})
	if err != nil {
		return "", err
	}
	return encode(addr.String())
}

// func (w *Wallet) NewChangeAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error)
func (w *Wallet) newChangeAddress(raw json.RawMessage) (string, error) {
	params := new(currentAddressParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}

	addr, err := w.NewChangeAddress(params.Account, waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	})
	if err != nil {
		return "", err
	}
	return encode(addr.String())
}

// func (w *Wallet) TotalReceivedForAccounts(scope waddrmgr.KeyScope, minConf int32) ([]AccountTotalReceivedResult, error)
type totalReceivedForAccountsParams struct {
	Scope   keyScope `json:"scope"`
	MinConf int32    `json:"minConf"`
}

type accountTotalReceivedResult struct {
	AccountNumber    uint32 `json:"accountNumber"`
	AccountName      string `json:"accountName"`
	TotalReceived    int64  `json:"totalReceived"`
	LastConfirmation int32  `json:"lastConfirmation"`
}

func (w *Wallet) totalReceivedForAccounts(raw json.RawMessage) (string, error) {
	params := new(totalReceivedForAccountsParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	res, err := w.TotalReceivedForAccounts(waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}, params.MinConf)

	outRows := make([]accountTotalReceivedResult, 0, len(res))
	for _, recv := range res {
		outRows = append(outRows, accountTotalReceivedResult{
			AccountNumber:    recv.AccountNumber,
			AccountName:      recv.AccountName,
			TotalReceived:    int64(recv.TotalReceived),
			LastConfirmation: recv.LastConfirmation,
		})
	}
	return encode(outRows)
}

// func (w *Wallet) TotalReceivedForAddr(addr btcutil.Address, minConf int32) (btcutil.Amount, error)
type totalReceivedForAddr struct {
	Addr    string `json:"addr"`
	MinConf int32  `json:"minConf"`
}

func (w *Wallet) totalReceivedForAddr(raw json.RawMessage) (string, error) {
	params := new(totalReceivedForAddr)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}
	addr, err := btcutil.DecodeAddress(params.Addr, w.params)
	if err != nil {
		return "", err
	}
	amt, err := w.TotalReceivedForAddr(addr, params.MinConf)
	if err != nil {
		return "", err
	}
	return encode(int64(amt))
}

// func (w *Wallet) SendOutputs(outputs []*wire.TxOut, account uint32, minconf int32, satPerKb btcutil.Amount, label string) (*wire.MsgTx, error)
type sendOutputsParams struct {
	Outputs   []scriptValue `json:"outputs"`
	Account   uint32        `json:"account"`
	MinConf   int32         `json:"minConf"`
	SatsPerKB float64       `json:"satPerKb"`
	Label     string        `json:"label"`
}

func (w *Wallet) sendOutputs(raw json.RawMessage) (string, error) {
	params := new(sendOutputsParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}

	outputs := make([]*wire.TxOut, 0, len(params.Outputs))
	for _, op := range params.Outputs {
		outputs = append(outputs, wire.NewTxOut(op.Value, op.Script))
	}

	satsPerKB, err := btcutil.NewAmount(params.SatsPerKB)
	if err != nil {
		return "", err
	}

	msgTx, err := w.SendOutputs(outputs, params.Account, params.MinConf, satsPerKB, params.Label)
	if err != nil {
		return "", err
	}

	msgB, err := serializeMsgTx(msgTx)
	if err != nil {
		return "", err
	}

	return encode(hex.EncodeToString(msgB))
}

// func (w *Wallet) SignTransaction(tx *wire.MsgTx, hashType txscript.SigHashType,
// 	                            additionalPrevScripts map[wire.OutPoint][]byte,
// 	                            additionalKeysByAddress map[string]*btcutil.WIF,
// 	                            p2shRedeemScriptsByAddress map[string][]byte) ([]SignatureError, error)
type signTransactionParams struct {
	Tx                         Bytes            `json:"tx"`
	HashType                   uint32           `json:"hashType"`
	AdditionalPrevScripts      map[string]Bytes `json:"additionalPrevScripts"`
	AdditionalKeysByAddress    map[string]WIF   `json:"additionalKeysByAddress"`
	P2shRedeemScriptsByAddress map[string]Bytes `json:"p2shRedeemScriptsByAddress"`
}

type signatureError struct {
	InputIndex uint32 `json:"inputIndex"`
	Error      string `json:"error"`
}

type signTxResponse struct {
	SigErrors []signatureError `json:"sigErrs"`
	SignedTx  Bytes            `json:"signedTx"`
}

func (w *Wallet) signTransaction(raw json.RawMessage) (string, error) {
	params := new(signTransactionParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}

	tx := new(wire.MsgTx)
	err = tx.Deserialize(bytes.NewBuffer(params.Tx))
	if err != nil {
		return "", err
	}

	additionalPrevScripts := make(map[wire.OutPoint][]byte, len(params.AdditionalPrevScripts))
	for opStr, script := range params.AdditionalPrevScripts {
		parts := strings.Split(opStr, ":")
		if len(parts) != 2 {
			return "", fmt.Errorf("error decoding outpoint %q: %v", opStr, err)
		}
		hashStr, voutStr := parts[0], parts[1]

		h, err := chainhash.NewHashFromStr(hashStr)
		if err != nil {
			return "", err
		}

		vout, err := strconv.Atoi(voutStr)
		if err != nil {
			return "", err
		}

		op := wire.NewOutPoint(h, uint32(vout))
		additionalPrevScripts[*op] = script
	}

	additionalKeysByAddress := make(map[string]*btcutil.WIF, len(params.AdditionalKeysByAddress))
	for addr, wif := range params.AdditionalKeysByAddress {
		privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), wif.PrivKey)
		walletWIF, err := btcutil.NewWIF(privKey, w.params, wif.CompressPubKey)
		if err != nil {
			return "", err
		}
		additionalKeysByAddress[addr] = walletWIF
	}

	p2shRedeemScriptsByAddress := make(map[string][]byte, len(params.P2shRedeemScriptsByAddress))
	for addr, script := range params.P2shRedeemScriptsByAddress {
		p2shRedeemScriptsByAddress[addr] = script
	}

	wSigErrs, err := w.SignTransaction(tx, txscript.SigHashType(params.HashType), additionalPrevScripts, additionalKeysByAddress, p2shRedeemScriptsByAddress)
	if err != nil {
		return "", err
	}

	sigErrs := make([]signatureError, 0, len(wSigErrs))
	for _, e := range wSigErrs {
		eStr := ""
		if e.Error != nil {
			eStr = e.Error.Error()
		}

		sigErrs = append(sigErrs, signatureError{
			InputIndex: e.InputIndex,
			Error:      eStr,
		})
	}

	signedTxB, err := serializeMsgTx(tx)
	if err != nil {
		return "", err
	}

	return encode(&signTxResponse{
		SigErrors: sigErrs,
		SignedTx:  signedTxB,
	})
}

// func (w *Wallet) PublishTransaction(tx *wire.MsgTx, label string) error
type publishTransactionParams struct {
	Tx    Bytes  `json:"tx"`
	Label string `json:"label"`
}

func (w *Wallet) publishTransaction(raw json.RawMessage) (string, error) {
	params := new(publishTransactionParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}

	var tx wire.MsgTx
	err = tx.Deserialize(bytes.NewBuffer(params.Tx))
	if err != nil {
		return "", err
	}

	return "", w.PublishTransaction(&tx, params.Label)
}

// TODO: Just pass the name and grab the python versions Python-side.
// func (w *Wallet) ChainParams() *chaincfg.Params

func (w *Wallet) prepHandlers() {
	w.handlers = map[string]func(json.RawMessage) (string, error){
		"makeMultiSigScript":           w.makeMultiSigScript,
		"importP2SHRedeemScript":       w.importP2SHRedeemScript,
		"unspentOutputs":               w.unspentOutputs,
		"start":                        w.start,
		"stop":                         w.stop,
		"shuttingDown":                 w.shuttingDown,
		"waitForShutdown":              w.waitForShutdown,
		"synchronizingToNetwork":       w.synchronizingToNetwork,
		"chainSynced":                  w.chainSynced,
		"setChainSynced":               w.setChainSynced,
		"createSimpleTx":               w.createSimpleTx,
		"unlock":                       w.unlock,
		"lock":                         w.lock,
		"locked":                       w.locked,
		"changePrivatePassphrase":      w.changePrivatePassphrase,
		"changePublicPassphrase":       w.changePublicPassphrase,
		"changePassphrases":            w.changePassphrases,
		"accountAddresses":             w.accountAddresses,
		"calculateBalance":             w.calculateBalance,
		"calculateAccountBalances":     w.calculateAccountBalances,
		"currentAddress":               w.currentAddress,
		"pubKeyForAddress":             w.pubKeyForAddress,
		"labelTransaction":             w.labelTransaction,
		"privKeyForAddress":            w.privKeyForAddress,
		"haveAddress":                  w.haveAddress,
		"accountOfAddress":             w.accountOfAddress,
		"addressInfo":                  w.addressInfo,
		"accountNumber":                w.accountNumber,
		"accountName":                  w.accountName,
		"accountProperties":            w.accountProperties,
		"renameAccount":                w.renameAccount,
		"nextAccount":                  w.nextAccount,
		"listSinceBlock":               w.listSinceBlock,
		"listTransactions":             w.listTransactions,
		"listAddressTransactions":      w.listAddressTransactions,
		"listAllTransactions":          w.listAllTransactions,
		"accounts":                     w.accounts,
		"accountBalances":              w.accountBalances,
		"listUnspent":                  w.listUnspent,
		"dumpPrivKeys":                 w.dumpPrivKeys,
		"dumpWIFPrivateKey":            w.dumpWIFPrivateKey,
		"importPrivateKey":             w.importPrivateKey,
		"lockedOutpoint":               w.lockedOutpoint,
		"lockOutpoint":                 w.lockOutpoint,
		"unlockOutpoint":               w.unlockOutpoint,
		"resetLockedOutpoints":         w.resetLockedOutpoints,
		"lockedOutpoints":              w.lockedOutpoints,
		"leaseOutput":                  w.leaseOutput,
		"releaseOutput":                w.releaseOutput,
		"sortedActivePaymentAddresses": w.sortedActivePaymentAddresses,
		"newAddress":                   w.newAddress,
		"newChangeAddress":             w.newChangeAddress,
		"totalReceivedForAccounts":     w.totalReceivedForAccounts,
		"totalReceivedForAddr":         w.totalReceivedForAddr,
		"sendOutputs":                  w.sendOutputs,
		"signTransaction":              w.signTransaction,
		"publishTransaction":           w.publishTransaction,
		"syncStatus":                   w.syncStatus,
	}
}

func (w *Wallet) router(name string) walletRouter {
	return w.handlers[name]
}

// syncHeight is the best known sync height among peers.
func (w *Wallet) syncHeight() int32 {
	var maxHeight int32
	for _, p := range w.neutrino.Peers() {
		tipHeight := p.StartingHeight()
		lastBlockHeight := p.LastBlock()
		if lastBlockHeight > tipHeight {
			tipHeight = lastBlockHeight
		}
		if tipHeight > maxHeight {
			maxHeight = tipHeight
		}
	}
	return maxHeight
}

type syncStatus struct {
	Target  int32 `json:"target"`
	Height  int32 `json:"height"`
	Syncing bool  `json:"syncing"`
}

func (w *Wallet) syncStatus(_ json.RawMessage) (string, error) {
	blk, err := w.neutrino.BestBlock()
	if err != nil {
		return "", err
	}

	target := w.syncHeight()
	height := blk.Height

	ss := &syncStatus{
		Target: target,
		Height: height,
		// Syncing is whether the wallet has finished syncing. The second filter
		// is to prevent unexpected value in certain error situations.
		Syncing: !w.ChainSynced() && height >= target-1,
	}

	b, err := json.Marshal(ss)

	if err != nil {
		return "", nil
	}

	return string(b), nil
}

func walletExistsUtility(raw json.RawMessage) (string, error) {
	params := new(walletSpecs)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}

	netParams, err := parseNet(params.Net)
	if err != nil {
		return "", err
	}

	exists, err := walletExists(params.Dir, netParams)
	if err != nil {
		return "", err
	}

	b, err := json.Marshal(exists)
	if err != nil {
		return "", fmt.Errorf("walletExists error:  %v", err)
	}
	return string(b), nil
}

type createWalletParams struct {
	walletSpecs
	PW   Bytes `json:"pw"`
	Seed Bytes `json:"seed"`
}

func createWalletUtility(raw json.RawMessage) (string, error) {
	params := new(createWalletParams)
	err := json.Unmarshal(raw, params)
	if err != nil {
		return "", err
	}

	netParams, err := parseNet(params.Net)
	if err != nil {
		return "", err
	}

	exists, err := walletExists(params.Dir, netParams)
	if err != nil {
		return "", err
	}
	if exists {
		return "", fmt.Errorf("wallet already exists")
	}

	return "", createWallet(params.PW, params.Seed, params.Dir, netParams)
}
