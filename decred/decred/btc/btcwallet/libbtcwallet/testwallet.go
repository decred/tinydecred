package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

type testWallet struct {
	data   map[string]json.RawMessage
	params *chaincfg.Params
}

func newTestWallet(dataPath string) (*testWallet, error) {
	enc, err := ioutil.ReadFile(dataPath)
	if err != nil {
		return nil, fmt.Errorf("error reading test data file: %v", err)
	}

	var testData map[string]json.RawMessage
	err = json.Unmarshal(enc, &testData)
	if err != nil {
		return nil, fmt.Errorf("error decoding test data: %v", err)
	}
	return &testWallet{
		data:   testData,
		params: &chaincfg.MainNetParams,
	}, nil
}

func (w *testWallet) testData(k string, thing interface{}) {
	stuff, found := w.data[k]
	if !found {
		panic("no test data at " + k)
	}
	err := json.Unmarshal(stuff, thing)
	if err != nil {
		panic(fmt.Sprintf("test data unmarshal error. key = %s, stuff = %s, err = %v", k, string(stuff), err))
	}
}

func (w *testWallet) MakeMultiSigScript(addrs []btcutil.Address, nRequired int) ([]byte, error) {
	var expAddr1, expAddr2 string
	var expConfs int
	w.testData("MakeMultiSigScript.in.addr.1", &expAddr1)
	w.testData("MakeMultiSigScript.in.addr.2", &expAddr2)
	w.testData("MakeMultiSigScript.in.nConfs", &expConfs)
	if addrs[0].String() != expAddr1 {
		return nil, fmt.Errorf("wrong address 1. wanted %s, got %s", expAddr1, addrs[0].String())
	}
	if addrs[1].String() != expAddr2 {
		return nil, fmt.Errorf("wrong address 1. wanted %s, got %s", expAddr1, addrs[1].String())
	}
	if nRequired != expConfs {
		return nil, fmt.Errorf("wrong number of confirmations. Expected %d, got %d", expConfs, nRequired)
	}

	var script Bytes
	w.testData("MakeMultiSigScript.out", &script)
	return script, nil
}

func (w *testWallet) ImportP2SHRedeemScript(script []byte) (*btcutil.AddressScriptHash, error) {
	var addrStr string
	var expScript Bytes
	w.testData("ImportP2SHRedeemScript.in.script", &expScript)
	w.testData("ImportP2SHRedeemScript.out.addr", &addrStr)
	if !bytes.Equal(script, expScript) {
		return nil, fmt.Errorf("wrong script. wanted %x, got %x", expScript[:], script)
	}
	addr, err := btcutil.DecodeAddress(addrStr, w.params)
	if err != nil {
		return nil, fmt.Errorf("DecodeAddress error: %v", err)
	}

	return addr.(*btcutil.AddressScriptHash), nil
}

func (w *testWallet) UnspentOutputs(policy wallet.OutputSelectionPolicy) ([]*wallet.TransactionOutput, error) {
	var expAcct uint32
	var expConfs int32
	w.testData("ImportP2SHRedeemScript.in.acct", &expAcct)
	w.testData("ImportP2SHRedeemScript.in.confs", &expConfs)

	if policy.Account != expAcct {
		return nil, fmt.Errorf("wrong account. wanted %d, got %d", expAcct, policy.Account)
	}
	if policy.RequiredConfirmations != expConfs {
		return nil, fmt.Errorf("wrong confs. wanted %d, got %d", expConfs, policy.RequiredConfirmations)
	}

	var txHashB, scriptB, blockHashB Bytes
	var outputKind byte
	var receiveTime, opVal int64
	var txIdx uint32
	var blockHeight int32
	w.testData("ImportP2SHRedeemScript.out.outPoint.hash", &txHashB)
	w.testData("ImportP2SHRedeemScript.out.outPoint.index", &txIdx)
	w.testData("ImportP2SHRedeemScript.out.output.script", &scriptB)
	w.testData("ImportP2SHRedeemScript.out.output.value", &opVal)
	w.testData("ImportP2SHRedeemScript.out.outputKind", &outputKind)
	w.testData("ImportP2SHRedeemScript.out.containingBlock.hash", &blockHashB)
	w.testData("ImportP2SHRedeemScript.out.containingBlock.index", &blockHeight)
	w.testData("ImportP2SHRedeemScript.out.receiveTime", &receiveTime)

	var txHash chainhash.Hash
	copy(txHash[:], txHashB)

	var blockHash chainhash.Hash
	copy(blockHash[:], blockHashB)

	return []*wallet.TransactionOutput{
		{
			OutPoint:   *wire.NewOutPoint(&txHash, txIdx),
			Output:     *wire.NewTxOut(opVal, scriptB),
			OutputKind: wallet.OutputKind(outputKind),
			ContainingBlock: wallet.BlockIdentity{
				Hash:   blockHash,
				Height: blockHeight,
			},
			ReceiveTime: time.Unix(receiveTime, 0),
		},
	}, nil
}

func (w *testWallet) Start() {}

func (w *testWallet) Stop() {}

func (w *testWallet) ShuttingDown() bool {
	var answer bool
	w.testData("ShuttingDown.out", &answer)
	return answer
}

func (w *testWallet) WaitForShutdown() {}

func (w *testWallet) SynchronizingToNetwork() bool {
	var answer bool
	w.testData("SynchronizingToNetwork.out", &answer)
	return answer
}

func (w *testWallet) ChainSynced() bool {
	var answer bool
	w.testData("ChainSynced.out", &answer)
	return answer
}

func (w *testWallet) SetChainSynced(synced bool) {
	var expSynced bool
	w.testData("SetChainSynced.in", &expSynced)
	if expSynced != synced {
		panic(fmt.Sprintf("wrong synced. wanted %t, got %t", expSynced, synced))
	}
}

func (w *testWallet) CreateSimpleTx(account uint32, outputs []*wire.TxOut, minconf int32, satPerKb btcutil.Amount, dryRun bool) (*txauthor.AuthoredTx, error) {
	var expAcct uint32
	var expOutputVal int64
	var expSatsPerKB float64
	var expPkScript Bytes
	var expMinConf int32
	var expDryRun bool
	w.testData("CreateSimpleTx.in.acct", &expAcct)
	w.testData("CreateSimpleTx.in.output.value", &expOutputVal)
	w.testData("CreateSimpleTx.in.output.script", &expPkScript)
	w.testData("CreateSimpleTx.in.minConf", &expMinConf)
	w.testData("CreateSimpleTx.in.satPerKb", &expSatsPerKB)
	w.testData("CreateSimpleTx.in.dryRun", &expDryRun)

	if account != expAcct {
		return nil, fmt.Errorf("wrong account. wanted %d, got %d", expAcct, account)
	}

	if len(outputs) != 1 {
		return nil, fmt.Errorf("expected 1 output. got %d", len(outputs))
	}
	output := outputs[0]
	if output.Value != expOutputVal {
		return nil, fmt.Errorf("wrong account. wanted %d, got %d", expOutputVal, output.Value)
	}
	if !bytes.Equal(output.PkScript, expPkScript) {
		return nil, fmt.Errorf("wrong pubkey script. wanted %x, got %x", expPkScript[:], output.PkScript)
	}

	if minconf != expMinConf {
		return nil, fmt.Errorf("wrong minconf. wanted %d, got %d", expMinConf, minconf)
	}

	expFeeRate, err := btcutil.NewAmount(expSatsPerKB)
	if err != nil {
		return nil, fmt.Errorf("NewAmount error: %v", err)
	}

	if satPerKb != expFeeRate {
		return nil, fmt.Errorf("wrong satPerKb. wanted %d, got %d", expFeeRate, satPerKb)
	}
	if dryRun != expDryRun {
		return nil, fmt.Errorf("wrong dryRun. wanted %t, got %t", expDryRun, dryRun)
	}

	// tx.addTxIn(msgtx.TxIn(previousOutPoint=msgtx.OutPoint(txHash=newHash(), idx=1982)))
	var txB, prevScript Bytes
	var prevVal int64
	var totalInput uint64
	var changeIndex int
	w.testData("CreateSimpleTx.out.tx", &txB)
	w.testData("CreateSimpleTx.out.prevScript", &prevScript)
	w.testData("CreateSimpleTx.out.prevInputValue", &prevVal)
	w.testData("CreateSimpleTx.out.totalInput", &totalInput)
	w.testData("CreateSimpleTx.out.changeIndex", &changeIndex)

	tx := &wire.MsgTx{}
	err = tx.Deserialize(bytes.NewBuffer(txB))
	if err != nil {
		return nil, fmt.Errorf("test tx deserialize error: %v", err)
	}

	return &txauthor.AuthoredTx{
		Tx:              tx,
		PrevScripts:     [][]byte{prevScript},
		PrevInputValues: []btcutil.Amount{btcutil.Amount(prevVal)},
		TotalInput:      btcutil.Amount(int64(totalInput)),
		ChangeIndex:     changeIndex,
	}, nil
}

func (w *testWallet) Unlock(passphrase []byte, lock <-chan time.Time) error {
	var expPassphrase string
	w.testData("Unlock.in.passphrase", &expPassphrase)
	if string(passphrase) != expPassphrase {
		return fmt.Errorf("wrong passphrase. expected %s, got  %s", expPassphrase, string(passphrase))
	}
	return nil
}

func (w *testWallet) Lock() {}

func (w *testWallet) Locked() bool {
	var answer bool
	w.testData("Locked.out", &answer)
	return answer
}

func (w *testWallet) ChangePrivatePassphrase(old, new []byte) error {
	var expOld, expNew string
	w.testData("ChangePrivatePassphrase.in.old", &expOld)
	w.testData("ChangePrivatePassphrase.in.new", &expNew)
	if string(old) != expOld {
		return fmt.Errorf("wrong old passphrase. expected %s, got %s", expOld, string(old))
	}
	if string(new) != expNew {
		return fmt.Errorf("wrong new passphrase. expected %s, got %s", expNew, string(new))
	}
	return nil
}

func (w *testWallet) ChangePublicPassphrase(old, new []byte) error {
	var expOld, expNew string
	w.testData("ChangePublicPassphrase.in.old", &expOld)
	w.testData("ChangePublicPassphrase.in.new", &expNew)
	if string(old) != expOld {
		return fmt.Errorf("wrong old passphrase. expected %s, got %s", expOld, string(old))
	}
	if string(new) != expNew {
		return fmt.Errorf("wrong new passphrase. expected %s, got %s", expNew, string(new))
	}
	return nil
}

func (w *testWallet) ChangePassphrases(publicOld, publicNew, privateOld, privateNew []byte) error {
	var expPublicOld, expPublicNew, expPrivateOld, expPrivateNew string
	w.testData("ChangePassphrases.in.publicOld", &expPublicOld)
	w.testData("ChangePassphrases.in.publicNew", &expPublicNew)
	w.testData("ChangePassphrases.in.privateOld", &expPrivateOld)
	w.testData("ChangePassphrases.in.privateNew", &expPrivateNew)
	if string(publicOld) != expPublicOld {
		return fmt.Errorf("wrong old public passphrase. expected %s, got %s", expPublicOld, string(publicOld))
	}
	if string(publicNew) != expPublicNew {
		return fmt.Errorf("wrong new public passphrase. expected %s, got %s", expPublicNew, string(publicNew))
	}
	if string(privateOld) != expPrivateOld {
		return fmt.Errorf("wrong old private passphrase. expected %s, got %s", expPrivateOld, string(privateOld))
	}
	if string(privateNew) != expPrivateNew {
		return fmt.Errorf("wrong new private passphrase. expected %s, got %s", expPrivateNew, string(privateNew))
	}
	return nil
}

func (w *testWallet) AccountAddresses(account uint32) (addrs []btcutil.Address, err error) {
	var expAcct uint32
	w.testData("AccountAddresses.in.acct", &expAcct)
	if account != expAcct {
		return nil, fmt.Errorf("wrong account. wanted %d, got %d", expAcct, account)
	}

	var outAddr1, outAddr2 string
	w.testData("AccountAddresses.out.addr.1", &outAddr1)
	w.testData("AccountAddresses.out.addr.2", &outAddr2)

	addr1, _ := btcutil.DecodeAddress(outAddr1, w.params)
	addr2, _ := btcutil.DecodeAddress(outAddr2, w.params)

	return []btcutil.Address{addr1, addr2}, nil
}

func (w *testWallet) CalculateBalance(confirms int32) (btcutil.Amount, error) {
	var expConfirms int32
	w.testData("CalculateBalance.in.confirms", &expConfirms)

	if expConfirms != confirms {
		return -1, fmt.Errorf("wrong confirms. expected %d, got %d", expConfirms, confirms)
	}

	var bal int64
	w.testData("CalculateBalance.out", &bal)
	return btcutil.Amount(bal), nil
}

func (w *testWallet) CalculateAccountBalances(account uint32, confirms int32) (wallet.Balances, error) {
	var expAcct uint32
	var expConfirms int32
	w.testData("CalculateAccountBalances.in.acct", &expAcct)
	w.testData("CalculateAccountBalances.in.confirms", &expConfirms)

	if expConfirms != confirms {
		return wallet.Balances{}, fmt.Errorf("wrong confirms. expected %d, got %d", expConfirms, confirms)
	}

	if account != expAcct {
		return wallet.Balances{}, fmt.Errorf("wrong account. wanted %d, got %d", expAcct, account)
	}

	var total, spendable, immature int64

	w.testData("CalculateAccountBalances.out.total", &total)
	w.testData("CalculateAccountBalances.out.spendable", &spendable)
	w.testData("CalculateAccountBalances.out.immatureReward", &immature)
	return wallet.Balances{
		Total:          btcutil.Amount(total),
		Spendable:      btcutil.Amount(spendable),
		ImmatureReward: btcutil.Amount(immature),
	}, nil
}

func (w *testWallet) CurrentAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error) {
	var expAcct, expPurpose, expCoin uint32
	w.testData("CurrentAddress.in.acct", &expAcct)
	w.testData("CurrentAddress.in.purpose", &expPurpose)
	w.testData("CurrentAddress.in.coin", &expCoin)
	if account != expAcct {
		return nil, fmt.Errorf("wrong account. wanted %d, got %d", expAcct, account)
	}
	if scope.Purpose != expPurpose {
		return nil, fmt.Errorf("wrong purpose. wanted %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return nil, fmt.Errorf("wrong coin. wanted %d, got %d", expCoin, scope.Coin)
	}

	var outAddrStr string
	w.testData("CurrentAddress.out.addr", &outAddrStr)
	addr, _ := btcutil.DecodeAddress(outAddrStr, w.params)
	return addr, nil
}

func (w *testWallet) PubKeyForAddress(a btcutil.Address) (*btcec.PublicKey, error) {
	var expAddr string
	w.testData("PubKeyForAddress.in.addr", &expAddr)
	if a.String() != expAddr {
		return nil, fmt.Errorf("wrong address. expected %s, got %s", expAddr, a.String())
	}

	var pkB Bytes
	w.testData("PubKeyForAddress.out.pubkey", &pkB)

	pubKey, err := btcec.ParsePubKey(pkB, btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("pubkey decode error %s: %v", hex.EncodeToString(pkB), err)
	}
	return pubKey, nil
}

func (w *testWallet) PrivKeyForAddress(a btcutil.Address) (*btcec.PrivateKey, error) {
	var expAddr string
	w.testData("PrivKeyForAddress.in.addr", &expAddr)

	var privB Bytes
	w.testData("PrivKeyForAddress.out.privkey", &privB)

	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), privB)

	return priv, nil
}

func (w *testWallet) LabelTransaction(hash chainhash.Hash, label string, overwrite bool) error {
	var expHash Bytes
	var expLabel string
	var expOverwrite bool
	w.testData("LabelTransaction.in.h", &expHash)
	w.testData("LabelTransaction.in.label", &expLabel)
	w.testData("LabelTransaction.in.overwrite", &expOverwrite)
	if !bytes.Equal(hash[:], expHash) {
		return fmt.Errorf("wrong tx hash. wanted %x, got %x", expHash[:], hash[:])
	}
	if expLabel != label {
		return fmt.Errorf("wrong tx hash. wanted %s, got %s", expLabel, label)
	}
	if expOverwrite != overwrite {
		return fmt.Errorf("wrong overwrite. wanted %t, got %t", expOverwrite, overwrite)
	}

	return nil
}

func (w *testWallet) HaveAddress(a btcutil.Address) (bool, error) {
	var expAddr string
	w.testData("HaveAddress.in", &expAddr)
	if expAddr != a.String() {
		return false, fmt.Errorf("wrong address. expected %s, got %s", expAddr, a.String())
	}

	var have bool
	w.testData("HaveAddress.out", &have)
	return have, nil
}

func (w *testWallet) AccountOfAddress(a btcutil.Address) (uint32, error) {
	var expAddr string
	w.testData("AccountOfAddress.in.addr", &expAddr)
	if expAddr != a.String() {
		return 0, fmt.Errorf("wrong address. expected %s, got %s", expAddr, a.String())
	}

	var acct uint32
	w.testData("AccountOfAddress.out.acct", &acct)
	return acct, nil
}

type tManagedAddress struct {
	acct       uint32
	addr       btcutil.Address
	addrHash   []byte
	imported   bool
	internal   bool
	compressed bool
	addrType   waddrmgr.AddressType
}

func (a *tManagedAddress) Account() uint32 {
	return a.acct
}

func (a *tManagedAddress) Address() btcutil.Address {
	return a.addr
}

func (a *tManagedAddress) AddrHash() []byte {
	return a.addrHash
}

func (a *tManagedAddress) Imported() bool {
	return a.imported
}

func (a *tManagedAddress) Internal() bool {
	return a.internal
}

func (a *tManagedAddress) Compressed() bool {
	return a.compressed
}

func (a *tManagedAddress) Used(ns walletdb.ReadBucket) bool {
	return false
}

func (a *tManagedAddress) AddrType() waddrmgr.AddressType {
	return a.addrType
}

func (w *testWallet) AddressInfo(a btcutil.Address) (waddrmgr.ManagedAddress, error) {
	var expAddr string
	w.testData("AddressInfo.in.addr", &expAddr)
	if expAddr != a.String() {
		return nil, fmt.Errorf("wrong address. expected %s, got %s", expAddr, a.String())
	}

	var acct uint32
	var addrStr string
	var addrHash Bytes
	var imported, internal, compressed bool
	var addrType uint8
	w.testData("AddressInfo.out.acct", &acct)
	w.testData("AddressInfo.out.addr", &addrStr)
	addr, _ := btcutil.DecodeAddress(addrStr, w.params)
	w.testData("AddressInfo.out.addrHash", &addrHash)
	w.testData("AddressInfo.out.imported", &imported)
	w.testData("AddressInfo.out.internal", &internal)
	w.testData("AddressInfo.out.compressed", &compressed)
	w.testData("AddressInfo.out.addrType", &addrType)

	return &tManagedAddress{
		acct:       acct,
		addr:       addr,
		addrHash:   addrHash,
		imported:   imported,
		internal:   internal,
		compressed: compressed,
		addrType:   waddrmgr.AddressType(addrType),
	}, nil
}

func (w *testWallet) AccountNumber(scope waddrmgr.KeyScope, accountName string) (uint32, error) {
	var expPurpose, expCoin uint32
	var expAcctName string
	w.testData("AccountNumber.in.scope.purpose", &expPurpose)
	w.testData("AccountNumber.in.scope.coin", &expCoin)
	w.testData("AccountNumber.in.accountName", &expAcctName)
	if scope.Purpose != expPurpose {
		return 0, fmt.Errorf("wrong purpose. expected %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return 0, fmt.Errorf("wrong coin. expected %d, got %d", expCoin, scope.Coin)
	}
	if accountName != expAcctName {
		return 0, fmt.Errorf("wrong account name. expected %s, got %s", expAcctName, accountName)
	}

	var acct uint32
	w.testData("AccountNumber.out.acct", &acct)
	return acct, nil
}

func (w *testWallet) AccountName(scope waddrmgr.KeyScope, accountNumber uint32) (string, error) {
	var expPurpose, expCoin, expAcct uint32
	w.testData("AccountName.in.scope.purpose", &expPurpose)
	w.testData("AccountName.in.scope.coin", &expCoin)
	w.testData("AccountName.in.acct", &expAcct)
	if scope.Purpose != expPurpose {
		return "", fmt.Errorf("wrong purpose. expected %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return "", fmt.Errorf("wrong coin. expected %d, got %d", expCoin, scope.Coin)
	}
	if accountNumber != expAcct {
		return "", fmt.Errorf("wrong account. wanted %d, got %d", expAcct, accountNumber)
	}

	var accountName string
	w.testData("AccountName.out.accountName", &accountName)
	return accountName, nil
}

func (w *testWallet) AccountProperties(scope waddrmgr.KeyScope, acct uint32) (*waddrmgr.AccountProperties, error) {
	var expPurpose, expCoin, expAcct uint32
	w.testData("AccountProperties.in.scope.purpose", &expPurpose)
	w.testData("AccountProperties.in.scope.coin", &expCoin)
	w.testData("AccountProperties.in.acct", &expAcct)
	if scope.Purpose != expPurpose {
		return nil, fmt.Errorf("wrong purpose. expected %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return nil, fmt.Errorf("wrong coin. expected %d, got %d", expCoin, scope.Coin)
	}
	if acct != expAcct {
		return nil, fmt.Errorf("wrong account. wanted %d, got %d", expAcct, acct)
	}

	var accountNumber, externalKeyCount, internalKeyCount, importedKeyCount uint32
	var accountName string
	w.testData("AccountProperties.out.accountNumber", &accountNumber)
	w.testData("AccountProperties.out.accountName", &accountName)
	w.testData("AccountProperties.out.externalKeyCount", &externalKeyCount)
	w.testData("AccountProperties.out.internalKeyCount", &internalKeyCount)
	w.testData("AccountProperties.out.importedKeyCount", &importedKeyCount)
	return &waddrmgr.AccountProperties{
		AccountNumber:    accountNumber,
		AccountName:      accountName,
		ExternalKeyCount: externalKeyCount,
		InternalKeyCount: internalKeyCount,
		ImportedKeyCount: importedKeyCount,
	}, nil
}

func (w *testWallet) RenameAccount(scope waddrmgr.KeyScope, account uint32, newName string) error {
	var expPurpose, expCoin, expAcct uint32
	var expNewName string
	w.testData("RenameAccount.in.scope.purpose", &expPurpose)
	w.testData("RenameAccount.in.scope.coin", &expCoin)
	w.testData("RenameAccount.in.acct", &expAcct)
	w.testData("RenameAccount.in.newName", &expNewName)
	if scope.Purpose != expPurpose {
		return fmt.Errorf("wrong purpose. expected %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return fmt.Errorf("wrong coin. expected %d, got %d", expCoin, scope.Coin)
	}
	if account != expAcct {
		return fmt.Errorf("wrong account. wanted %d, got %d", expAcct, account)
	}
	if newName != expNewName {
		return fmt.Errorf("wrong name. wanted %s, got %s", expNewName, newName)
	}
	return nil
}

func (w *testWallet) NextAccount(scope waddrmgr.KeyScope, name string) (uint32, error) {
	var expPurpose, expCoin uint32
	var expAcctName string
	w.testData("NextAccount.in.scope.purpose", &expPurpose)
	w.testData("NextAccount.in.scope.coin", &expCoin)
	w.testData("NextAccount.in.accountName", &expAcctName)
	if scope.Purpose != expPurpose {
		return 0, fmt.Errorf("wrong purpose. wanted %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return 0, fmt.Errorf("wrong coin. wanted %d, got %d", expCoin, scope.Coin)
	}
	if name != expAcctName {
		return 0, fmt.Errorf("wrong name. wanted %s, got %s", expAcctName, name)
	}

	var acct uint32
	w.testData("NextAccount.out.acct", &acct)
	return acct, nil
}

func (w *testWallet) ListSinceBlock(start, end, syncHeight int32) ([]btcjson.ListTransactionsResult, error) {
	var expStart, expEnd, expSyncHeight int32
	w.testData("ListSinceBlock.in.start", &expStart)
	w.testData("ListSinceBlock.in.end", &expEnd)
	w.testData("ListSinceBlock.in.syncHeight", &expSyncHeight)
	if start != expStart {
		return nil, fmt.Errorf("wrong start. wanted %d, got %d", expStart, start)
	}
	if end != expEnd {
		return nil, fmt.Errorf("wrong end. wanted %d, got %d", expEnd, end)
	}
	if syncHeight != expSyncHeight {
		return nil, fmt.Errorf("wrong syncHeight. wanted %d, got %d", expSyncHeight, syncHeight)
	}

	var blockTime int64
	w.testData("ListSinceBlock.out.blockTime", &blockTime)

	return []btcjson.ListTransactionsResult{{
		BlockTime: blockTime,
	}}, nil
}

func (w *testWallet) ListTransactions(from, count int) ([]btcjson.ListTransactionsResult, error) {
	var expFrom, expCount int
	w.testData("ListTransactions.in.skip", &expFrom)
	w.testData("ListTransactions.in.count", &expCount)
	if from != expFrom {
		return nil, fmt.Errorf("wrong from. wanted %d, got %d", expFrom, from)
	}
	if count != expCount {
		return nil, fmt.Errorf("wrong count. wanted %d, got %d", expCount, count)
	}

	var confs int64
	w.testData("ListTransactions.out.confs", &confs)
	return []btcjson.ListTransactionsResult{{
		Confirmations: confs,
	}}, nil
}

func (w *testWallet) ListAddressTransactions(pkHashes map[string]struct{}) ([]btcjson.ListTransactionsResult, error) {
	var pkHash []byte
	for hStr := range pkHashes {
		pkHash = []byte(hStr)
		break
	}
	var expPkHash Bytes
	w.testData("ListAddressTransactions.in.pkHash", &expPkHash)
	if !bytes.Equal(expPkHash, pkHash) {
		return nil, fmt.Errorf("wrong pkHash. wanted %x, got %x", expPkHash[:], pkHash)
	}

	var timeReceived int64
	w.testData("ListAddressTransactions.out.timeReceived", &timeReceived)
	return []btcjson.ListTransactionsResult{{
		TimeReceived: timeReceived,
	}}, nil
}

func (w *testWallet) ListAllTransactions() ([]btcjson.ListTransactionsResult, error) {
	var vout uint32
	w.testData("ListAllTransactions.out.vout", &vout)
	return []btcjson.ListTransactionsResult{{
		Vout: vout,
	}}, nil
}

func (w *testWallet) Accounts(scope waddrmgr.KeyScope) (*wallet.AccountsResult, error) {
	var expPurpose, expCoin uint32
	w.testData("Accounts.in.purpose", &expPurpose)
	w.testData("Accounts.in.coin", &expCoin)
	if scope.Purpose != expPurpose {
		return nil, fmt.Errorf("wrong purpose. wanted %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return nil, fmt.Errorf("wrong coin. wanted %d, got %d", expCoin, scope.Coin)
	}

	var blockHashB Bytes
	var blockHeight int32
	var balance int64
	var acct uint32
	w.testData("Accounts.out.blockHash", &blockHashB)
	w.testData("Accounts.out.blockHeight", &blockHeight)
	w.testData("Accounts.out.balance", &balance)
	w.testData("Accounts.out.acct", &acct)
	var blockHash chainhash.Hash
	copy(blockHash[:], blockHashB)
	return &wallet.AccountsResult{
		Accounts: []wallet.AccountResult{{
			AccountProperties: waddrmgr.AccountProperties{
				AccountNumber: acct,
			},
			TotalBalance: btcutil.Amount(balance),
		}},
		CurrentBlockHash:   &blockHash,
		CurrentBlockHeight: blockHeight,
	}, nil
}

func (w *testWallet) AccountBalances(scope waddrmgr.KeyScope, requiredConfs int32) ([]wallet.AccountBalanceResult, error) {
	var expConfs int32
	var expPurpose, expCoin uint32
	w.testData("AccountBalances.in.confs", &expConfs)
	w.testData("AccountBalances.in.purpose", &expPurpose)
	w.testData("AccountBalances.in.coin", &expCoin)
	if scope.Purpose != expPurpose {
		return nil, fmt.Errorf("wrong purpose. wanted %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return nil, fmt.Errorf("wrong coin. wanted %d, got %d", expCoin, scope.Coin)
	}
	if requiredConfs != expConfs {
		return nil, fmt.Errorf("wrong confs. wanted %d, got %d", expConfs, requiredConfs)
	}

	var acctNumber uint32
	var bal int64
	var acctName string
	w.testData("AccountBalances.out.acctNumber", &acctNumber)
	w.testData("AccountBalances.out.acctName", &acctName)
	w.testData("AccountBalances.out.balance", &bal)
	return []wallet.AccountBalanceResult{{
		AccountNumber:  acctNumber,
		AccountName:    acctName,
		AccountBalance: btcutil.Amount(bal),
	}}, nil
}

func (w *testWallet) ListUnspent(minconf, maxconf int32, addresses map[string]struct{}) ([]*btcjson.ListUnspentResult, error) {
	var expMinConf, expMaxConf int32
	var expAddr string
	w.testData("ListUnspent.in.minConf", &expMinConf)
	w.testData("ListUnspent.in.maxConf", &expMaxConf)
	w.testData("ListUnspent.in.addr", &expAddr)
	if minconf != expMinConf {
		return nil, fmt.Errorf("wrong minconf. wanted %d, got %d", expMinConf, minconf)
	}
	if maxconf != expMaxConf {
		return nil, fmt.Errorf("wrong maxconf. wanted %d, got %d", expMaxConf, maxconf)
	}
	var addr string
	for addr = range addresses {
		break
	}
	if addr != expAddr {
		return nil, fmt.Errorf("wrong addr. wanted %s, got %s", expAddr, addr)
	}

	var scriptPubKey string
	w.testData("ListUnspent.out.scriptPubKey", &scriptPubKey)
	return []*btcjson.ListUnspentResult{{
		ScriptPubKey: scriptPubKey,
	}}, nil
}

func (w *testWallet) DumpPrivKeys() ([]string, error) {
	var privKey string
	w.testData("DumpPrivKeys.out", &privKey)
	return []string{privKey}, nil
}

func (w *testWallet) DumpWIFPrivateKey(a btcutil.Address) (string, error) {
	var expAddr string
	w.testData("DumpWIFPrivateKey.in.addr", &expAddr)
	if expAddr != a.String() {
		return "", fmt.Errorf("wrong address. expected %s, got %s", expAddr, a.String())
	}

	var encWIF string
	w.testData("DumpWIFPrivateKey.out.wif", &encWIF)
	return encWIF, nil
}

func (w *testWallet) ImportPrivateKey(scope waddrmgr.KeyScope, wif *btcutil.WIF, bs *waddrmgr.BlockStamp, rescan bool) (string, error) {
	var expPurpose, expCoin uint32
	var expBlockHeight int32
	var expBlockHash Bytes
	var expStamp int64
	var expEncWIF string
	var expRescan bool
	w.testData("ImportPrivateKey.in.purpose", &expPurpose)
	w.testData("ImportPrivateKey.in.coin", &expCoin)
	w.testData("ImportPrivateKey.in.wif", &expEncWIF)
	w.testData("ImportPrivateKey.in.blockHeight", &expBlockHeight)
	w.testData("ImportPrivateKey.in.blockHash", &expBlockHash)
	w.testData("ImportPrivateKey.in.blockStamp", &expStamp)
	w.testData("ImportPrivateKey.in.rescan", &expRescan)
	if scope.Purpose != expPurpose {
		return "", fmt.Errorf("wrong purpose. wanted %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return "", fmt.Errorf("wrong coin. wanted %d, got %d", expCoin, scope.Coin)
	}
	if wif.String() != expEncWIF {
		return "", fmt.Errorf("wrong wif. wanted %s, got %s", expEncWIF, wif.String())
	}
	if bs.Height != expBlockHeight {
		return "", fmt.Errorf("wrong block height. wanted %d, got %d", expBlockHeight, bs.Height)
	}
	if !bytes.Equal(bs.Hash[:], expBlockHash[:]) {
		return "", fmt.Errorf("wrong block hash. wanted %x, got %x", expBlockHash[:], bs.Hash[:])
	}
	if bs.Timestamp.Unix() != expStamp {
		return "", fmt.Errorf("wrong block time. wanted %d, got %d", expStamp, bs.Timestamp.Unix())
	}
	if rescan != expRescan {
		return "", fmt.Errorf("wrong rescan. wanted %t, got %t", expRescan, rescan)
	}

	var addrStr string
	w.testData("ImportPrivateKey.out.addr", &addrStr)
	return addrStr, nil
}

func (w *testWallet) LockedOutpoint(op wire.OutPoint) bool {
	var expHash Bytes
	var expIndex uint32
	w.testData("LockedOutpoint.in.hash", &expHash)
	w.testData("LockedOutpoint.in.index", &expIndex)
	if !bytes.Equal(op.Hash[:], expHash) {
		panic(fmt.Sprintf("LockedOutpoint: wrong tx hash. wanted %x, got %x", expHash[:], op.Hash[:]))
	}
	if op.Index != expIndex {
		panic(fmt.Sprintf("LockedOutpoint: wrong tx index. wanted %d, got %d", expIndex, op.Index))
	}

	var locked bool
	w.testData("LockedOutpoint.out.locked", &locked)
	return locked
}

func (w *testWallet) LockOutpoint(op wire.OutPoint) {
	var expHash Bytes
	var expIndex uint32
	w.testData("LockOutpoint.in.hash", &expHash)
	w.testData("LockOutpoint.in.index", &expIndex)
	if !bytes.Equal(op.Hash[:], expHash) {
		panic(fmt.Sprintf("LockOutpoint: wrong tx hash. wanted %x, got %x", expHash[:], op.Hash[:]))
	}
	if op.Index != expIndex {
		panic(fmt.Sprintf("LockOutpoint: wrong tx index. wanted %d, got %d", expIndex, op.Index))
	}
}

func (w *testWallet) UnlockOutpoint(op wire.OutPoint) {
	var expHash Bytes
	var expIndex uint32
	w.testData("UnlockOutpoint.in.hash", &expHash)
	w.testData("UnlockOutpoint.in.index", &expIndex)
	if !bytes.Equal(op.Hash[:], expHash) {
		panic(fmt.Sprintf("UnlockOutpoint: wrong tx hash. wanted %x, got %x", expHash[:], op.Hash[:]))
	}
	if op.Index != expIndex {
		panic(fmt.Sprintf("UnlockOutpoint: wrong tx index. wanted %d, got %d", expIndex, op.Index))
	}
}

func (w *testWallet) ResetLockedOutpoints() {}

func (w *testWallet) LockedOutpoints() []btcjson.TransactionInput {
	var hexHash Bytes
	w.testData("LockedOutpoints.out.hash", &hexHash)

	var h chainhash.Hash
	copy(h[:], hexHash)

	return []btcjson.TransactionInput{{
		Txid: h.String(),
	}}
}

func (w *testWallet) LeaseOutput(id wtxmgr.LockID, op wire.OutPoint) (time.Time, error) {
	var expLockID, expHash Bytes
	var expIdx uint32
	w.testData("LeaseOutput.in.hash", &expHash)
	w.testData("LeaseOutput.in.index", &expIdx)
	w.testData("LeaseOutput.in.lockID", &expLockID)
	if !bytes.Equal(op.Hash[:], expHash) {
		return time.Time{}, fmt.Errorf("wrong tx hash. wanted %x, got %x", expHash[:], op.Hash[:])
	}
	if op.Index != expIdx {
		return time.Time{}, fmt.Errorf("wrong tx index. wanted %d, got %d", expIdx, op.Index)
	}
	if !bytes.Equal(id[:], expLockID) {
		return time.Time{}, fmt.Errorf("wrong lock ID. wanted %x, got %x", id[:], expLockID[:])
	}

	var stamp int64
	w.testData("LeaseOutput.out", &stamp)
	return time.Unix(stamp, 0), nil
}

func (w *testWallet) ReleaseOutput(id wtxmgr.LockID, op wire.OutPoint) error {
	var expLockID, expHash Bytes
	var expIdx uint32
	w.testData("ReleaseOutput.in.hash", &expHash)
	w.testData("ReleaseOutput.in.index", &expIdx)
	w.testData("ReleaseOutput.in.lockID", &expLockID)
	if !bytes.Equal(op.Hash[:], expHash) {
		return fmt.Errorf("wrong tx hash. wanted %x, got %x", expHash[:], op.Hash[:])
	}
	if op.Index != expIdx {
		return fmt.Errorf("wrong tx index. wanted %d, got %d", expIdx, op.Index)
	}
	if !bytes.Equal(id[:], expLockID) {
		return fmt.Errorf("wrong lock ID. wanted %x, got %x", id[:], expLockID[:])
	}
	return nil
}

func (w *testWallet) SortedActivePaymentAddresses() ([]string, error) {
	var addr string
	w.testData("SortedActivePaymentAddresses.out", &addr)
	return []string{addr}, nil
}

func (w *testWallet) NewAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error) {
	var expAcct, expPurpose, expCoin uint32
	w.testData("NewAddress.in.acct", &expAcct)
	w.testData("NewAddress.in.purpose", &expPurpose)
	w.testData("NewAddress.in.coin", &expCoin)
	if account != expAcct {
		return nil, fmt.Errorf("wrong account. wanted %d, got %d", expAcct, account)
	}
	if scope.Purpose != expPurpose {
		return nil, fmt.Errorf("wrong purpose. wanted %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return nil, fmt.Errorf("wrong coin. wanted %d, got %d", expCoin, scope.Coin)
	}

	var addrStr string
	w.testData("NewAddress.out.addr", &addrStr)
	addr, _ := btcutil.DecodeAddress(addrStr, w.params)
	return addr, nil
}

func (w *testWallet) NewChangeAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error) {
	var expAcct, expPurpose, expCoin uint32
	w.testData("NewChangeAddress.in.acct", &expAcct)
	w.testData("NewChangeAddress.in.purpose", &expPurpose)
	w.testData("NewChangeAddress.in.coin", &expCoin)
	if account != expAcct {
		return nil, fmt.Errorf("wrong account. wanted %d, got %d", expAcct, account)
	}
	if scope.Purpose != expPurpose {
		return nil, fmt.Errorf("wrong purpose. wanted %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return nil, fmt.Errorf("wrong coin. wanted %d, got %d", expCoin, scope.Coin)
	}

	var addrStr string
	w.testData("NewChangeAddress.out.addr", &addrStr)
	addr, _ := btcutil.DecodeAddress(addrStr, w.params)
	return addr, nil
}

func (w *testWallet) TotalReceivedForAccounts(scope waddrmgr.KeyScope, minConf int32) ([]wallet.AccountTotalReceivedResult, error) {
	var expPurpose, expCoin uint32
	var expConfs int32
	w.testData("TotalReceivedForAccounts.in.purpose", &expPurpose)
	w.testData("TotalReceivedForAccounts.in.coin", &expCoin)
	w.testData("TotalReceivedForAccounts.in.minConf", &expConfs)
	if scope.Purpose != expPurpose {
		return nil, fmt.Errorf("wrong purpose. wanted %d, got %d", expPurpose, scope.Purpose)
	}
	if scope.Coin != expCoin {
		return nil, fmt.Errorf("wrong coin. wanted %d, got %d", expCoin, scope.Coin)
	}
	if minConf != expConfs {
		return nil, fmt.Errorf("wrong minConf. wanted %d, got %d", expConfs, minConf)
	}

	var accountNumber uint32
	var lastConfirmation int32
	var accountName string
	var totalReceived int64
	w.testData("TotalReceivedForAccounts.out.accountNumber", &accountNumber)
	w.testData("TotalReceivedForAccounts.out.accountName", &accountName)
	w.testData("TotalReceivedForAccounts.out.totalReceived", &totalReceived)
	w.testData("TotalReceivedForAccounts.out.lastConfirmation", &lastConfirmation)
	return []wallet.AccountTotalReceivedResult{{
		AccountNumber:    accountNumber,
		AccountName:      accountName,
		TotalReceived:    btcutil.Amount(totalReceived),
		LastConfirmation: lastConfirmation,
	}}, nil
}

func (w *testWallet) TotalReceivedForAddr(a btcutil.Address, minConf int32) (btcutil.Amount, error) {
	var expAddr string
	var expConfs int32
	w.testData("TotalReceivedForAddr.in.addr", &expAddr)
	w.testData("TotalReceivedForAddr.in.minConf", &expConfs)
	if expAddr != a.String() {
		return 0, fmt.Errorf("wrong address. expected %s, got %s", expAddr, a.String())
	}
	if minConf != expConfs {
		return 0, fmt.Errorf("wrong minConf. wanted %d, got %d", expConfs, minConf)
	}
	var total int64
	w.testData("TotalReceivedForAddr.out.amt", &total)
	return btcutil.Amount(total), nil
}

func (w *testWallet) SendOutputs(outputs []*wire.TxOut, account uint32, minconf int32, satPerKb btcutil.Amount, label string) (*wire.MsgTx, error) {
	if len(outputs) != 1 {
		return nil, fmt.Errorf("expected 1 output, got %d", len(outputs))
	}
	output := outputs[0]

	var expVal int64
	var expSatPerKb float64
	var expPkScript Bytes
	var expAcct uint32
	var expConfs int32
	var expLabel string
	w.testData("SendOutputs.in.value", &expVal)
	w.testData("SendOutputs.in.pkScript", &expPkScript)
	w.testData("SendOutputs.in.acct", &expAcct)
	w.testData("SendOutputs.in.minconf", &expConfs)
	w.testData("SendOutputs.in.satPerKb", &expSatPerKb)
	w.testData("SendOutputs.in.label", &expLabel)
	if output.Value != expVal {
		return nil, fmt.Errorf("wrong output value. wanted %d, got %d", expVal, output.Value)
	}
	if !bytes.Equal(output.PkScript, expPkScript) {
		return nil, fmt.Errorf("wrong pubkey script. wanted %x, got %x", expPkScript[:], output.PkScript)
	}
	if account != expAcct {
		return nil, fmt.Errorf("wrong account. wanted %d, got %d", expAcct, account)
	}
	if minconf != expConfs {
		return nil, fmt.Errorf("wrong minconf. wanted %d, got %d", expConfs, minconf)
	}
	expFeeRate, err := btcutil.NewAmount(expSatPerKb)
	if err != nil {
		return nil, fmt.Errorf("NewAmount error: %v", err)
	}
	if satPerKb != expFeeRate {
		return nil, fmt.Errorf("wrong satPerKb. wanted %d, got %d", expFeeRate, satPerKb)
	}
	if expLabel != label {
		return nil, fmt.Errorf("wrong label. wanted %s, got %s", expLabel, label)
	}

	var txB Bytes
	w.testData("SendOutputs.out.tx", &txB)
	tx := &wire.MsgTx{}
	err = tx.Deserialize(bytes.NewBuffer(txB))
	if err != nil {
		return nil, fmt.Errorf("test tx deserialize error: %v", err)
	}

	return tx, nil
}

func (w *testWallet) SignTransaction(tx *wire.MsgTx, hashType txscript.SigHashType, additionalPrevScripts map[wire.OutPoint][]byte,
	additionalKeysByAddress map[string]*btcutil.WIF, p2shRedeemScriptsByAddress map[string][]byte) ([]wallet.SignatureError, error) {

	var expTxB, expPrevHash, expPrevScript, expRedeemScript Bytes
	var expHashType, expPrevIdx uint32
	var expKeyAddr, expWIF, expScriptAddr string
	w.testData("SignTransaction.in.tx", &expTxB)
	w.testData("SignTransaction.in.hashType", &expHashType)
	w.testData("SignTransaction.in.prevout.hash", &expPrevHash)
	w.testData("SignTransaction.in.prevout.idx", &expPrevIdx)
	w.testData("SignTransaction.in.prevout.script", &expPrevScript)
	w.testData("SignTransaction.in.key.addr", &expKeyAddr)
	w.testData("SignTransaction.in.key.wif", &expWIF)
	w.testData("SignTransaction.in.script.addr", &expScriptAddr)
	w.testData("SignTransaction.in.script.script", &expRedeemScript)

	txB, err := serializeMsgTx(tx)
	if err != nil {
		return nil, fmt.Errorf("error serializing input transaction: %v", err)
	}
	if !bytes.Equal(expTxB, txB) {
		return nil, fmt.Errorf("wrong tx. wanted %x, got %x", expTxB[:], txB)
	}
	if hashType != txscript.SigHashType(expHashType) {
		return nil, fmt.Errorf("wrong hash type. wanted %d, got %d", expHashType, hashType)
	}
	if len(additionalPrevScripts) != 1 {
		return nil, fmt.Errorf("expected 1 additionalPrevScripts, got %d", len(additionalPrevScripts))
	}
	var op wire.OutPoint
	var prevScript []byte
	for op, prevScript = range additionalPrevScripts {
		break
	}
	if !bytes.Equal(op.Hash[:], expPrevHash) {
		return nil, fmt.Errorf("wrong prev hash. wanted %x, got %x", expPrevHash, op.Hash[:])
	}
	if op.Index != expPrevIdx {
		return nil, fmt.Errorf("wrong prev index. wanted %d, got %d", expPrevIdx, op.Index)
	}
	if !bytes.Equal(prevScript, expPrevScript) {
		return nil, fmt.Errorf("wrong previous script. expected %x, got %x", expPrevScript[:], prevScript)
	}
	if len(additionalKeysByAddress) != 1 {
		return nil, fmt.Errorf("expected 1 additionalKeysByAddress, got %d", len(additionalKeysByAddress))
	}
	var addrStr string
	var wif *btcutil.WIF
	for addrStr, wif = range additionalKeysByAddress {
		break
	}
	if addrStr != expKeyAddr {
		return nil, fmt.Errorf("wrong key addr. wanted %s, got %s", expKeyAddr, addrStr)
	}
	if wif.String() != expWIF {
		return nil, fmt.Errorf("wrong wif. wanted %s, got %s", expWIF, wif.String())
	}
	if len(p2shRedeemScriptsByAddress) != 1 {
		return nil, fmt.Errorf("expected 1 p2shRedeemScriptsByAddress, got %d", len(p2shRedeemScriptsByAddress))
	}
	var scriptAddr string
	var redeemScript []byte
	for scriptAddr, redeemScript = range p2shRedeemScriptsByAddress {
		break
	}
	if scriptAddr != expScriptAddr {
		return nil, fmt.Errorf("wrong wif. wanted %s, got %s", expScriptAddr, scriptAddr)
	}
	if !bytes.Equal(redeemScript, expRedeemScript) {
		return nil, fmt.Errorf("wrong redeem script. expected %x, got %x", expRedeemScript[:], redeemScript)
	}

	var sigScript Bytes
	w.testData("SignTransaction.out.sigScript", &sigScript)
	if len(tx.TxIn) != 1 {
		return nil, fmt.Errorf("expected 1 input, got %d", len(tx.TxIn))
	}
	tx.TxIn[0].SignatureScript = sigScript

	return nil, nil
}

func (w *testWallet) PublishTransaction(tx *wire.MsgTx, label string) error {
	var expTxB Bytes
	var expLabel string
	w.testData("PublishTransaction.in.tx", &expTxB)
	w.testData("PublishTransaction.in.label", &expLabel)
	txB, err := serializeMsgTx(tx)
	if err != nil {
		return fmt.Errorf("error serializing input transaction: %v", err)
	}
	if !bytes.Equal(expTxB, txB) {
		return fmt.Errorf("wrong tx. wanted %x, got %x", expTxB[:], txB)
	}
	if expLabel != label {
		return fmt.Errorf("wrong tx hash. wanted %s, got %s", expLabel, label)
	}
	return nil
}
