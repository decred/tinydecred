package main

import (
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

type btcWallet interface {
	MakeMultiSigScript(addrs []btcutil.Address, nRequired int) ([]byte, error)
	ImportP2SHRedeemScript(script []byte) (*btcutil.AddressScriptHash, error)
	// FundPsbt(packet *psbt.Packet, account uint32, feeSatPerKB btcutil.Amount) (int32, error)
	// FinalizePsbt(packet *psbt.Packet) error
	// SubmitRescan(job *RescanJob) <-chan error
	// Rescan(addrs []btcutil.Address, unspent []wtxmgr.Credit) error
	// ComputeInputScript(tx *wire.MsgTx, output *wire.TxOut, inputIndex int,
	// 	sigHashes *txscript.TxSigHashes, hashType txscript.SigHashType, tweaker PrivKeyTweaker) (wire.TxWitness, []byte, error)
	UnspentOutputs(policy wallet.OutputSelectionPolicy) ([]*wallet.TransactionOutput, error)
	// FetchInputInfo(prevOut *wire.OutPoint) (*wire.MsgTx, *wire.TxOut, int64, error)
	Start()
	// SynchronizeRPC(chainClient chain.Interface)
	// ChainClient() chain.Interface
	Stop()
	ShuttingDown() bool
	WaitForShutdown()
	SynchronizingToNetwork() bool
	ChainSynced() bool
	SetChainSynced(synced bool)
	CreateSimpleTx(account uint32, outputs []*wire.TxOut, minconf int32, satPerKb btcutil.Amount, dryRun bool) (*txauthor.AuthoredTx, error)
	Unlock(passphrase []byte, lock <-chan time.Time) error
	Lock()
	Locked() bool
	ChangePrivatePassphrase(old, new []byte) error
	ChangePublicPassphrase(old, new []byte) error
	ChangePassphrases(publicOld, publicNew, privateOld, privateNew []byte) error
	AccountAddresses(account uint32) (addrs []btcutil.Address, err error)
	CalculateBalance(confirms int32) (btcutil.Amount, error)
	CalculateAccountBalances(account uint32, confirms int32) (wallet.Balances, error)
	CurrentAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error)
	PubKeyForAddress(a btcutil.Address) (*btcec.PublicKey, error)
	LabelTransaction(hash chainhash.Hash, label string, overwrite bool) error
	PrivKeyForAddress(a btcutil.Address) (*btcec.PrivateKey, error)
	HaveAddress(a btcutil.Address) (bool, error)
	AccountOfAddress(a btcutil.Address) (uint32, error)
	AddressInfo(a btcutil.Address) (waddrmgr.ManagedAddress, error)
	AccountNumber(scope waddrmgr.KeyScope, accountName string) (uint32, error)
	AccountName(scope waddrmgr.KeyScope, accountNumber uint32) (string, error)
	AccountProperties(scope waddrmgr.KeyScope, acct uint32) (*waddrmgr.AccountProperties, error)
	RenameAccount(scope waddrmgr.KeyScope, account uint32, newName string) error
	NextAccount(scope waddrmgr.KeyScope, name string) (uint32, error)
	ListSinceBlock(start, end, syncHeight int32) ([]btcjson.ListTransactionsResult, error)
	ListTransactions(from, count int) ([]btcjson.ListTransactionsResult, error)
	ListAddressTransactions(pkHashes map[string]struct{}) ([]btcjson.ListTransactionsResult, error)
	ListAllTransactions() ([]btcjson.ListTransactionsResult, error)
	// GetTransactions(startBlock, endBlock *BlockIdentifier, cancel <-chan struct{}) (*GetTransactionsResult, error)
	Accounts(scope waddrmgr.KeyScope) (*wallet.AccountsResult, error)
	AccountBalances(scope waddrmgr.KeyScope, requiredConfs int32) ([]wallet.AccountBalanceResult, error)
	ListUnspent(minconf, maxconf int32, addresses map[string]struct{}) ([]*btcjson.ListUnspentResult, error)
	DumpPrivKeys() ([]string, error)
	DumpWIFPrivateKey(addr btcutil.Address) (string, error)
	ImportPrivateKey(scope waddrmgr.KeyScope, wif *btcutil.WIF, bs *waddrmgr.BlockStamp, rescan bool) (string, error)
	LockedOutpoint(op wire.OutPoint) bool
	LockOutpoint(op wire.OutPoint)
	UnlockOutpoint(op wire.OutPoint)
	ResetLockedOutpoints()
	LockedOutpoints() []btcjson.TransactionInput
	LeaseOutput(id wtxmgr.LockID, op wire.OutPoint) (time.Time, error)
	ReleaseOutput(id wtxmgr.LockID, op wire.OutPoint) error
	SortedActivePaymentAddresses() ([]string, error)
	NewAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error)
	NewChangeAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error)
	TotalReceivedForAccounts(scope waddrmgr.KeyScope, minConf int32) ([]wallet.AccountTotalReceivedResult, error)
	TotalReceivedForAddr(addr btcutil.Address, minConf int32) (btcutil.Amount, error)
	SendOutputs(outputs []*wire.TxOut, account uint32, minconf int32, satPerKb btcutil.Amount, label string) (*wire.MsgTx, error)
	SignTransaction(tx *wire.MsgTx, hashType txscript.SigHashType, additionalPrevScripts map[wire.OutPoint][]byte,
		additionalKeysByAddress map[string]*btcutil.WIF, p2shRedeemScriptsByAddress map[string][]byte) ([]wallet.SignatureError, error)
	PublishTransaction(tx *wire.MsgTx, label string) error
	// ChainParams() *chaincfg.Params
	// Database() walletdb.DB
}
