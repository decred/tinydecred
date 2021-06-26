// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/lightninglabs/neutrino"
)

type walletConfig struct {
	DBDir        string
	Net          *chaincfg.Params
	ConnectPeers []string
}

func loadWallet(cfg *walletConfig) (*wallet.Wallet, *neutrino.ChainService, error) {
	netDir := filepath.Join(cfg.DBDir, cfg.Net.Name)
	// timeout and recoverWindow arguments borrowed from btcwallet directly.
	loader := wallet.NewLoader(cfg.Net, netDir, true, 60*time.Second, 250)

	exists, err := loader.WalletExists()
	if err != nil {
		return nil, nil, fmt.Errorf("error verifying wallet existence: %v", err)
	}
	if !exists {
		return nil, nil, fmt.Errorf("wallet not found")
	}

	nuetrinoDBPath := filepath.Join(netDir, "neutrino.db")
	spvdb, err := walletdb.Create("bdb", nuetrinoDBPath, true, 60*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to create wallet: %s", err)
	}
	// defer spvdb.Close()
	chainService, err := neutrino.NewChainService(neutrino.Config{
		DataDir:      netDir,
		Database:     spvdb,
		ChainParams:  *cfg.Net,
		ConnectPeers: cfg.ConnectPeers,
		// AddPeers:     cfg.AddPeers,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("Couldn't create Neutrino ChainService: %s", err)
	}

	chainClient := chain.NewNeutrinoClient(cfg.Net, chainService)
	err = chainClient.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("Couldn't start Neutrino client: %s", err)
	}

	loader.RunAfterLoad(func(w *wallet.Wallet) {
		w.SynchronizeRPC(chainClient)
	})

	w, err := loader.OpenExistingWallet([]byte(wallet.InsecurePubPassphrase), false)
	if err != nil {
		return nil, nil, err
	}

	return w, chainService, nil
}

func convertTxSummary(summary *wallet.TransactionSummary) *jsonTransactionSummary {

	jsonSummary := &jsonTransactionSummary{
		Hash:        summary.Hash[:],
		Transaction: summary.Transaction,
		MyInputs:    make([]jsonTransactionSummaryInput, 0, len(summary.MyInputs)),
		MyOutputs:   make([]jsonTransactionSummaryOutput, 0, len(summary.MyOutputs)),
		Fee:         int64(summary.Fee),
		Timestamp:   summary.Timestamp,
		Label:       summary.Label,
	}

	for i := range summary.MyInputs {
		input := &summary.MyInputs[i]
		jsonSummary.MyInputs = append(jsonSummary.MyInputs, jsonTransactionSummaryInput{
			Index:           input.Index,
			PreviousAccount: input.PreviousAccount,
			PreviousAmount:  int64(input.PreviousAmount),
		})
	}

	for i := range summary.MyOutputs {
		output := &summary.MyOutputs[i]
		jsonSummary.MyOutputs = append(jsonSummary.MyOutputs, jsonTransactionSummaryOutput{
			Index:    output.Index,
			Account:  output.Account,
			Internal: output.Internal,
		})
	}

	return jsonSummary
}

func notesLoop(ctx context.Context, w *wallet.Wallet) {
	txNotes := w.NtfnServer.TransactionNotifications()
	defer txNotes.Done()
	acctNotes := w.NtfnServer.AccountNotifications()
	defer acctNotes.Done()

	// TODO: Get fancier about which accounts to register for.
	spendNotes := w.NtfnServer.AccountSpentnessNotifications(0)
	defer spendNotes.Done()
	// confirmNotes := w.NtfnServer.ConfirmationNotifications(ctx)

	defer fmt.Println("--exiting notesLoop")

	for {
		var msg *feedMessage
		select {
		case note := <-txNotes.C:

			fmt.Printf("--txNote: %+v \n", note)

			noteBlocks := make([]noteBlock, 0, len(note.AttachedBlocks))
			for i := range note.AttachedBlocks {
				blk := &note.AttachedBlocks[i]
				txs := make([]jsonTransactionSummary, 0, len(blk.Transactions))
				for i := range blk.Transactions {
					txs = append(txs, *convertTxSummary(&blk.Transactions[i]))
				}
				noteBlocks = append(noteBlocks, noteBlock{
					Hash:         blk.Hash[:],
					Height:       blk.Height,
					Timestamp:    blk.Timestamp,
					Transactions: txs,
				})
			}

			detachedBlocks := make([]Bytes, 0, len(note.DetachedBlocks))
			for i := range note.DetachedBlocks {
				detachedBlocks = append(detachedBlocks, note.DetachedBlocks[i][:])
			}

			unminedTxs := make([]jsonTransactionSummary, 0, len(note.UnminedTransactions))
			for i := range note.UnminedTransactions {
				unminedTxs = append(unminedTxs, *convertTxSummary(&note.UnminedTransactions[i]))
			}

			bals := make([]noteBalance, 0, len(note.NewBalances))
			for i := range note.NewBalances {
				bal := &note.NewBalances[i]
				bals = append(bals, noteBalance{
					Acct:         bal.Account,
					TotalBalance: int64(bal.TotalBalance),
				})
			}

			msg = &feedMessage{
				FeedID:  walletFeedID,
				Subject: "tx",
				Payload: &jsonTransactionNotifications{
					AttachedBlocks:      noteBlocks,
					DetachedBlocks:      detachedBlocks,
					UnminedTransactions: unminedTxs,
					NewBalances:         bals,
				},
			}

		case note := <-acctNotes.C:

			fmt.Printf("--acctNotes: %+v \n", note)

			msg = &feedMessage{
				FeedID:  walletFeedID,
				Subject: "acct",
				Payload: accountNote{
					AccountNumber:    note.AccountNumber,
					AccountName:      note.AccountName,
					ExternalKeyCount: note.ExternalKeyCount,
					InternalKeyCount: note.InternalKeyCount,
					ImportedKeyCount: note.ImportedKeyCount,
				},
			}

		case note := <-spendNotes.C:

			fmt.Printf("--spendNotes: %+v \n", note)

			var spendHashB Bytes
			spendHash, spendVin, spent := note.Spender()
			if spent {
				spendHashB = spendHash[:]
			}

			h := note.Hash()

			msg = &feedMessage{
				FeedID:  walletFeedID,
				Subject: "spend",
				Payload: spentnessNote{
					Hash:        h[:],
					Vout:        note.Index(),
					SpenderHash: spendHashB,
					SpenderVin:  spendVin,
				},
			}

		case <-ctx.Done():
			return
		}

		select {
		case feedChan <- msg:
		case <-time.After(time.Second * 5):
			log.Errorf("Failed to send feed message")
		}
	}
}

func walletExists(dbDir string, net *chaincfg.Params) (bool, error) {
	netDir := filepath.Join(dbDir, net.Name)
	return wallet.NewLoader(net, netDir, true, 60*time.Second, 250).WalletExists()
}

func createWallet(privPass []byte, seed []byte, dbDir string, net *chaincfg.Params) error {
	netDir := filepath.Join(dbDir, net.Name)
	err := os.MkdirAll(netDir, 0777)
	if err != nil {
		return fmt.Errorf("error creating wallet directories: %v", err)
	}

	loader := wallet.NewLoader(net, netDir, true, 60*time.Second, 250)
	defer loader.UnloadWallet()

	// Ascertain the public passphrase.  This will either be a value
	// specified by the user or the default hard-coded public passphrase if
	// the user does not want the additional public data encryption.
	pubPass := []byte(wallet.InsecurePubPassphrase)

	log.Infof("Creating the wallet...")
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, time.Now())
	if err != nil {
		return err
	}

	_, err = w.NewAddress(0, waddrmgr.KeyScopeBIP0044)
	if err != nil {
		log.Errorf("Error creating first address: %v", err)
	}

	// fmt.Println("Creating the base '" + spvAcctName + "' account")
	// err = w.Unlock(privPass, time.After(time.Minute))
	// if err != nil {
	// 	return nil, err
	// }
	// _, err = w.NextAccount(waddrmgr.KeyScopeBIP0044, spvAcctName)
	// if err != nil {
	// 	return nil, err
	// }
	// w.Lock()

	return nil
}
