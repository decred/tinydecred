package main

import (
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/neutrino"
)

// LevelTrace Level = iota
// LevelDebug
// LevelInfo
// LevelWarn
// LevelError
// LevelCritical
// LevelOff

var log btclog.Logger

func useLogBackend(be *btclog.Backend, lvl btclog.Level) {
	logger := func(name string) btclog.Logger {
		lggr := be.Logger(name)
		lggr.SetLevel(lvl)
		return lggr
	}

	log = logger("LIB")
	wallet.UseLogger(logger("WLLT"))
	chain.UseLogger(logger("CHAIN"))
	wtxmgr.UseLogger(logger("TXMGR"))
	neutrino.UseLogger(logger("NTRNO"))
}

type logWriter struct{}

func (logWriter) Write(p []byte) (n int, err error) {
	feedChan <- &feedMessage{
		FeedID:  logFeedID,
		Payload: string(p),
	}

	return len(p), nil
}

func initializeLogging(lvl btclog.Level) {
	useLogBackend(btclog.NewBackend(logWriter{}), lvl)
}
