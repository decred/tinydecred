package main

/*
#include <stdlib.h>

typedef void (*pyfunc) (char *);

static inline void call_py_func(pyfunc ptr, char *b) {
    (ptr)(b);
}
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/btcsuite/btclog"
)

// CallData is the type sent for all golink calls.
type CallData struct {
	Function string          `json:"function"`
	Params   json.RawMessage `json:"params"`
}

func callError(s string, a ...interface{}) *C.char {
	b, _ := json.Marshal(&struct {
		Error string `json:"error"`
	}{
		Error: fmt.Sprintf(s, a...),
	})
	return C.CString(string(b))
}

var (
	wllt    *Wallet
	wlltMtx sync.RWMutex
)

func theWallet() *Wallet {
	wlltMtx.RLock()
	defer wlltMtx.RUnlock()
	return wllt
}

var utilityFuncs = map[string]walletRouter{
	"walletExists": walletExistsUtility,
	"createWallet": createWalletUtility,
	"init":         initUtility,
	"exit":         exitUtility,
}

// Call is used to invoke a registered function.
//export Call
func Call(msg *C.char, msgLen C.int) *C.char {
	jsonStr := C.GoString(msg)
	cd := new(CallData)
	err := json.Unmarshal([]byte(jsonStr), cd)
	if err != nil {
		return callError("json Unmarshal error: %v", err)
	}

	f, ok := utilityFuncs[cd.Function]
	if ok {
		s, err := f(cd.Params)
		if err != nil {
			return callError("%s error: %v", cd.Function, err)
		}
		return C.CString(s)
	}

	w := theWallet()

	if w == nil {
		return callError("wallet not initialized")
	}

	f = w.router(cd.Function)
	if f == nil {
		return callError("no function %q", cd.Function)
	}
	s, err := f(cd.Params)
	if err != nil {
		return callError("%s error: %v", cd.Function, err)
	}
	return C.CString(s)
}

var feeders = map[C.pyfunc]struct{}{}

// Feed allows the user to subscribe a function to receive asynchronous
// updates like log messages and streaming notifications.
//export Feed
func Feed(fn C.pyfunc) {
	if theWallet() != nil {
		panic("do not register golink Feed after the wallet is initialized")
	}
	feeders[fn] = struct{}{}
}

// FreeCharPtr frees the memory associated with a *C.char.
//export FreeCharPtr
func FreeCharPtr(b *C.char) {
	C.free(unsafe.Pointer(b))
}

const (
	logFeedID uint32 = iota
	walletFeedID
)

type feedMessage struct {
	FeedID  uint32      `json:"feedID"`
	Subject string      `json:"subject"`
	Payload interface{} `json:"payload"`
}

var feedChan = make(chan *feedMessage, 16)
var inited uint32

type initParams struct {
	walletInitParams
	LogLevel uint32 `json:"logLevel"`
}

func initUtility(raw json.RawMessage) (string, error) {

	if !atomic.CompareAndSwapUint32(&inited, 0, 1) || theWallet() != nil {
		return "", fmt.Errorf("already initialized")
	}

	init := new(initParams)
	err := json.Unmarshal(raw, init)
	if err != nil {
		return "", err
	}

	w, err := newWallet(&init.walletInitParams)
	if err != nil {
		return "", fmt.Errorf("wallet init error: %v", err)
	}

	wlltMtx.Lock()
	wllt = w
	wlltMtx.Unlock()

	// Just log to stdout for now. I thought sending logs
	// through the feed would be a good idea, but now I'm thinking
	// a separate log file and stdout when available.
	// initializeLogging(btclog.Level(init.LogLevel))

	go func() {
		for {
			select {
			case msg := <-feedChan:
				for feeder := range feeders {
					msgB, err := json.Marshal(msg)
					if err != nil {
						log.Errorf("JSON Marshal error: %v", err)
						continue
					}
					cStr := C.CString(string(msgB))
					C.call_py_func(feeder, cStr)
					FreeCharPtr(cStr)
				}
			case <-w.ctx.Done():
				return
			}
		}
	}()

	return `true`, nil
}

var isShutdown uint32

func exitUtility(_ json.RawMessage) (string, error) {
	w := theWallet()
	if !atomic.CompareAndSwapUint32(&isShutdown, 0, 1) || w == nil {
		return "", nil
	}
	w.Stop()
	w.WaitForShutdown()
	w.shutdown() // cancel the context
	return "", nil
}

func main() {}

func init() {
	useLogBackend(btclog.NewBackend(os.Stdout), btclog.LevelInfo)
}
