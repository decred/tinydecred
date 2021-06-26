package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type scriptValue struct {
	Script Bytes `json:"script"`
	Value  int64 `json:"value"`
}

type hashIndex struct {
	Hash  Bytes `json:"hash"`
	Index int64 `json:"index"`
}

// Bytes is a byte slice that marshals to and unmarshals from a hexadecimal
// string. The default go behavior is to marshal []byte to a base-64 string.
type Bytes []byte

// String return the hex encoding of the Bytes.
func (b Bytes) String() string {
	return hex.EncodeToString(b)
}

// MarshalJSON satisfies the json.Marshaller interface, and will marshal the
// bytes to a hex string.
func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(b))
}

// UnmarshalJSON satisfies the json.Unmarshaler interface, and expects a UTF-8
// encoding of a hex string in double quotes.
func (b *Bytes) UnmarshalJSON(encHex []byte) (err error) {
	if len(encHex) < 2 {
		return fmt.Errorf("marshalled Bytes, %q, not valid", string(encHex))
	}
	if encHex[0] != '"' || encHex[len(encHex)-1] != '"' {
		return fmt.Errorf("marshalled Bytes, %q, not quoted", string(encHex))
	}
	// DecodeString overallocates by at least double, and it makes a copy.
	src := encHex[1 : len(encHex)-1]
	dst := make([]byte, len(src)/2)
	_, err = hex.Decode(dst, src)
	if err == nil {
		*b = dst
	}
	return err
}

type jsonTransactionSummary struct {
	Hash        Bytes                          `json:"hash"`
	Transaction Bytes                          `json:"transaction"`
	MyInputs    []jsonTransactionSummaryInput  `json:"myInputs"`
	MyOutputs   []jsonTransactionSummaryOutput `json:"myOutputs"`
	Fee         int64                          `json:"fee"`
	Timestamp   int64                          `json:"stamp"`
	Label       string                         `json:"label"`
	// Confs       int32                          `json:"confs"`
	// BlockHash   Bytes                          `json:"blockHash"`
}

type jsonTransactionSummaryInput struct {
	Index           uint32 `json:"index"`
	PreviousAccount uint32 `json:"previousAccount"`
	PreviousAmount  int64  `json:"previousAmount"`
}

type jsonTransactionSummaryOutput struct {
	Index    uint32 `json:"index"`
	Account  uint32 `json:"acct"`
	Internal bool   `json:"internal"`
}

type noteBlock struct {
	Hash         Bytes                    `json:"hash"`
	Height       int32                    `json:"height"`
	Timestamp    int64                    `json:"stamp"`
	Transactions []jsonTransactionSummary `json:"transactions"`
}

type noteBalance struct {
	Acct         uint32 `json:"acct"`
	TotalBalance int64  `json:"totalBalance"`
}

type jsonTransactionNotifications struct {
	AttachedBlocks      []noteBlock              `json:"attachedBlocks"`
	DetachedBlocks      []Bytes                  `json:"detachedBlocks"` // headers
	UnminedTransactions []jsonTransactionSummary `json:"unminedTransactions"`
	NewBalances         []noteBalance            `json:"newBalances"`
}

type accountNote struct {
	AccountNumber    uint32 `json:"accountNumber"`
	AccountName      string `json:"accountName"`
	ExternalKeyCount uint32 `json:"externalKeyCount"`
	InternalKeyCount uint32 `json:"internalKeyCount"`
	ImportedKeyCount uint32 `json:"importedKeyCount"`
}

type spentnessNote struct {
	Hash        Bytes  `json:"hash"`
	Vout        uint32 `json:"vout"`
	SpenderHash Bytes  `json:"spenderHash"`
	SpenderVin  uint32 `json:"spenderVin"`
}
