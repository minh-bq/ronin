// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package state

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// journalEntry is a modification entry in the state change journal that can be
// reverted on demand.
type journalEntry interface {
	// revert undoes the changes introduced by this journal entry.
	revert(*StateDB)

	// dirtied returns the Ethereum address modified by this journal entry.
	dirtied() *common.Address

	// getStored return the journal part that is stored on disk in optimized archive mode
	getStore() storedJournal
}

// storedJournal is the stored journal entry to re-apply when trying to re-generate
// state in optimized archive node
type storedJournal interface {
	apply(*StateDB)
}

// journal contains the list of state modifications applied since the last state
// commit. These are tracked to be able to be reverted in the case of an execution
// exception or request for reversal.
type journal struct {
	entries []journalEntry         // Current changes tracked by the journal
	dirties map[common.Address]int // Dirty accounts and the number of changes
}

// newJournal creates a new initialized journal.
func newJournal() *journal {
	return &journal{
		dirties: make(map[common.Address]int),
	}
}

// append inserts a new modification entry to the end of the change journal.
func (j *journal) append(entry journalEntry) {
	j.entries = append(j.entries, entry)
	if addr := entry.dirtied(); addr != nil {
		j.dirties[*addr]++
	}
}

// revert undoes a batch of journalled modifications along with any reverted
// dirty handling too.
func (j *journal) revert(statedb *StateDB, snapshot int) {
	for i := len(j.entries) - 1; i >= snapshot; i-- {
		// Undo the changes made by the operation
		j.entries[i].revert(statedb)

		// Drop any dirty tracking induced by the change
		if addr := j.entries[i].dirtied(); addr != nil {
			if j.dirties[*addr]--; j.dirties[*addr] == 0 {
				delete(j.dirties, *addr)
			}
		}
	}
	j.entries = j.entries[:snapshot]
}

// dirty explicitly sets an address to dirty, even if the change entries would
// otherwise suggest it as clean. This method is an ugly hack to handle the RIPEMD
// precompile consensus exception.
func (j *journal) dirty(addr common.Address) {
	j.dirties[addr]++
}

// length returns the current number of entries in the journal.
func (j *journal) length() int {
	return len(j.entries)
}

type (
	// Changes to the account trie.
	createObjectChangeStore struct {
		Account *common.Address
	}
	createObjectChange struct {
		store *createObjectChangeStore
	}
	resetObjectChange struct {
		prev         *stateObject
		prevdestruct bool
	}
	suicideChangeStore struct {
		Account *common.Address
	}
	suicideChange struct {
		store       *suicideChangeStore
		prev        bool // whether account had already suicided
		prevbalance *big.Int
	}

	// Changes to individual accounts.
	balanceChangeStore struct {
		Account *common.Address
		Current *big.Int
	}
	balanceChange struct {
		store *balanceChangeStore
		prev  *big.Int
	}
	nonceChangeStore struct {
		Account *common.Address
		Current uint64
	}
	nonceChange struct {
		store *nonceChangeStore
		prev  uint64
	}
	storageChangeStore struct {
		Account      *common.Address
		Key          common.Hash
		CurrentValue common.Hash
	}
	storageChange struct {
		store    *storageChangeStore
		prevalue common.Hash
	}
	codeChangeStore struct {
		Account                  *common.Address
		CurrentCode, CurrentHash []byte
	}
	codeChange struct {
		store              *codeChangeStore
		prevcode, prevhash []byte
	}

	// Changes to other state values.
	refundChange struct {
		prev uint64
	}
	addLogChange struct {
		txhash common.Hash
	}
	addPreimageChange struct {
		hash common.Hash
	}
	touchChangeStore struct {
		Account *common.Address
	}
	touchChange struct {
		store *touchChangeStore
	}
	// Changes to the access list
	accessListAddAccountChange struct {
		address *common.Address
	}
	accessListAddSlotChange struct {
		address *common.Address
		slot    *common.Hash
	}
)

const (
	createObjectChangeStoreType uint8 = iota
	touchChangeStoreType
	suicideChangeStoreType
	balanceChangeStoreType
	nonceChangeStoreType
	codeChangeStoreType
	storageChangeStoreType
)

func (ch createObjectChange) revert(s *StateDB) {
	delete(s.stateObjects, *ch.store.Account)
	delete(s.stateObjectsDirty, *ch.store.Account)
}

func (ch createObjectChange) dirtied() *common.Address {
	return ch.store.Account
}

func (ch createObjectChange) getStore() storedJournal {
	return ch.store
}

func (chStore createObjectChangeStore) apply(s *StateDB) {
	s.setStateObject(newObject(s, *chStore.Account, types.StateAccount{}))
	s.journal.dirty(*chStore.Account)
}

func (chStore createObjectChangeStore) String() string {
	return fmt.Sprintf("CreateObjectChange{Account: %s}", chStore.Account)
}

func (ch resetObjectChange) revert(s *StateDB) {
	s.setStateObject(ch.prev)
	if !ch.prevdestruct && s.snap != nil {
		delete(s.snapDestructs, ch.prev.addrHash)
	}
}

func (ch resetObjectChange) dirtied() *common.Address {
	return nil
}

func (ch resetObjectChange) getStore() storedJournal {
	return nil
}

func (ch suicideChange) revert(s *StateDB) {
	obj := s.getStateObject(*ch.store.Account)
	if obj != nil {
		obj.suicided = ch.prev
		obj.setBalance(ch.prevbalance)
	}
}

func (ch suicideChange) dirtied() *common.Address {
	return ch.store.Account
}

func (ch suicideChange) getStore() storedJournal {
	return ch.store
}

func (chStore suicideChangeStore) apply(s *StateDB) {
	stateObject := s.getStateObject(*chStore.Account)

	// This does not normally happen in the main execution
	// but can happen when pre-apply the journal. In this
	// case, just return early
	if stateObject == nil {
		return
	}
	stateObject.markSuicided()
	stateObject.data.Balance = new(big.Int)
	s.journal.dirty(*chStore.Account)
}

func (chStore suicideChangeStore) String() string {
	return fmt.Sprintf("SuicideChange{Account: %s}", chStore.Account)
}

var ripemd = common.HexToAddress("0000000000000000000000000000000000000003")

func (ch touchChange) revert(s *StateDB) {
	// The touch to ripemd persists statedb.journal.dirties even though journal is reverted.
	// This is a special rule to address consensus issue on Ethereum, more detail at
	// https://github.com/ethereum/EIPs/issues/716#issuecomment-330824096
	//
	// So in optimized archive mode, we need to have ripemd touch change dumped to disk
	// when the entry is reverted. Since the order of touch change is not important we simply
	// append to s.storedEntries
	if s.OptimizedMode {
		if *ch.store.Account == ripemd {
			s.blockJournal = append(
				s.blockJournal,
				touchChange{store: &touchChangeStore{Account: &ripemd}},
			)
		}
	}
}

func (ch touchChange) dirtied() *common.Address {
	return ch.store.Account
}
func (ch touchChange) getStore() storedJournal {
	return ch.store
}
func (chStore touchChangeStore) apply(s *StateDB) {
	// Fill the live state objects set
	s.getStateObject(*chStore.Account)
	s.journal.dirty(*chStore.Account)
}
func (chStore touchChangeStore) String() string {
	return fmt.Sprintf("TouchChange{Account: %s}", chStore.Account)
}

func (ch balanceChange) revert(s *StateDB) {
	s.getStateObject(*ch.store.Account).setBalance(ch.prev)
}

func (ch balanceChange) dirtied() *common.Address {
	return ch.store.Account
}

func (ch balanceChange) getStore() storedJournal {
	return ch.store
}

func (chStore balanceChangeStore) apply(s *StateDB) {
	stateObject := s.getStateObject(*chStore.Account)
	if stateObject == nil {
		return
	}
	stateObject.setBalance(chStore.Current)
	s.journal.dirty(*chStore.Account)
}

func (chStore balanceChangeStore) String() string {
	return fmt.Sprintf("BalanceChange{Account: %s, Current: %d}", chStore.Account, chStore.Current)
}

func (ch nonceChange) revert(s *StateDB) {
	s.getStateObject(*ch.store.Account).setNonce(ch.prev)
}

func (ch nonceChange) dirtied() *common.Address {
	return ch.store.Account
}

func (ch nonceChange) getStore() storedJournal {
	return ch.store
}

func (chStore nonceChangeStore) apply(s *StateDB) {
	stateObject := s.getStateObject(*chStore.Account)
	if stateObject == nil {
		return
	}
	stateObject.setNonce(chStore.Current)
	s.journal.dirty(*chStore.Account)
}

func (chStore nonceChangeStore) String() string {
	return fmt.Sprintf("NonceChange{Account: %s, Current: %d}", chStore.Account, chStore.Current)
}

func (ch codeChange) revert(s *StateDB) {
	s.getStateObject(*ch.store.Account).setCode(common.BytesToHash(ch.prevhash), ch.prevcode)
}

func (ch codeChange) dirtied() *common.Address {
	return ch.store.Account
}

func (ch codeChange) getStore() storedJournal {
	return ch.store
}

func (chStore codeChangeStore) apply(s *StateDB) {
	stateObject := s.getStateObject(*chStore.Account)
	if stateObject == nil {
		return
	}
	stateObject.setCode(common.BytesToHash(chStore.CurrentHash), chStore.CurrentCode)
	s.journal.dirty(*chStore.Account)
}

func (chStore codeChangeStore) String() string {
	return fmt.Sprintf(
		"CodeChange{Account: %s, CurrentCode: %s, CurrentHash: %s}",
		chStore.Account,
		common.Bytes2Hex(chStore.CurrentCode),
		common.Bytes2Hex(chStore.CurrentHash),
	)
}

func (ch storageChange) revert(s *StateDB) {
	s.getStateObject(*ch.store.Account).setState(ch.store.Key, ch.prevalue)
}

func (ch storageChange) dirtied() *common.Address {
	return ch.store.Account
}

func (ch storageChange) getStore() storedJournal {
	return ch.store
}

func (chStore storageChangeStore) apply(s *StateDB) {
	stateObject := s.getStateObject(*chStore.Account)
	if stateObject == nil {
		return
	}

	// In updateTrie, when writing the changed value to storage trie,
	// there is a check to see whether the new value is different from
	// stateObject.originStorage[key]. We need to call to GetState to
	// initialize the stateObject.originStorage[key]
	stateObject.GetState(s.db, chStore.Key)
	s.getStateObject(*chStore.Account).setState(chStore.Key, chStore.CurrentValue)
	s.journal.dirty(*chStore.Account)
}

func (chStore storageChangeStore) String() string {
	return fmt.Sprintf(
		"StorageChange{Account: %s, Key: %s, CurrentValue: %s}",
		chStore.Account,
		chStore.Key.Hex(),
		chStore.CurrentValue.Hex(),
	)
}

func (ch refundChange) revert(s *StateDB) {
	s.refund = ch.prev
}

func (ch refundChange) dirtied() *common.Address {
	return nil
}

func (ch refundChange) getStore() storedJournal {
	return nil
}

func (ch addLogChange) revert(s *StateDB) {
	logs := s.logs[ch.txhash]
	if len(logs) == 1 {
		delete(s.logs, ch.txhash)
	} else {
		s.logs[ch.txhash] = logs[:len(logs)-1]
	}
	s.logSize--
}

func (ch addLogChange) dirtied() *common.Address {
	return nil
}

func (ch addLogChange) getStore() storedJournal {
	return nil
}

func (ch addPreimageChange) revert(s *StateDB) {
	delete(s.preimages, ch.hash)
}

func (ch addPreimageChange) dirtied() *common.Address {
	return nil
}

func (ch addPreimageChange) getStore() storedJournal {
	return nil
}

func (ch accessListAddAccountChange) revert(s *StateDB) {
	/*
		One important invariant here, is that whenever a (addr, slot) is added, if the
		addr is not already present, the add causes two journal entries:
		- one for the address,
		- one for the (address,slot)
		Therefore, when unrolling the change, we can always blindly delete the
		(addr) at this point, since no storage adds can remain when come upon
		a single (addr) change.
	*/
	s.accessList.DeleteAddress(*ch.address)
}

func (ch accessListAddAccountChange) dirtied() *common.Address {
	return nil
}

func (ch accessListAddAccountChange) getStore() storedJournal {
	return nil
}

func (ch accessListAddSlotChange) revert(s *StateDB) {
	s.accessList.DeleteSlot(*ch.address, *ch.slot)
}

func (ch accessListAddSlotChange) dirtied() *common.Address {
	return nil
}

func (ch accessListAddSlotChange) getStore() storedJournal {
	return nil
}

func DecodeJournal(rawJournal []byte) []storedJournal {
	var journal []storedJournal

	reader := bytes.NewReader(rawJournal)
	for reader.Len() > 0 {
		var entryType uint8
		err := rlp.Decode(reader, &entryType)
		if err != nil {
			log.Error("Failed to decode journal type", "err", err)
			return nil
		}

		switch entryType {
		case createObjectChangeStoreType:
			var entry createObjectChangeStore
			err := rlp.Decode(reader, &entry)
			if err != nil {
				log.Error("Failed to decode create object journal entry", "err", err)
				return nil
			}
			journal = append(journal, entry)
		case touchChangeStoreType:
			var entry touchChangeStore
			err := rlp.Decode(reader, &entry)
			if err != nil {
				log.Error("Failed to decode touch change journal entry", "err", err)
				return nil
			}
			journal = append(journal, entry)
		case suicideChangeStoreType:
			var entry suicideChangeStore
			err := rlp.Decode(reader, &entry)
			if err != nil {
				log.Error("Failed to decode suicide journal entry", "err", err)
				return nil
			}
			journal = append(journal, entry)
		case balanceChangeStoreType:
			var entry balanceChangeStore
			err := rlp.Decode(reader, &entry)
			if err != nil {
				log.Error("Failed to decode balance change journal entry", "err", err)
				return nil
			}
			journal = append(journal, entry)
		case nonceChangeStoreType:
			var entry nonceChangeStore
			err := rlp.Decode(reader, &entry)
			if err != nil {
				log.Error("Failed to decode nonce change journal entry", "err", err)
				return nil
			}
			journal = append(journal, entry)
		case codeChangeStoreType:
			var entry codeChangeStore
			err := rlp.Decode(reader, &entry)
			if err != nil {
				log.Error("Failed to decode code change journal entry", "err", err)
				return nil
			}
			journal = append(journal, entry)
		case storageChangeStoreType:
			var entry storageChangeStore
			err := rlp.Decode(reader, &entry)
			if err != nil {
				log.Error("Failed to decode storage change journal entry", "err", err)
				return nil
			}
			journal = append(journal, entry)
		default:
			log.Error("Unknown journal entry type", "type", entryType)
			return nil
		}
	}

	return journal
}
