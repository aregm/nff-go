//Package nbserver ...
// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Custom thread safe map for storing UE Session
//
package nbserver

import (
	"strconv"
	"sync"
)

//SessionMap structure
type SessionMap struct {
	Shards  int
	HashMap ConcurrentMap
}

//ConcurrentMap  map implemetation for uint32 key
//  based on fnva hashing with shards
type ConcurrentMap []*ConcurrentMapShared

//ConcurrentMapShared  A "thread" safe uint32 to anything map.
type ConcurrentMapShared struct {
	items map[uint32]Session
	sync.RWMutex
}

//New concurrent map.
func New(shards int) *SessionMap {
	m := &SessionMap{Shards: shards, HashMap: make(ConcurrentMap, shards)}
	for i := 0; i < shards; i++ {
		m.HashMap[i] = &ConcurrentMapShared{items: make(map[uint32]Session)}
	}
	return m
}

//GetShard rReturns shard under given key
func (m *SessionMap) GetShard(key uint32) *ConcurrentMapShared {
	//return m.HashMap[fnv32N(key)%uint32(m.Shards)]
	return m.HashMap[fnv32a(strconv.FormatUint(uint64(key), 10))%uint32(m.Shards)]
}

//Store sets the given value under the specified key.
func (m *SessionMap) Store(key uint32, value Session) {
	shard := m.GetShard(key)
	shard.Lock()
	shard.items[key] = value
	shard.Unlock()
}

//StoreIfAbsent sets the given value under the specified key if no value was associated with it.
func (m *SessionMap) StoreIfAbsent(key uint32, value Session) bool {
	shard := m.GetShard(key)
	shard.Lock()
	_, ok := shard.items[key]
	if !ok {
		shard.items[key] = value
	}
	shard.Unlock()
	return !ok
}

//Load retrieves an element from map under given key.
func (m *SessionMap) Load(key uint32) (Session, bool) {
	shard := m.GetShard(key)
	shard.RLock()
	val, ok := shard.items[key]
	shard.RUnlock()
	return val, ok
}

//Count returns the number of elements within the map.
func (m *SessionMap) Count() int {
	count := 0
	for i := 0; i < m.Shards; i++ {
		shard := m.HashMap[i]
		shard.RLock()
		count += len(shard.items)
		shard.RUnlock()
	}
	return count
}

//Has Check if an item exist under specified key
func (m *SessionMap) Has(key uint32) bool {
	shard := m.GetShard(key)
	shard.RLock()
	_, ok := shard.items[key]
	shard.RUnlock()
	return ok
}

//Delete deletes an element from the map.
func (m *SessionMap) Delete(key uint32) {
	// Try to get shard.
	shard := m.GetShard(key)
	shard.Lock()
	delete(shard.items, key)
	shard.Unlock()
}

//fnv32a implementation
func fnv32a(key string) uint32 {
	hash := uint32(2166136261)
	const prime32 = uint32(16777619)
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= prime32
	}
	return hash
}
