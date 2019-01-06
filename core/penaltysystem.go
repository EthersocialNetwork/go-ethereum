// Copyright 2018 The go-ethereum Authors
// Copyright 2018 The Pirl Team <dev@pirl.io>
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

// Package core implements the Penalty System proposed by Pirl Team
package core

import (
	"errors"
	"sort"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/core/types"
)

var syncStatus bool

const (
	Author = "Original Author: The Pirl Team"
)

// CheckChainForAttack will check possible 51% attack.
// Copyright: 2018 Pirl Sprl
// Description: CheckChainForAttack penalize newily inserted blocks.
// The amount of penalty blocks assigned depends on the amount of blocks that the malicious miner mined in private.
func (bc *BlockChain) CheckChainForAttack(blocks types.Blocks) error {
	err := errors.New("")
	err = nil
	penalties := make(map[uint64]int64)
	tipOfTheMainChain := bc.CurrentBlock().NumberU64()

	if !syncStatus {
		syncStatus = bc.CurrentBlock().NumberU64() == blocks[0].NumberU64()-1
	}

	if syncStatus && len(blocks) > int(params.DelayedBlockLength) && bc.CurrentBlock().NumberU64() > uint64(params.PenaltySystemBlock) {
		for _, b := range blocks {
			penalties[b.NumberU64()] = penaltyForBlock(tipOfTheMainChain, b.NumberU64())
		}
	} else {
		return nil
	}

	p := make(PairList, len(penalties))
	i := 0
	for k, v := range penalties {
		p[i] = Pair{k, v}
		i++
	}
	sort.Sort(p)
	var penalty int64
	for _, v := range p {
		penalty += v.Value
	}

	multi := difficultyWeight(bc.CurrentBlock().Difficulty().Uint64())
	penalty = penalty * int64(multi)

	if penalty < 0 {
		penalty = 0
	}
	context := []interface{}{
		"synced", syncStatus, "number", tipOfTheMainChain, "incoming_number", blocks[0].NumberU64() - 1, "penalty", penalty, "implementation", Author,
	}

	log.Info("Checking the legitimity of the chain", context...)

	if penalty > 0 {
		context := []interface{}{
			"penalty", penalty,
		}
		log.Error("Malicious Chain! We should reject it", context...)
		err = ErrDelayTooHigh
	}

	if penalty == 0 {
		err = nil
	}

	return err
}

func penaltyForBlock(tipOfTheMainChain, incomingBlock uint64) int64 {
	if incomingBlock < tipOfTheMainChain {
		return int64(tipOfTheMainChain - incomingBlock)
	}
	if incomingBlock == tipOfTheMainChain {
		return 0
	}
	if incomingBlock > tipOfTheMainChain {
		return -1
	}
	return 0
}

func difficultyWeight(diff uint64) uint64 {
	if diff <= 500000000 {
		return 5
	}
	if diff >= 500000000 && diff < 20000000000 {
		return 4
	}
	if diff >= 20000000000 && diff < 30000000000 {
		return 3
	}
	if diff >= 30000000000 && diff < 50000000000 {
		return 2
	}
	return 1
}

// A data structure to hold key/value pairs
type Pair struct {
	Key   uint64
	Value int64
}

// A slice of pairs that implements sort.Interface to sort by values
type PairList []Pair

func (p PairList) Len() int           { return len(p) }
func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PairList) Less(i, j int) bool { return p[i].Key < p[j].Key }
