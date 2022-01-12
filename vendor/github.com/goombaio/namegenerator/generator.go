// Copyright 2018, Goomba project Authors. All rights reserved.
//
// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with this
// work for additional information regarding copyright ownership.  The ASF
// licenses this file to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations
// under the License.

package namegenerator

import (
	"fmt"
	"math/rand"
)

// Generator ...
type Generator interface {
	Generate() string
}

// NameGenerator ...
type NameGenerator struct {
	random *rand.Rand
}

// Generate ...
func (rn *NameGenerator) Generate() string {
	randomAdjective := ADJECTIVES[rn.random.Intn(len(ADJECTIVES))]
	randomNoun := NOUNS[rn.random.Intn(len(NOUNS))]

	randomName := fmt.Sprintf("%v-%v", randomAdjective, randomNoun)

	return randomName
}

// NewNameGenerator ...
func NewNameGenerator(seed int64) Generator {
	nameGenerator := &NameGenerator{
		random: rand.New(rand.New(rand.NewSource(99))),
	}
	nameGenerator.random.Seed(seed)

	return nameGenerator
}
