package parser

import (
	"hash/fnv"
	"sync"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
)

type ExprCache struct {
	cache map[uint32]*vm.Program
	mu    sync.Mutex
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func NewExprCache() *ExprCache {
	return &ExprCache{
		cache: make(map[uint32]*vm.Program),
	}
}

// Get returns a compiled expression from the cache if it exists, otherwise it compiles it and adds it to the cache
func (c *ExprCache) Get(toParse string, opts []expr.Option) (*vm.Program, error) {
	var err error
	key := hash(toParse)
	c.mu.Lock()
	program, ok := c.cache[key]
	if !ok {
		c.mu.Unlock()
		program, err = expr.Compile(toParse, opts...)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.cache[key] = program
	}
	c.mu.Unlock()
	return program, err
}
