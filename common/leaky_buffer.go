package common

import "bytes"

type LeakyBuffer struct {
	pool_       chan *bytes.Buffer
	bufferSize_ int
}

func NewLeakyBuffer(poolSize int, bufferSize int) (ret *LeakyBuffer) {
	ret = &LeakyBuffer{}
	ret.pool_ = make(chan *bytes.Buffer, poolSize)
	ret.bufferSize_ = bufferSize
	return
}

func (c *LeakyBuffer) GetBufferSize() int {
	return c.bufferSize_
}
func (c *LeakyBuffer) Get() *bytes.Buffer {
	select {
	case ret := <-c.pool_:
		return ret
	default:
		ret := bytes.NewBuffer(make([]byte, c.bufferSize_))
		return ret
	}
}

func (c *LeakyBuffer) Put(buffer *bytes.Buffer) {
	if buffer.Cap() > c.bufferSize_ {
		buffer = bytes.NewBuffer(make([]byte, c.bufferSize_))
	}
	select {
	case c.pool_ <- buffer:
	default:
	}

}
