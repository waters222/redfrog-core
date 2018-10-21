package common

type LeakyBuffer struct {
	pool_       chan []byte
	bufferSize_ int
}

func NewLeakyBuffer(poolSize int, bufferSize int) (ret *LeakyBuffer) {
	ret = &LeakyBuffer{}
	ret.pool_ = make(chan []byte, poolSize)
	ret.bufferSize_ = bufferSize
	return
}

func (c *LeakyBuffer) GetBufferSize() int {
	return c.bufferSize_
}
func (c *LeakyBuffer) Get() []byte {
	select {
	case ret := <-c.pool_:
		return ret
	default:
		ret := make([]byte, c.bufferSize_)
		return ret
	}
}

func (c *LeakyBuffer) Put(buffer []byte) {
	if buffer != nil {
		capacity := cap(buffer)
		if capacity != c.bufferSize_ {
			buffer = make([]byte, c.bufferSize_)
		} else {
			// restore to full capacity
			buffer = buffer[:capacity]
		}
		select {
		case c.pool_ <- buffer:
		default:
		}
	}
}
