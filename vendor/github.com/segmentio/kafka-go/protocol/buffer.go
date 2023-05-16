package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
)

// Bytes is an interface implemented by types that represent immutable
// sequences of bytes.
//
// Bytes values are used to abstract the location where record keys and
// values are read from (e.g. in-memory buffers, network sockets, files).
//
// The Close method should be called to release resources held by the object
// when the program is done with it.
//
// Bytes values are generally not safe to use concurrently from multiple
// goroutines.
type Bytes interface {
	io.ReadCloser
	// Returns the number of bytes remaining to be read from the payload.
	Len() int
}

// NewBytes constructs a Bytes value from b.
//
// The returned value references b, it does not make a copy of the backing
// array.
//
// If b is nil, nil is returned to represent a null BYTES value in the kafka
// protocol.
func NewBytes(b []byte) Bytes {
	if b == nil {
		return nil
	}
	r := new(bytesReader)
	r.Reset(b)
	return r
}

// ReadAll is similar to ioutil.ReadAll, but it takes advantage of knowing the
// length of b to minimize the memory footprint.
//
// The function returns a nil slice if b is nil.
func ReadAll(b Bytes) ([]byte, error) {
	if b == nil {
		return nil, nil
	}
	s := make([]byte, b.Len())
	_, err := io.ReadFull(b, s)
	return s, err
}

type bytesReader struct{ bytes.Reader }

func (*bytesReader) Close() error { return nil }

type refCount uintptr

func (rc *refCount) ref() { atomic.AddUintptr((*uintptr)(rc), 1) }

func (rc *refCount) unref(onZero func()) {
	if atomic.AddUintptr((*uintptr)(rc), ^uintptr(0)) == 0 {
		onZero()
	}
}

const (
	// Size of the memory buffer for a single page. We use a farily
	// large size here (64 KiB) because batches exchanged with kafka
	// tend to be multiple kilobytes in size, sometimes hundreds.
	// Using large pages amortizes the overhead of the page metadata
	// and algorithms to manage the pages.
	pageSize = 65536
)

type page struct {
	refc   refCount
	offset int64
	length int
	buffer *[pageSize]byte
}

func newPage(offset int64) *page {
	p, _ := pagePool.Get().(*page)
	if p != nil {
		p.offset = offset
		p.length = 0
		p.ref()
	} else {
		p = &page{
			refc:   1,
			offset: offset,
			buffer: &[pageSize]byte{},
		}
	}
	return p
}

func (p *page) ref() { p.refc.ref() }

func (p *page) unref() { p.refc.unref(func() { pagePool.Put(p) }) }

func (p *page) slice(begin, end int64) []byte {
	i, j := begin-p.offset, end-p.offset

	if i < 0 {
		i = 0
	} else if i > pageSize {
		i = pageSize
	}

	if j < 0 {
		j = 0
	} else if j > pageSize {
		j = pageSize
	}

	if i < j {
		return p.buffer[i:j]
	}

	return nil
}

func (p *page) Cap() int { return pageSize }

func (p *page) Len() int { return p.length }

func (p *page) Size() int64 { return int64(p.length) }

func (p *page) Truncate(n int) {
	if n < p.length {
		p.length = n
	}
}

func (p *page) ReadAt(b []byte, off int64) (int, error) {
	if off -= p.offset; off < 0 || off > pageSize {
		panic("offset out of range")
	}
	if off > int64(p.length) {
		return 0, nil
	}
	return copy(b, p.buffer[off:p.length]), nil
}

func (p *page) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.ReadFull(r, p.buffer[p.length:])
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil
	}
	p.length += n
	return int64(n), err
}

func (p *page) WriteAt(b []byte, off int64) (int, error) {
	if off -= p.offset; off < 0 || off > pageSize {
		panic("offset out of range")
	}
	n := copy(p.buffer[off:], b)
	if end := int(off) + n; end > p.length {
		p.length = end
	}
	return n, nil
}

func (p *page) Write(b []byte) (int, error) {
	return p.WriteAt(b, p.offset+int64(p.length))
}

var (
	_ io.ReaderAt   = (*page)(nil)
	_ io.ReaderFrom = (*page)(nil)
	_ io.Writer     = (*page)(nil)
	_ io.WriterAt   = (*page)(nil)
)

type pageBuffer struct {
	refc   refCount
	pages  contiguousPages
	length int
	cursor int
}

func newPageBuffer() *pageBuffer {
	b, _ := pageBufferPool.Get().(*pageBuffer)
	if b != nil {
		b.cursor = 0
		b.refc.ref()
	} else {
		b = &pageBuffer{
			refc:  1,
			pages: make(contiguousPages, 0, 16),
		}
	}
	return b
}

func (pb *pageBuffer) refTo(ref *pageRef, begin, end int64) {
	length := end - begin

	if length > math.MaxUint32 {
		panic("reference to contiguous buffer pages exceeds the maximum size of 4 GB")
	}

	ref.pages = append(ref.buffer[:0], pb.pages.slice(begin, end)...)
	ref.pages.ref()
	ref.offset = begin
	ref.length = uint32(length)
}

func (pb *pageBuffer) ref(begin, end int64) *pageRef {
	ref := new(pageRef)
	pb.refTo(ref, begin, end)
	return ref
}

func (pb *pageBuffer) unref() {
	pb.refc.unref(func() {
		pb.pages.unref()
		pb.pages.clear()
		pb.pages = pb.pages[:0]
		pb.length = 0
		pageBufferPool.Put(pb)
	})
}

func (pb *pageBuffer) newPage() *page {
	return newPage(int64(pb.length))
}

func (pb *pageBuffer) Close() error {
	return nil
}

func (pb *pageBuffer) Len() int {
	return pb.length - pb.cursor
}

func (pb *pageBuffer) Size() int64 {
	return int64(pb.length)
}

func (pb *pageBuffer) Discard(n int) (int, error) {
	remain := pb.length - pb.cursor
	if remain < n {
		n = remain
	}
	pb.cursor += n
	return n, nil
}

func (pb *pageBuffer) Truncate(n int) {
	if n < pb.length {
		pb.length = n

		if n < pb.cursor {
			pb.cursor = n
		}

		for i := range pb.pages {
			if p := pb.pages[i]; p.length <= n {
				n -= p.length
			} else {
				if n > 0 {
					pb.pages[i].Truncate(n)
					i++
				}
				pb.pages[i:].unref()
				pb.pages[i:].clear()
				pb.pages = pb.pages[:i]
				break
			}
		}
	}
}

func (pb *pageBuffer) Seek(offset int64, whence int) (int64, error) {
	c, err := seek(int64(pb.cursor), int64(pb.length), offset, whence)
	if err != nil {
		return -1, err
	}
	pb.cursor = int(c)
	return c, nil
}

func (pb *pageBuffer) ReadByte() (byte, error) {
	b := [1]byte{}
	_, err := pb.Read(b[:])
	return b[0], err
}

func (pb *pageBuffer) Read(b []byte) (int, error) {
	if pb.cursor >= pb.length {
		return 0, io.EOF
	}
	n, err := pb.ReadAt(b, int64(pb.cursor))
	pb.cursor += n
	return n, err
}

func (pb *pageBuffer) ReadAt(b []byte, off int64) (int, error) {
	return pb.pages.ReadAt(b, off)
}

func (pb *pageBuffer) ReadFrom(r io.Reader) (int64, error) {
	if len(pb.pages) == 0 {
		pb.pages = append(pb.pages, pb.newPage())
	}

	rn := int64(0)

	for {
		tail := pb.pages[len(pb.pages)-1]
		free := tail.Cap() - tail.Len()

		if free == 0 {
			tail = pb.newPage()
			free = pageSize
			pb.pages = append(pb.pages, tail)
		}

		n, err := tail.ReadFrom(r)
		pb.length += int(n)
		rn += n
		if n < int64(free) {
			return rn, err
		}
	}
}

func (pb *pageBuffer) WriteString(s string) (int, error) {
	return pb.Write([]byte(s))
}

func (pb *pageBuffer) Write(b []byte) (int, error) {
	wn := len(b)
	if wn == 0 {
		return 0, nil
	}

	if len(pb.pages) == 0 {
		pb.pages = append(pb.pages, pb.newPage())
	}

	for len(b) != 0 {
		tail := pb.pages[len(pb.pages)-1]
		free := tail.Cap() - tail.Len()

		if len(b) <= free {
			tail.Write(b)
			pb.length += len(b)
			break
		}

		tail.Write(b[:free])
		b = b[free:]

		pb.length += free
		pb.pages = append(pb.pages, pb.newPage())
	}

	return wn, nil
}

func (pb *pageBuffer) WriteAt(b []byte, off int64) (int, error) {
	n, err := pb.pages.WriteAt(b, off)
	if err != nil {
		return n, err
	}
	if n < len(b) {
		pb.Write(b[n:])
	}
	return len(b), nil
}

func (pb *pageBuffer) WriteTo(w io.Writer) (int64, error) {
	var wn int
	var err error
	pb.pages.scan(int64(pb.cursor), int64(pb.length), func(b []byte) bool {
		var n int
		n, err = w.Write(b)
		wn += n
		return err == nil
	})
	pb.cursor += wn
	return int64(wn), err
}

var (
	_ io.ReaderAt     = (*pageBuffer)(nil)
	_ io.ReaderFrom   = (*pageBuffer)(nil)
	_ io.StringWriter = (*pageBuffer)(nil)
	_ io.Writer       = (*pageBuffer)(nil)
	_ io.WriterAt     = (*pageBuffer)(nil)
	_ io.WriterTo     = (*pageBuffer)(nil)

	pagePool       sync.Pool
	pageBufferPool sync.Pool
)

type contiguousPages []*page

func (pages contiguousPages) ref() {
	for _, p := range pages {
		p.ref()
	}
}

func (pages contiguousPages) unref() {
	for _, p := range pages {
		p.unref()
	}
}

func (pages contiguousPages) clear() {
	for i := range pages {
		pages[i] = nil
	}
}

func (pages contiguousPages) ReadAt(b []byte, off int64) (int, error) {
	rn := 0

	for _, p := range pages.slice(off, off+int64(len(b))) {
		n, _ := p.ReadAt(b, off)
		b = b[n:]
		rn += n
		off += int64(n)
	}

	return rn, nil
}

func (pages contiguousPages) WriteAt(b []byte, off int64) (int, error) {
	wn := 0

	for _, p := range pages.slice(off, off+int64(len(b))) {
		n, _ := p.WriteAt(b, off)
		b = b[n:]
		wn += n
		off += int64(n)
	}

	return wn, nil
}

func (pages contiguousPages) slice(begin, end int64) contiguousPages {
	i := pages.indexOf(begin)
	j := pages.indexOf(end)
	if j < len(pages) {
		j++
	}
	return pages[i:j]
}

func (pages contiguousPages) indexOf(offset int64) int {
	if len(pages) == 0 {
		return 0
	}
	return int((offset - pages[0].offset) / pageSize)
}

func (pages contiguousPages) scan(begin, end int64, f func([]byte) bool) {
	for _, p := range pages.slice(begin, end) {
		if !f(p.slice(begin, end)) {
			break
		}
	}
}

var (
	_ io.ReaderAt = contiguousPages{}
	_ io.WriterAt = contiguousPages{}
)

type pageRef struct {
	buffer [2]*page
	pages  contiguousPages
	offset int64
	cursor int64
	length uint32
	once   uint32
}

func (ref *pageRef) unref() {
	if atomic.CompareAndSwapUint32(&ref.once, 0, 1) {
		ref.pages.unref()
		ref.pages.clear()
		ref.pages = nil
		ref.offset = 0
		ref.cursor = 0
		ref.length = 0
	}
}

func (ref *pageRef) Len() int { return int(ref.Size() - ref.cursor) }

func (ref *pageRef) Size() int64 { return int64(ref.length) }

func (ref *pageRef) Close() error { ref.unref(); return nil }

func (ref *pageRef) String() string {
	return fmt.Sprintf("[offset=%d cursor=%d length=%d]", ref.offset, ref.cursor, ref.length)
}

func (ref *pageRef) Seek(offset int64, whence int) (int64, error) {
	c, err := seek(ref.cursor, int64(ref.length), offset, whence)
	if err != nil {
		return -1, err
	}
	ref.cursor = c
	return c, nil
}

func (ref *pageRef) ReadByte() (byte, error) {
	var c byte
	var ok bool
	ref.scan(ref.cursor, func(b []byte) bool {
		c, ok = b[0], true
		return false
	})
	if ok {
		ref.cursor++
	} else {
		return 0, io.EOF
	}
	return c, nil
}

func (ref *pageRef) Read(b []byte) (int, error) {
	if ref.cursor >= int64(ref.length) {
		return 0, io.EOF
	}
	n, err := ref.ReadAt(b, ref.cursor)
	ref.cursor += int64(n)
	return n, err
}

func (ref *pageRef) ReadAt(b []byte, off int64) (int, error) {
	limit := ref.offset + int64(ref.length)
	off += ref.offset

	if off >= limit {
		return 0, io.EOF
	}

	if off+int64(len(b)) > limit {
		b = b[:limit-off]
	}

	if len(b) == 0 {
		return 0, nil
	}

	n, err := ref.pages.ReadAt(b, off)
	if n == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}

func (ref *pageRef) WriteTo(w io.Writer) (wn int64, err error) {
	ref.scan(ref.cursor, func(b []byte) bool {
		var n int
		n, err = w.Write(b)
		wn += int64(n)
		return err == nil
	})
	ref.cursor += wn
	return
}

func (ref *pageRef) scan(off int64, f func([]byte) bool) {
	begin := ref.offset + off
	end := ref.offset + int64(ref.length)
	ref.pages.scan(begin, end, f)
}

var (
	_ io.Closer   = (*pageRef)(nil)
	_ io.Seeker   = (*pageRef)(nil)
	_ io.Reader   = (*pageRef)(nil)
	_ io.ReaderAt = (*pageRef)(nil)
	_ io.WriterTo = (*pageRef)(nil)
)

type pageRefAllocator struct {
	refs []pageRef
	head int
	size int
}

func (a *pageRefAllocator) newPageRef() *pageRef {
	if a.head == len(a.refs) {
		a.refs = make([]pageRef, a.size)
		a.head = 0
	}
	ref := &a.refs[a.head]
	a.head++
	return ref
}

func seek(cursor, limit, offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		// absolute offset
	case io.SeekCurrent:
		offset = cursor + offset
	case io.SeekEnd:
		offset = limit - offset
	default:
		return -1, fmt.Errorf("seek: invalid whence value: %d", whence)
	}
	if offset < 0 {
		offset = 0
	}
	if offset > limit {
		offset = limit
	}
	return offset, nil
}

func closeBytes(b Bytes) {
	if b != nil {
		b.Close()
	}
}
