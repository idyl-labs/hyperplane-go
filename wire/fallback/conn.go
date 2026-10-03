// Copyright 2026 Idyl Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fallback

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Conn is one fallback/1 connection: a TLS 1.3 connection carrying
// multiplexed dock streams. Client and server use the same type; only the
// parity of the stream ids each side opens differs. A Conn is safe for
// concurrent use. A background goroutine reads frames until the
// connection closes.
type Conn struct {
	tc       net.Conn
	isClient bool
	idle     time.Duration

	ctx    context.Context
	cancel context.CancelCauseFunc

	writeMu sync.Mutex // one frame at a time; frames are atomic

	mu         sync.Mutex
	streams    map[uint32]*Stream
	nextSID    uint32 // next local stream id
	maxPeerSID uint32 // highest peer-opened id seen (monotonicity check)
	dead       bool

	acceptBidi chan *Stream
	acceptUni  chan *Stream
}

// Client wraps an established TLS connection, with its handshake
// complete, as the dialing side. idle bounds how long the peer may send
// no frame at all before the connection closes with IdleTimeoutError;
// any received frame resets it, and 0 disables the bound. The Conn owns
// tc and closes it when the connection closes.
func Client(tc net.Conn, idle time.Duration) *Conn { return newConn(tc, true, idle) }

// Server wraps an established TLS connection, with its handshake
// complete, as the accepting side. idle has the same meaning as for
// Client.
func Server(tc net.Conn, idle time.Duration) *Conn { return newConn(tc, false, idle) }

func newConn(tc net.Conn, isClient bool, idle time.Duration) *Conn {
	ctx, cancel := context.WithCancelCause(context.Background())
	c := &Conn{
		tc:         tc,
		isClient:   isClient,
		idle:       idle,
		ctx:        ctx,
		cancel:     cancel,
		streams:    map[uint32]*Stream{},
		acceptBidi: make(chan *Stream, acceptBacklog),
		acceptUni:  make(chan *Stream, acceptBacklog),
	}
	if isClient {
		c.nextSID = 1
	} else {
		c.nextSID = 2
	}
	go c.readLoop()
	return c
}

// Context is canceled when the connection closes. Its cause is the close
// reason: a *ConnError for a close by either side, IdleTimeoutError when
// the peer fell silent, or the underlying read or write error. Callers
// classify a closed connection the same way they classify a QUIC one.
func (c *Conn) Context() context.Context { return c.ctx }

// CloseWithError sends a CLOSE frame carrying a dock application code and
// reason, then closes the connection, as a QUIC application close does.
// The send is best effort and CloseWithError always returns nil.
func (c *Conn) CloseWithError(code uint64, reason string) error {
	payload := binary.BigEndian.AppendUint64(nil, code)
	payload = append(payload, reason...)
	_ = c.writeFrame(typeClose, 0, payload)
	c.fail(&ConnError{Code: code, Reason: reason})
	return nil
}

// SendKeepalive sends one PING frame, the counterpart of a QUIC
// keepalive datagram. No reply is expected; receipt alone resets the
// peer's idle clock.
func (c *Conn) SendKeepalive() error {
	return c.writeFrame(typePing, 0, nil)
}

// OpenStreamSync opens a bidirectional stream. As with QUIC, opening only
// announces the stream to the peer; it waits for no round trip. ctx is
// checked only before the stream is opened.
func (c *Conn) OpenStreamSync(ctx context.Context) (*Stream, error) {
	return c.open(typeOpenBidi, ctx)
}

// OpenUniStream opens a unidirectional stream that carries data from this
// side to the peer.
func (c *Conn) OpenUniStream() (*Stream, error) {
	return c.open(typeOpenUni, context.Background())
}

func (c *Conn) open(typ byte, ctx context.Context) (*Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %w", ErrConnClosed, context.Cause(c.ctx))
	}
	sid := c.nextSID
	c.nextSID += 2
	s := newStream(c, sid)
	if typ == typeOpenUni {
		s.recvFin = true // send-only on the opener
	}
	c.streams[sid] = s
	c.mu.Unlock()
	if err := c.writeFrame(typ, sid, nil); err != nil {
		return nil, err
	}
	return s, nil
}

// AcceptStream blocks until the peer opens a bidirectional stream, ctx is
// done, or the connection closes. At most 64 peer-opened streams wait
// for acceptance; the peer's further opens are reset.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	return c.accept(ctx, c.acceptBidi)
}

// AcceptUniStream blocks until the peer opens a unidirectional stream,
// ctx is done, or the connection closes. The same accept backlog applies
// as for AcceptStream.
func (c *Conn) AcceptUniStream(ctx context.Context) (*Stream, error) {
	return c.accept(ctx, c.acceptUni)
}

func (c *Conn) accept(ctx context.Context, ch chan *Stream) (*Stream, error) {
	select {
	case s := <-ch:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrConnClosed, context.Cause(c.ctx))
	}
}

// writeFrame writes one frame. Frames from concurrent writers never
// interleave.
func (c *Conn) writeFrame(typ byte, sid uint32, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return fmt.Errorf("%w: frame payload %d", ErrProtocol, len(payload))
	}
	buf := make([]byte, headerLen+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], sid)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(payload)))
	copy(buf[headerLen:], payload)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.ctx.Err() != nil {
		return fmt.Errorf("%w: %w", ErrConnClosed, context.Cause(c.ctx))
	}
	if _, err := c.tc.Write(buf); err != nil {
		c.fail(fmt.Errorf("fallback: write: %w", err))
		return fmt.Errorf("%w: %w", ErrConnClosed, err)
	}
	return nil
}

// fail closes the connection exactly once: it records cause on the
// connection context, terminates every stream, and closes the underlying
// connection.
func (c *Conn) fail(cause error) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	streams := make([]*Stream, 0, len(c.streams))
	for _, s := range c.streams {
		streams = append(streams, s)
	}
	c.streams = map[uint32]*Stream{}
	c.mu.Unlock()

	c.cancel(cause)
	for _, s := range streams {
		s.terminate(fmt.Errorf("%w: %w", ErrConnClosed, cause))
	}
	_ = c.tc.Close()
}

func (c *Conn) readLoop() {
	hdr := make([]byte, headerLen)
	for {
		if c.idle > 0 {
			_ = c.tc.SetReadDeadline(time.Now().Add(c.idle))
		}
		if _, err := io.ReadFull(c.tc, hdr); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				err = IdleTimeoutError{}
			}
			c.fail(err)
			return
		}
		typ := hdr[0]
		sid := binary.BigEndian.Uint32(hdr[1:5])
		n := binary.BigEndian.Uint32(hdr[5:9])
		if n > MaxFramePayload {
			c.fail(fmt.Errorf("%w: declared payload %d", ErrProtocol, n))
			return
		}
		var payload []byte
		if n > 0 {
			payload = make([]byte, n)
			if _, err := io.ReadFull(c.tc, payload); err != nil {
				c.fail(err)
				return
			}
		}
		if !c.handleFrame(typ, sid, payload) {
			return // handleFrame closed the connection
		}
	}
}

// handleFrame dispatches one frame and reports false when the frame
// closed the connection.
func (c *Conn) handleFrame(typ byte, sid uint32, payload []byte) bool {
	if sid == 0 {
		switch typ {
		case typeData, typeFin, typeReset, typeWindow:
			c.fail(fmt.Errorf("%w: stream frame type 0x%02x used connection stream id 0", ErrProtocol, typ))
			return false
		}
	}

	switch typ {
	case typeOpenBidi, typeOpenUni:
		return c.handleOpen(typ, sid)

	case typeData:
		if s := c.lookup(sid); s != nil {
			if err := s.deliver(payload); err != nil {
				c.fail(err)
				return false
			}
		}
		return true // unknown sid: data that crossed our RESET in flight; drop it

	case typeFin:
		if s := c.lookup(sid); s != nil {
			s.deliverFin()
			c.maybeGC(s)
		}
		return true

	case typeReset:
		if len(payload) != 8 {
			c.fail(fmt.Errorf("%w: reset payload", ErrProtocol))
			return false
		}
		if s := c.lookup(sid); s != nil {
			s.terminate(StreamResetError{Code: binary.BigEndian.Uint64(payload), Remote: true})
			c.remove(sid)
		}
		return true

	case typeWindow:
		if len(payload) != 4 {
			c.fail(fmt.Errorf("%w: window payload", ErrProtocol))
			return false
		}
		if s := c.lookup(sid); s != nil {
			s.addSendWindow(int(binary.BigEndian.Uint32(payload)))
		}
		return true

	case typePing:
		return true // the read-deadline reset in readLoop is the whole effect

	case typeClose:
		if len(payload) < 8 {
			c.fail(fmt.Errorf("%w: close payload", ErrProtocol))
			return false
		}
		c.fail(&ConnError{
			Code:   binary.BigEndian.Uint64(payload[:8]),
			Reason: string(payload[8:]),
			Remote: true,
		})
		return false

	default:
		c.fail(fmt.Errorf("%w: frame type 0x%02x", ErrProtocol, typ))
		return false
	}
}

func (c *Conn) handleOpen(typ byte, sid uint32) bool {
	peerOdd := !c.isClient // a server's peer opens odd ids
	if sid == 0 || (sid%2 == 1) != peerOdd {
		c.fail(fmt.Errorf("%w: peer opened stream %d with our parity", ErrProtocol, sid))
		return false
	}
	c.mu.Lock()
	if c.dead {
		// The connection failed after this frame was read. fail has
		// already terminated every registered stream, so a stream
		// registered now would never be terminated.
		c.mu.Unlock()
		return false
	}
	if sid <= c.maxPeerSID {
		c.mu.Unlock()
		c.fail(fmt.Errorf("%w: stream %d reopened", ErrProtocol, sid))
		return false
	}
	c.maxPeerSID = sid
	s := newStream(c, sid)
	if typ == typeOpenUni {
		s.sendFin = true // receive-only on the acceptor
	}
	c.streams[sid] = s
	c.mu.Unlock()

	ch := c.acceptBidi
	if typ == typeOpenUni {
		ch = c.acceptUni
	}
	select {
	case ch <- s:
	default:
		// Accept backlog full: shed the stream, not the connection.
		s.terminate(fmt.Errorf("%w: accept backlog full", ErrStreamReset))
		c.remove(sid)
		_ = c.writeFrame(typeReset, sid, binary.BigEndian.AppendUint64(nil, 0))
	}
	return true
}

func (c *Conn) lookup(sid uint32) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[sid]
}

func (c *Conn) remove(sid uint32) {
	c.mu.Lock()
	delete(c.streams, sid)
	c.mu.Unlock()
}

// maybeGC drops a stream whose both directions are done.
func (c *Conn) maybeGC(s *Stream) {
	s.mu.Lock()
	done := s.sendFin && s.recvFin && len(s.recvBuf) == 0
	s.mu.Unlock()
	if done {
		c.remove(s.id)
	}
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

// Stream is one multiplexed stream. Its methods mirror the subset of
// quic.Stream that the dock protocol uses, so one adapter can serve both
// transports. Read and Write may be called concurrently with each other
// and with the other methods.
type Stream struct {
	id uint32
	c  *Conn

	ctx    context.Context
	cancel context.CancelCauseFunc

	mu   sync.Mutex
	cond *sync.Cond

	recvBuf []byte
	recvFin bool
	recvWin int // receive credit remaining; data past it is a violation
	err     error

	sendFin bool
	sendWin int

	deadline      time.Time
	deadlineTimer *time.Timer
}

func newStream(c *Conn, id uint32) *Stream {
	ctx, cancel := context.WithCancelCause(context.Background())
	s := &Stream{
		id:      id,
		c:       c,
		ctx:     ctx,
		cancel:  cancel,
		recvWin: InitialWindow,
		sendWin: InitialWindow,
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Context is canceled when the stream is reset or its connection closes.
// An orderly FIN never cancels it.
func (s *Stream) Context() context.Context { return s.ctx }

// deliver appends received data, enforcing the credit window.
func (s *Stream) deliver(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil || s.recvFin {
		return nil // the stream is already finished or torn down on this side; drop
	}
	if len(p) > s.recvWin {
		return fmt.Errorf("%w: stream %d overran its window", ErrProtocol, s.id)
	}
	s.recvWin -= len(p)
	s.recvBuf = append(s.recvBuf, p...)
	s.cond.Broadcast()
	return nil
}

func (s *Stream) deliverFin() {
	s.mu.Lock()
	s.recvFin = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) addSendWindow(n int) {
	s.mu.Lock()
	s.sendWin += n
	s.cond.Broadcast()
	s.mu.Unlock()
}

// terminate ends the stream in both directions. The first error recorded
// is the one later operations return.
func (s *Stream) terminate(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	s.cancel(err)
}

// Read implements io.Reader with QUIC stream semantics: buffered data is
// returned first, then io.EOF after the peer's FIN, or the terminal error
// after a reset or connection close. A Read blocked past the read
// deadline returns os.ErrDeadlineExceeded.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	for {
		if len(s.recvBuf) > 0 {
			n := copy(p, s.recvBuf)
			s.recvBuf = s.recvBuf[n:]
			s.recvWin += n
			fin := s.recvFin
			buffered := len(s.recvBuf)
			s.mu.Unlock()
			// Replenish the peer's credit for what the consumer took.
			_ = s.c.writeFrame(typeWindow, s.id, binary.BigEndian.AppendUint32(nil, uint32(n)))
			if fin && buffered == 0 {
				s.c.maybeGC(s)
			}
			return n, nil
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return 0, err
		}
		if s.recvFin {
			s.mu.Unlock()
			return 0, io.EOF
		}
		if !s.deadline.IsZero() && !time.Now().Before(s.deadline) {
			s.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		s.cond.Wait()
	}
}

// Write implements io.Writer under the peer's credit window. It blocks at
// zero credit until the peer's consumer reads and grants more, so a slow
// reader applies backpressure instead of growing a buffer. It returns an
// error once the stream is reset, its connection closes, or Close has
// been called.
func (s *Stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		s.mu.Lock()
		for s.sendWin == 0 && s.err == nil && !s.sendFin {
			s.cond.Wait()
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return written, err
		}
		if s.sendFin {
			s.mu.Unlock()
			return written, fmt.Errorf("fallback: write after close on stream %d", s.id)
		}
		n := min(len(p), s.sendWin, MaxFramePayload)
		s.sendWin -= n
		s.mu.Unlock()

		if err := s.c.writeFrame(typeData, s.id, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Close half-closes the send side by sending FIN; reads continue to drain
// normally, matching QUIC stream Close. Closing twice, or closing a reset
// stream, returns nil.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.sendFin || s.err != nil {
		s.mu.Unlock()
		return nil
	}
	s.sendFin = true
	s.cond.Broadcast()
	s.mu.Unlock()
	err := s.c.writeFrame(typeFin, s.id, nil)
	s.c.maybeGC(s)
	return err
}

// CancelRead aborts the stream in both directions with the given code.
// fallback/1 has a single RESET frame where QUIC distinguishes the two
// directions; the dock protocol never cancels one direction while keeping
// the other.
func (s *Stream) CancelRead(code uint64) { s.reset(code) }

// CancelWrite aborts the stream in both directions with the given code,
// exactly as CancelRead does.
func (s *Stream) CancelWrite(code uint64) { s.reset(code) }

func (s *Stream) reset(code uint64) {
	s.mu.Lock()
	already := s.err != nil
	s.mu.Unlock()
	if already {
		return
	}
	s.terminate(StreamResetError{Code: code})
	s.c.remove(s.id)
	_ = s.c.writeFrame(typeReset, s.id, binary.BigEndian.AppendUint64(nil, code))
}

// SetReadDeadline bounds blocked Reads: past t, a Read with no data
// available returns os.ErrDeadlineExceeded. A zero t removes the bound.
// It always returns nil.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
	if s.deadlineTimer != nil {
		s.deadlineTimer.Stop()
		s.deadlineTimer = nil
	}
	if !t.IsZero() {
		d := max(time.Until(t), 0)
		s.deadlineTimer = time.AfterFunc(d, func() {
			s.mu.Lock()
			s.cond.Broadcast()
			s.mu.Unlock()
		})
	}
	return nil
}
