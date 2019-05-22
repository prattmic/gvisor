// Copyright 2018 The gVisor Authors.
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

package pipe

import (
	"io"
	"math"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ReaderWriter satisfies the FileOperations interface and services both
// read and write requests. This should only be used directly for named pipes.
// pipe(2) and pipe2(2) only support unidirectional pipes and should use
// either pipe.Reader or pipe.Writer.
//
// +stateify savable
type ReaderWriter struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	*Pipe
}

// Release implements fs.FileOperations.Release.
func (rw *ReaderWriter) Release() {
	rw.Pipe.rClose()
	rw.Pipe.wClose()

	// Wake up readers and writers.
	rw.Pipe.Notify(waiter.EventIn | waiter.EventOut)
}

// Read implements fs.FileOperations.Read.
func (rw *ReaderWriter) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	n, err := rw.Pipe.read(ctx, readOps{
		left: func() int64 {
			return dst.NumBytes()
		},
		limit: func(l int64) {
			dst = dst.TakeFirst64(l)
		},
		read: func(buf *buffer) (int64, error) {
			n, err := dst.CopyOutFrom(ctx, buf)
			dst = dst.DropFirst64(n)
			return n, err
		},
	})
	if n > 0 {
		rw.Pipe.Notify(waiter.EventOut)
	}
	return n, err
}

// WriteTo implements fs.FileOperations.WriteTo.
func (rw *ReaderWriter) WriteTo(ctx context.Context, _ *fs.File, w io.Writer, count int64, dup bool) (int64, error) {
	ops := readOps{
		left: func() int64 {
			return count
		},
		limit: func(l int64) {
			count = l
		},
		read: func(buf *buffer) (int64, error) {
			n, err := buf.ReadToWriter(w, count, dup)
			count -= n
			return n, err
		},
	}
	if dup {
		// There is no notification for dup operations.
		return rw.Pipe.dup(ctx, ops)
	}
	n, err := rw.Pipe.read(ctx, ops)
	if n > 0 {
		rw.Pipe.Notify(waiter.EventOut)
	}
	return n, err
}

// Write implements fs.FileOperations.Write.
func (rw *ReaderWriter) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	n, err := rw.Pipe.write(ctx, writeOps{
		left: func() int64 {
			return src.NumBytes()
		},
		limit: func(l int64) {
			src = src.TakeFirst64(l)
		},
		write: func(buf *buffer) (int64, error) {
			n, err := src.CopyInTo(ctx, buf)
			src = src.DropFirst64(n)
			return n, err
		},
	})
	if n > 0 {
		rw.Pipe.Notify(waiter.EventIn)
	}
	return n, err
}

// ReadFrom implements fs.FileOperations.WriteTo.
func (rw *ReaderWriter) ReadFrom(ctx context.Context, _ *fs.File, r io.Reader, count int64) (int64, error) {
	n, err := rw.Pipe.write(ctx, writeOps{
		left: func() int64 {
			return count
		},
		limit: func(l int64) {
			count = l
		},
		write: func(buf *buffer) (int64, error) {
			n, err := buf.WriteFromReader(r, count)
			count -= n
			return n, err
		},
	})
	if n > 0 {
		rw.Pipe.Notify(waiter.EventIn)
	}
	return n, err
}

// Readiness returns the ready events in the underlying pipe.
func (rw *ReaderWriter) Readiness(mask waiter.EventMask) waiter.EventMask {
	return rw.Pipe.rwReadiness() & mask
}

// Ioctl implements fs.FileOperations.Ioctl.
func (rw *ReaderWriter) Ioctl(ctx context.Context, _ *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	// Switch on ioctl request.
	switch int(args[1].Int()) {
	case linux.FIONREAD:
		v := rw.queued()
		if v > math.MaxInt32 {
			v = math.MaxInt32 // Silently truncate.
		}
		// Copy result to user-space.
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), int32(v), usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	default:
		return 0, syscall.ENOTTY
	}
}
