package store

import (
	"encoding/binary"
	"fmt"
	"os"
)

// A truncated bbolt file crashes the process before anything can report why.
//
// bbolt memory-maps the database and trusts the page count in its meta page. If
// the file is shorter than that count implies — a partial copy, an interrupted
// write, a filesystem that ran out of space — the first freelist read
// dereferences unmapped memory and the process dies with:
//
//	unexpected fault address 0x...
//	fatal error: fault
//	[signal SIGSEGV: segmentation violation]
//
// That is a FAULT, not a panic: recover() cannot catch it, and no deferred
// handler runs. Every command dies the same way, including the diagnostics an
// operator would reach for — which is what makes it worth a pre-flight check
// rather than a graceful failure somewhere downstream.
//
// So the file is inspected before bbolt is allowed near it. This means knowing
// a little of bbolt's on-disk layout, which is a real cost; the alternative is
// a crash with no explanation at the exact moment someone is trying to
// understand what went wrong.

const (
	boltMagic       = 0xED0CDAED
	boltPageHeader  = 16 // Page: id uint64, flags uint16, count uint16, overflow uint32
	boltMetaMinSize = boltPageHeader + 56
)

// CheckBoltFile reports whether a bbolt database is structurally plausible.
//
// It is deliberately shallow: confirm the meta pages are meta pages, and that
// the file is at least as long as they say it is. Anything subtler is bbolt's
// business — the goal is only to turn an unrecoverable fault into a sentence.
func CheckBoltFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return nil // absent is fine; bbolt will create it
	}
	size := fi.Size()
	if size == 0 {
		return nil // freshly created, not yet written
	}

	f, err := os.Open(path)
	if err != nil {
		return nil // let bbolt produce the permission error
	}
	defer f.Close()

	// bbolt keeps two meta pages, at page 0 and page 1, and uses whichever has
	// the higher valid transaction id. One being damaged is survivable, which
	// is the whole point of there being two.
	var (
		anyValid bool
		needed   int64
		problems []string
	)
	for page := int64(0); page < 2; page++ {
		buf := make([]byte, boltMetaMinSize)
		off := page * 4096 // page 1's true offset needs pageSize, resolved below
		if page == 1 {
			if ps := readPageSize(f); ps > 0 {
				off = int64(ps)
			}
		}
		if _, err := f.ReadAt(buf, off); err != nil {
			problems = append(problems, fmt.Sprintf("meta page %d is unreadable", page))
			continue
		}
		m := buf[boltPageHeader:]
		if binary.LittleEndian.Uint32(m[0:4]) != boltMagic {
			problems = append(problems, fmt.Sprintf("meta page %d has no bbolt magic", page))
			continue
		}
		// bbolt's Meta, after the 16-byte page header:
		//   0  magic uint32      16 root.root    pgid
		//   4  version uint32    24 root.seq     uint64
		//   8  pageSize uint32   32 freelist     pgid
		//  12  flags uint32      40 pgid         (high-water)
		//                        48 txid         uint64
		//                        56 checksum     uint64
		pageSize := int64(binary.LittleEndian.Uint32(m[8:12]))
		freelist := int64(binary.LittleEndian.Uint64(m[32:40]))
		highWater := int64(binary.LittleEndian.Uint64(m[40:48]))
		if pageSize <= 0 || highWater <= 0 {
			problems = append(problems, fmt.Sprintf("meta page %d is self-inconsistent", page))
			continue
		}
		anyValid = true
		// The high-water mark is the next page to ALLOCATE, so the file must
		// hold pages [0, highWater). The freelist page must also be inside it —
		// reading that page past the end of the mapping is the exact fault this
		// check exists to prevent.
		want := highWater * pageSize
		if freelist > 0 && freelist < highWater {
			if fl := (freelist + 1) * pageSize; fl > want {
				want = fl
			}
		}
		if want > needed {
			needed = want
		}
	}

	if !anyValid {
		return fmt.Errorf(
			"store: %s does not look like a bbolt database (%v). It is corrupt or is not the file "+
				"it is supposed to be; restore it from a backup rather than starting on it",
			path, problems)
	}
	if size < needed {
		return fmt.Errorf(
			"store: %s is truncated — it is %d bytes and its own header says it should be at least "+
				"%d. Opening it would fault inside the memory-mapped read, killing this process and "+
				"every other command against this directory, with no diagnosis. Restore it from a "+
				"backup", path, size, needed)
	}
	return nil
}

func readPageSize(f *os.File) uint32 {
	buf := make([]byte, boltMetaMinSize)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return 0
	}
	m := buf[boltPageHeader:]
	if binary.LittleEndian.Uint32(m[0:4]) != boltMagic {
		return 0
	}
	return binary.LittleEndian.Uint32(m[8:12])
}
