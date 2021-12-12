package app

import "gopkg.in/src-d/go-git.v4/plumbing"

type Result struct {
	Hash []byte
	Refs []*plumbing.Reference
}

func (r *Result) AddRef(ref *plumbing.Reference) {
	r.Refs = append(r.Refs, ref)
}
