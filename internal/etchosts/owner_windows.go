//go:build windows

package etchosts

import "os"

// keepOwner does nothing on Windows: a file created by the same account in
// the same directory gets the same access control entries.
func keepOwner(*os.File, os.FileInfo) error { return nil }
