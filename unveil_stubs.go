//+build !openbsd

package main

func unveil(path string, flags string) {}
func unveilBlock()                     {}
