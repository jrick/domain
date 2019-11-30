package main

import (
	"log"

	"golang.org/x/sys/unix"
)

func unveil(path string, flags string) {
	err := unix.Unveil(path, flags)
	if err != nil {
		log.Fatal(err)
	}
}

func unveilBlock() {
	err := unix.UnveilBlock()
	if err != nil {
		log.Fatal(err)
	}
}
