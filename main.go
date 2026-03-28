package main

import (
	"os"

	"github.com/inovacc/sentinel/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
