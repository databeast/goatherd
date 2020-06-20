package cmd

import (
	"log"
	"os"
)

var logger = log.New(os.Stdout, "goatherd: ", log.Lshortfile)
