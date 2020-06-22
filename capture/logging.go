package capture

import (
	"log"
	"os"
)

var logger = log.New(os.Stdout, "capture: ", log.Lshortfile)
