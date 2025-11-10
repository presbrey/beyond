package beyond

import (
	"log"

	"github.com/presbrey/pkg/wait"
)

func init() {
	// prepend file:lineno
	log.SetFlags(log.Flags() | log.Lshortfile)

	// wait for networking
	wait.ForNetwork()
}
