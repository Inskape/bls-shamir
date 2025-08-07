package global

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	once    sync.Once
	dataDir string
)

func DefaultDataDir() string {
	// TODO: figure out a better directory to use for mac/linux
	once.Do(func() {
		var dataDirEnvVar string
		switch runtime.GOOS {
		case "windows":
			// TODO: Get back to this to verify windows points to the right directory
			dataDirEnvVar = "%LOCALAPPDATA%"
		// case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "js", "linux", "netbsd", "openbsd", "plan9", "solaris":
		default:
			dataDirEnvVar = "$HOME"
		}

		if envDataDir, ok := os.LookupEnv(dataDirEnvVar); ok {
			dataDir = filepath.Join(envDataDir, fmt.Sprintf(".%s", Name), "data")
		} else {
			dataDir = filepath.Join(".", fmt.Sprintf(".%s", Name), "data")
		}
	})
	return dataDir
}
