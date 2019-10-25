package shellicator

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/pkg/browser"
)

func openURL(url string) {
	switch oss := runtime.GOOS; oss {
	case "linux":
		// Didn't find another way to suppress error message from xdg-open.
		// Replace the stdout and stderr for the browser pkg doesn't work,
		// because firefox won't show the page and blocks until it is closed.
		exec.Command("sh", "-c", fmt.Sprintf("xdg-open '%v' 2>/dev/null", url)).Run()
	default:
		browser.OpenURL(url)
	}
}
