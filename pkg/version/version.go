package version

import (
	"fmt"
)

/*

Given a version number MAJOR.MINOR.PATCH, increment the:

	MAJOR version when you make incompatible API changes,
	MINOR version when you add functionality in a backwards compatible manner, and
	PATCH version when you make backwards compatible bug fixes.

Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format.

*/

var (
	Version   string // = "v0.0.0"
	BuildDate string // = "I don't remember exactly"
	Tag       string // = "dev"
	GoVersion string // = "1.13"
)

func VersionStr() string {
	return fmt.Sprintf("%s-%s", Version, Tag)
}
