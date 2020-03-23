package version

import (
	"fmt"
	"runtime"
	"strconv"
)

// Get 用于转换编译时的静态信息，如版本号等
func Get() Info {
	cut, err := strconv.ParseInt(CommitUnixTime, 10, 64)
	if err != nil {
		cut = 0
	}

	return Info{
		GitCommit:      GitCommit,
		BuildDate:      BuildDate,
		CommitUnixTime: cut,
		GitBranch:      GitBranch,
		ReleaseVersion: ReleaseVersion,
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
		Platform:       fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		CliVersion:     CliVersion,
	}
}
