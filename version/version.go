package version

import (
	"fmt"
	"runtime"
	"strconv"
)

// Get 用于转换编译时的静态信息，如版本号等，同时为未设置变量参数设置默认值（对于直接访问变量则无法提供默认值）
func Get() Info {
	cut, err := strconv.ParseInt(CommitUnixTime, 10, 64)
	if err != nil {
		cut = 0
	}

	info := Info{
		Appname:        Appname,
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

	if info.GitCommit == "" {
		info.GitCommit = "1234567890123456789012345678901234567890"
	}
	if info.BuildDate == "" {
		info.BuildDate = "1970-01-01T00:00:00Z"
	}
	if info.GitBranch == "" {
		info.GitBranch = ""
	}
	if info.ReleaseVersion == "" {
		info.ReleaseVersion = "v0.0.0"
	}
	if info.CliVersion == "" {
		info.CliVersion = "v0.0.0"
	}

	return info
}
