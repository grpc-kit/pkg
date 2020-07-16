package version

import (
	"encoding/json"
)

var (
	// AppName 应用程序的名称
	Appname string
	// GitCommit 最后一次git提交的hash值，计算方式：git rev-parse HEAD
	GitCommit string
	// BuildDate 编译二进制时的时间，RFC3339规范，计算方式：date -u +'%Y-%m-%dT%H:%M:%SZ'
	BuildDate string
	// GitBranch 编译是所在的git分支，计算方式：git rev-parse --abbrev-ref HEAD
	GitBranch string
	// CliVersion 生成该服务模版所使用的 github.com/grpc-kit/cli 版本
	CliVersion string
	// CommitUnixTime 最后一次git提交的UNIX时间，计算方式：git --no-pager log -1 --format='%ct'
	CommitUnixTime string
	// ReleaseVersion 服务正式发布对外的版本，计算方式：git describe --tags --dirty --always
	ReleaseVersion string
)

// Info 用于记录版本相关信息结构
type Info struct {
	Appname        string `json:"appname" yaml:"appname"`
	BuildDate      string `json:"build_date" yaml:"build_date"`
	GitCommit      string `json:"git_commit" yaml:"git_commit"`
	GitBranch      string `json:"git_branch" yaml:"git_branch"`
	GoVersion      string `json:"go_version" yaml:"go_version"`
	Compiler       string `json:"compiler" yaml:"compiler"`
	Platform       string `json:"platform" yaml:"platform"`
	CliVersion     string `json:"cli_version" yaml:"cli_version"`
	CommitUnixTime int64  `json:"commit_unix_time" yaml:"commit_unix_time"`
	ReleaseVersion string `json:"release_version" yaml:"release_version"`
}

// String 用于统一标准化格式输出
func (info Info) String() string {
	rawBody, err := json.Marshal(&info)
	if err != nil {
		tmp := Info{
			BuildDate:      "1970-01-01T00:00:00Z",
			CommitUnixTime: 0,
			ReleaseVersion: "v0.0.0",
		}
		rawBody, _ = json.Marshal(tmp)
		return string(rawBody)
	}

	return string(rawBody)
}
