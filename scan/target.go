package scan

import "github.com/snyk/code-client-go/internal/util"

type RepositoryTarget struct {
	LocalFilePath string
	repositoryUrl string
}

type Target interface {
	GetPath() string
}

func (r RepositoryTarget) GetPath() string {
	return r.LocalFilePath
}

func (r RepositoryTarget) GetRepositoryUrl() string {
	return r.repositoryUrl
}

type TargetOptions func(*RepositoryTarget) error

func WithRepositoryUrl(repositoryUrl string) TargetOptions {
	return func(target *RepositoryTarget) error {
		var err error
		target.repositoryUrl, err = util.SanitiseCredentials(repositoryUrl)
		return err
	}
}

func NewRepositoryTarget(path string, options ...TargetOptions) (Target, error) {
	result := &RepositoryTarget{
		LocalFilePath: path,
	}

	for _, option := range options {
		option(result)
	}

	if len(result.repositoryUrl) == 0 {
		var err error
		result.repositoryUrl, err = util.GetRepositoryUrl(path)
		if err != nil {
			return result, err
		}
	}

	return result, nil
}
