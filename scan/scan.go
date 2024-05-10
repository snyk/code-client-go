package scan

import "github.com/snyk/code-client-go/internal/util"

type RepositoryTarget struct {
	LocalFilePath string
	repositoryUrl string
}

type ScanTarget interface {
	GetPath() string
}

func (r RepositoryTarget) GetPath() string {
	return r.LocalFilePath
}

func (r RepositoryTarget) GetRepositoryUrl() string {
	return r.repositoryUrl
}

func NewRepositoryTarget(path string, repositoryUrl string) (ScanTarget, error) {
	var err error
	if len(repositoryUrl) == 0 {
		repositoryUrl, err = util.GetRepositoryUrl(path)
		if err != nil {
			return &RepositoryTarget{}, err
		}
	} else {
		repositoryUrl, err = util.SanitiseCredentials(repositoryUrl)
		if err != nil {
			return &RepositoryTarget{}, err
		}
	}

	result := &RepositoryTarget{
		LocalFilePath: path,
		repositoryUrl: repositoryUrl,
	}
	return result, nil
}

func NewRepositoryTargetFromPath(path string) (ScanTarget, error) {
	return NewRepositoryTarget(path, "")
}
