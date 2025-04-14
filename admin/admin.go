package admin

import (
	"fmt"

	"github.com/grpc-kit/pkg/lion"
	"github.com/sirupsen/logrus"
)

// KnownAdminAPI xx
type KnownAdminAPI struct {
	config *config
	logger *logrus.Entry
}

// New xx
func New(opts ...Options) *KnownAdminAPI {
	c := &config{}

	for _, opt := range opts {
		opt(c)
	}

	// TODO; 默认值设置
	if c.logger == nil {
		c.logger = logrus.NewEntry(logrus.New())
	}

	return &KnownAdminAPI{
		config: c,
		logger: c.logger,
	}
}

func (a *KnownAdminAPI) GetLionClient() (*lion.Client, error) {
	if a.config == nil || a.config.db == nil {
		return nil, fmt.Errorf("not found database client")
	}

	return a.config.db, nil
}
