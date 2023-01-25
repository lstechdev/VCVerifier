package operations

import (
	"github.com/fiware/vcbackend/vault"
	"github.com/hesusruiz/vcutils/yaml"

	zlog "github.com/rs/zerolog/log"
)

type Manager struct {
	v   *vault.Vault
	cfg *yaml.YAML
}

func NewManager(cfg *yaml.YAML) *Manager {

	// Open the Vault
	v, err := vault.New(cfg)
	if err != nil {
		zlog.Panic().Err(err).Send()
	}

	manager := &Manager{
		v:   v,
		cfg: cfg,
	}
	return manager

}

func (m *Manager) User() *User {
	return &User{db: m.v.Client}
}
