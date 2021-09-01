package azureconfig

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common"
)

type Config struct {
	Location           string `mapstructure:"location"`
	InventoryLocalPath string `mapstructure:"inventory_local_path"`

	Common common.Config
}

type inventory struct {
	Subscriptions []Subscription `json:"subscriptions"`
}

type Subscription struct {
	Id string `json:"Id"`
}

type Azure struct {
	config Config
}

func (b *Azure) GetAccounts() ([]Subscription, error) {
	log.Infof("azure config - %+v", b.config)
	inv, err := b.getInventory()
	if err != nil {
		log.Error(err)
		return nil, err
	}

	subscriptions := []Subscription{}
	for _, a := range inv.Subscriptions {
		subscriptions = append(subscriptions, a)
	}
	return subscriptions, nil
}

func (b *Azure) getInventory() (*inventory, error) {
	var invRaw io.Reader
	var err error
	if b.config.Location == "local" {
		invRaw, err = os.Open(b.config.InventoryLocalPath)
		if err != nil {
			log.Errorf("error while opening local azure inv file - %v", err)
			return nil, err
		}
	} else if b.config.Location == "azure" {
		//To be implemented
	} else {
		return nil, errors.New("unsupported azure inventory location")
	}
	inv := &inventory{}
	err = json.NewDecoder(invRaw).Decode(inv)
	if err != nil {
		log.Errorf("while decoding inv file - %v", err)
		return nil, err
	}
	return inv, nil
}

// creating the creator
func NewAzure(config Config) *Azure {
	b := &Azure{
		config: config,
	}
	return b
}
