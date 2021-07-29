package brahma

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	log "github.com/sirupsen/logrus"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common"
)

type Config struct {
	Location             string   `mapstructure:"location"`
	InventoryLocalPath   string   `mapstructure:"inventory_local_path"`
	InventoryAwsS3Bucket string   `mapstructure:"inventory_aws_s3_bucket"`
	InventoryAwsS3Key    string   `mapstructure:"inventory_aws_s3_key"`
	PlatformFilter       string   `mapstructure:"platform_filter"`
	AccountsToSkip       []string `mapstructure:"accounts_to_skip"`

	Common common.Config
}

type inventory struct {
	Accounts []Account `json:"subaccounts"`
}

type Account struct {
	AccountNumber string `json:"AccountNumber"`
	AccountStatus string `json:"AccountStatus"`
	CostingFamily string `json:"Costing_Family"`
	AccountType   string `json:"AccountType"`
	Comments      string `json:"Comments"`
	ExternalID    string `json:"External_ID"`
	Name          string `json:"Name"`
	Platform      string `json:"Platform"`
	Provider      string
	PrimaryPIC    string `json:"Primary_PIC"`
	RoleARN       string `json:"Role_ARN"`
	SecondaryPIC  string `json:"Secondary_PIC"`
	//Agents        agent `json:"agents"`
}

type agent struct {
	DeepSecurity string `json:"DeepSecurity"`
	NESSUS       string `json:"NESSUS"`
	OKTASSH      string `json:"OKTASSH"`
	OSQUERY      string `json:"OSQUERY"`
}

type Brahma struct {
	config Config
}

func (b *Brahma) GetAccounts() ([]Account, error) {
	log.Infof("brahma config - %+v", b.config)
	inv, err := b.getInventory()
	if err != nil {
		log.Error(err)
		return nil, err
	}
	skipMap := map[string]bool{}
	for _, a := range b.config.AccountsToSkip {
		skipMap[a] = true
	}
	accounts := []Account{}
	for _, a := range inv.Accounts {
		_, skip := skipMap[a.AccountNumber]
		if skip {
			continue
		}
		platform := strings.ToLower(strings.TrimSpace(a.Platform))
		status := strings.ToLower(strings.TrimSpace(a.AccountStatus))
		//TODO - regex
		if platform != b.config.PlatformFilter || status != "active" {
			continue
		}
		a.Provider = platform
		a.AccountNumber = strings.TrimSpace(a.AccountNumber)
		accounts = append(accounts, a)
	}
	return accounts, nil
}

func (b *Brahma) getInventory() (*inventory, error) {
	var invRaw io.Reader
	var err error
	if b.config.Location == "local" {
		invRaw, err = os.Open(b.config.InventoryLocalPath)
		if err != nil {
			log.Errorf("error while opening local brahma inv file - %v", err)
			return nil, err
		}
	} else if b.config.Location == "aws" {
		sess, _ := session.NewSession(&aws.Config{
			Region: aws.String("ap-southeast-1")},
		)
		downloader := s3manager.NewDownloader(sess)
		buf := aws.NewWriteAtBuffer([]byte{})
		_, err := downloader.Download(buf,
			&s3.GetObjectInput{
				Bucket: aws.String(b.config.InventoryAwsS3Bucket),
				Key:    aws.String(b.config.InventoryAwsS3Key),
			})
		if err != nil {
			log.Errorf("error while fetching aws brahma inv file - %v", err)
			return nil, err
		}
		invRaw = bytes.NewBuffer(buf.Bytes())
	} else {
		return nil, errors.New("unsupported brahma inventory location")
	}
	inv := &inventory{}
	err = json.NewDecoder(invRaw).Decode(inv)
	if err != nil {
		log.Errorf("while decoding inv file - %v", err)
		return nil, err
	}
	return inv, nil
}

// lol - creating the creator

func NewBrahma(config Config) *Brahma {
	b := &Brahma{
		config: config,
	}
	return b
}
