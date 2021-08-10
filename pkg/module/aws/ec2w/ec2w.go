package ec2w

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/brahma"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/util"
)

type Wrapper struct {
	svc     *ec2.EC2
	Account *brahma.Account
}

func (w *Wrapper) ListIPs() (*ec2.DescribeAddressesOutput, error) {
	i := &ec2.DescribeAddressesInput{}
	out, err := w.svc.DescribeAddresses(i)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch hosted zone: %v", err)
	}
	return out, nil
}

func NewWrapper(account *brahma.Account) (*Wrapper, error) {
	//Create a Manager client
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("ap-southeast-1"),
	})
	if err != nil {
		return nil, fmt.Errorf("can't init session %v", err)
	}
	creds := &credentials.Credentials{}
	if account != nil {
		roleArn := account.RoleARN
		externalID := account.ExternalID
		if !util.IsNAOrEmpty(roleArn) && !util.IsNAOrEmpty(externalID) {
			creds = stscreds.NewCredentials(sess, roleArn, func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = &externalID
			})
		} else if !util.IsNAOrEmpty(roleArn) {
			creds = stscreds.NewCredentials(sess, roleArn)
		} else {
			return nil, fmt.Errorf("can't assume to the account %v", account.Name)
		}
	}
	svc := ec2.New(sess, &aws.Config{Credentials: creds})
	wrapper := &Wrapper{
		svc:     svc,
		Account: account,
	}
	return wrapper, nil
}
