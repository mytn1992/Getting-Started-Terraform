package route53w

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/brahma"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/util"
)

type Wrapper struct {
	svc     *route53.Route53
	Account *brahma.Account
}

func (w *Wrapper) ListHostedZones(nextMarker *string) (*route53.ListHostedZonesOutput, error) {
	i := &route53.ListHostedZonesInput{
		Marker: nextMarker,
	}
	out, err := w.svc.ListHostedZones(i)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch hosted zone: %v", err)
	}
	return out, nil
}

func (w *Wrapper) ListAllHostedZones() ([]*route53.HostedZone, error) {
	zones := []*route53.HostedZone{}
	var nextMarker *string
	for {
		res, err := w.ListHostedZones(nextMarker)
		if err != nil {
			return nil, err
		}
		zones = append(zones, res.HostedZones...)
		if !*res.IsTruncated {
			break
		}
		nextMarker = res.NextMarker
	}
	return zones, nil
}

func (w *Wrapper) ListRecordSets(hostedZoneId string, startRecordName *string) (*route53.ListResourceRecordSetsOutput, error) {
	i := &route53.ListResourceRecordSetsInput{
		HostedZoneId:    &hostedZoneId,
		StartRecordName: startRecordName,
	}
	out, err := w.svc.ListResourceRecordSets(i)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch record sets: %v", err)
	}
	return out, nil
}

func (w *Wrapper) ListAllRecordSets(hostedZoneId string) ([]*route53.ResourceRecordSet, error) {
	records := []*route53.ResourceRecordSet{}
	var startRecordName *string
	for {
		res, err := w.ListRecordSets(hostedZoneId, startRecordName)
		if err != nil {
			return nil, err
		}
		records = append(records, res.ResourceRecordSets...)
		if !*res.IsTruncated {
			break
		}
		startRecordName = res.NextRecordName
	}
	return records, nil
}

func (w *Wrapper) ParseTarget(recordset *route53.ResourceRecordSet) string {
	if recordset.AliasTarget != nil {
		return *recordset.AliasTarget.DNSName
	}
	values := []string{}
	for _, r := range recordset.ResourceRecords {
		values = append(values, *r.Value)
	}
	return strings.Join(values, ",")
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
	svc := route53.New(sess, &aws.Config{Credentials: creds})
	wrapper := &Wrapper{
		svc:     svc,
		Account: account,
	}
	return wrapper, nil
}
