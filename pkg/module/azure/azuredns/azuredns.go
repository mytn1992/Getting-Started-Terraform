package azuredns

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2018-05-01/dns"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/azureconfig"
)

const (
	PlatformName = "AZURE"
	recCountMax  = 1000
)

func ListDNSBySubscription(subscription azureconfig.Subscription) ([]common.DNSRecord, error) {
	// // Authorize from File (To be implemented when Azure subscription is ready)
	// os.Setenv("AZURE_AUTH_LOCATION", "./config/azurecredentials.json")
	// authorizer, err := auth.NewAuthorizerFromFile("https://management.azure.com")
	// if err != nil || authorizer == nil {
	// 	fmt.Error("NewAuthorizerFromFile failed, got error %v", err)
	// }

	authorizer, _ := auth.NewAuthorizerFromCLI()
	c := dns.NewZonesClient(subscription.Id)
	rsc := dns.NewRecordSetsClient(subscription.Id)
	c.Client.Authorizer = authorizer
	rsc.Client.Authorizer = authorizer
	count := int32(recCountMax)

	azureDNSRecord := []common.DNSRecord{}
	res, err := c.List(context.Background(), &count)
	if err != nil {
		fmt.Errorf("Azure DNS Zone Client List Error: %v\n", err)
		return azureDNSRecord, err
	}
	for _, ri := range res.Values() {
		fmt.Println("----------------------------------------------------------")
		fmt.Println("Listing for DNS: ", *ri.Name)
		fmt.Println("ID: ", *ri.ID)
		fmt.Println("Type: ", *ri.Type)
		fmt.Println("Location: ", *ri.Location)
		fmt.Println("Num of Record Set: ", *ri.NumberOfRecordSets)
		var ResourceGroup string = strings.Split(*ri.ID, "/")[4]
		fmt.Println("ResourceGroup: ", ResourceGroup)
		dnsrec := common.DNSRecord{}

		rs, err := rsc.ListAllByDNSZone(context.Background(), ResourceGroup, *ri.Name, &count, "")
		if err != nil {
			fmt.Errorf("Azure DNS Record Set Client (Zone:%v) List Error:%v\n", *ri.Name, err)
			continue
		}

		for _, ii := range rs.Values() {
			if ii.ARecords != nil {
				for key, dns := range *ii.ARecords {
					fmt.Printf("Domain name (%v), ARecords #%v: %v\n", *ii.Fqdn, key+1, *dns.Ipv4Address)
					dnsrec = CreateDNSRecord(*ii.Fqdn, *dns.Ipv4Address, "A", PlatformName, subscription.Id, "")
					azureDNSRecord = append(azureDNSRecord, dnsrec)
				}
			}

			if ii.AaaaRecords != nil {
				for key, dns := range *ii.AaaaRecords {
					fmt.Printf("Domain name (%v), AaaaRecords #%v: %v\n", *ii.Fqdn, key+1, *dns.Ipv6Address)
					dnsrec = CreateDNSRecord(*ii.Fqdn, *dns.Ipv6Address, "AAAA", PlatformName, subscription.Id, "")
					azureDNSRecord = append(azureDNSRecord, dnsrec)
				}
			}

			if ii.NsRecords != nil {
				for key, dns := range *ii.NsRecords {
					fmt.Printf("Domain name (%v), Nameserver #%v: %v\n", *ii.Fqdn, key+1, *dns.Nsdname)
					dnsrec = CreateDNSRecord(*ii.Fqdn, *dns.Nsdname, "NS", PlatformName, subscription.Id, "")
					azureDNSRecord = append(azureDNSRecord, dnsrec)
				}
			}

			if ii.CnameRecord != nil {
				fmt.Printf("Domain name (%v), CnameRecord: %v \n", *ii.Fqdn, *ii.CnameRecord.Cname)
				dnsrec = CreateDNSRecord(*ii.Fqdn, *ii.CnameRecord.Cname, "CNAME", PlatformName, subscription.Id, "")
				azureDNSRecord = append(azureDNSRecord, dnsrec)
			}
		}
	}
	return azureDNSRecord, nil
}

func CreateDNSRecord(source, target, Type, provider, accountId, techFamily string) common.DNSRecord {
	record := common.DNSRecord{
		Source:     source,
		Target:     target,
		Type:       Type,
		Provider:   provider,
		AccountId:  accountId,
		TechFamily: techFamily,
	}
	return record
}
