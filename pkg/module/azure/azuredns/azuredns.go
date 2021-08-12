package azuredns

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2018-05-01/dns"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

func NewWrapper() {
	//Create a Manager client
	authorizer, err := auth.NewAuthorizerFromEnvironment()
	c := dns.NewZonesClient("d7c31df5-29ac-4d96-87d4-78dd5e8b107e")
	c.Client.Authorizer = authorizer
	fmt.Println(c)
	r, err := c.List(context.Background(), nil)
	fmt.Println(err)
	fmt.Println(r)

}
