package subdomainNSTakeover

import (
	"fmt"
	"io/ioutil"
	logstd "log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/brahma"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/util"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/module/aws/ec2w"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/module/aws/route53w"
)

var subdoomainTakeoverStatusMap = struct {
	Vulnerable    int
	NonVulnerable int
	Suspect       int
	Warning       int
}{
	Vulnerable:    1,
	NonVulnerable: 0,
	Suspect:       2,
	Warning:       3,
}

func Run() {
	initLogging()
	log.Infof("starting")

	cwd, _ := os.Getwd()
	ls, _ := filepath.Glob("*")
	log.Infof("cwd - %v, ls - %v", cwd, ls)
	util.LogSystemUsage(1 * time.Second)
	conf := loadConfig()
	loglevel, err := log.ParseLevel(conf.LogLevel)
	if err != nil {
		loglevel = log.InfoLevel
	}
	log.SetLevel(loglevel)

	start := time.Now()
	//fetchDNSRecords(*conf)
	// Open the services file
	services := []*Service{}
	err = util.OpenJSONFile("data/services.json", &services)
	if err != nil {
		log.Fatal(err)
	}

	// Open the low risk file
	lowRiskList := []*string{}
	err = util.OpenJSONFile("data/lowRisk.json", &lowRiskList)
	if err != nil {
		log.Fatal(err)
	}

	// Open the ip file
	ips := []IP{}
	err = util.OpenCSVFile("data/ips.csv", ips)
	if err != nil {
		log.Fatal(err)
	}
	ipsMap := map[string]IP{}
	for _, ip := range ips {
		ipsMap[ip.IP] = ip
	}

	// Open the file
	dnsRecords := []DNSRecord{}
	err = util.OpenCSVFile("data/inventory.csv", &dnsRecords)
	if err != nil {
		log.Fatal(err)
	}

	results := []interface{}{}
	wg := sync.WaitGroup{}
	guardC := make(chan int, conf.Common.WorkerCount)
	mutex := &sync.Mutex{}
	for _, v := range dnsRecords {
		guardC <- 1
		wg.Add(1)
		go func(r DNSRecord) {
			if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" {
				if isSubdomainTakeover(r, services, lowRiskList, ipsMap) != subdoomainTakeoverStatusMap.NonVulnerable {
					mutex.Lock()
					results = append(results, r)
					mutex.Unlock()
				}
			} else if r.Type == "NS" {
				if isNSTakeover(r) {
					mutex.Lock()
					results = append(results, r)
					mutex.Unlock()
				}
			}
			<-guardC
			wg.Done()
		}(v)
	}
	wg.Wait()
	if len(results) > 0 {
		exported, err := util.WriteToCSV("output.csv", results)
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("Exported to %v", *exported)
	}

	timeTaken := time.Since(start)
	log.Infof("done shipping. time taken %v", timeTaken)
}

func isPrivateIP(ip net.IP) bool {
	var privateIPBlocks []*net.IPNet
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func isSubdomainTakeover(record DNSRecord, services []*Service, lowRiskList []*string, ipsMap map[string]IP) int {
	// 1. try to resolve a record
	target := strings.Split(record.Target, ",")[0]
	log.Infof("Scanning: %v", target)
	// skip it if it it in the lowrisklist
	if isInLowRiskList(lowRiskList, target) {
		log.Infof("Skipped: %v, low risk", target)
		return subdoomainTakeoverStatusMap.NonVulnerable
	}
	if ip, found := ipsMap[target]; found {
		if ip.AssociationId == "" {
			return subdoomainTakeoverStatusMap.Warning
		}
		return subdoomainTakeoverStatusMap.NonVulnerable
	}
	result, err := net.LookupHost(target)
	if err != nil {
		log.Infof("LookupHost Result: %v", err)
		return subdoomainTakeoverStatusMap.Vulnerable
	} else {
		log.Infof("LookupHost Result: %v", result)
		ip1 := result[0]
		// 2. check if it is private ip
		if isPrivateIP(net.ParseIP(ip1)) {
			return subdoomainTakeoverStatusMap.NonVulnerable
		}
		// try to request it
		protocols := []string{"http://", "https://"}
		for _, p := range protocols {
			client := http.Client{
				Timeout: 2 * time.Second,
			}
			resp, err := client.Get(p + target)
			if err == nil {
				defer resp.Body.Close()
				html, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Error(err)
				}
				// show the HTML code as a string %s
				isVulnerable, _ := isKnownResponse(string(html), []*Service{})
				if isVulnerable {
					return subdoomainTakeoverStatusMap.Vulnerable
				}
			}
		}

	}
	return subdoomainTakeoverStatusMap.NonVulnerable
}

func isNSTakeover(record DNSRecord) bool {
	target := record.Target
	result, err := net.LookupNS(target)
	if err != nil {
		log.Infof("LookupNS Result: %v", err)
		return true
	} else {
		nsMap := map[string]bool{}
		for _, r := range result {
			nsMap[r.Host] = true
		}
		log.Infof("LookupNS Result: %v", nsMap)
		nsRecords := strings.Split(record.Target, ",")
		for _, nsRecord := range nsRecords {
			if !nsMap[nsRecord] {
				return true
			}
		}
	}
	return false
}

func isKnownResponse(html string, services []*Service) (bool, *Service) {
	for _, service := range services {
		if strings.Contains(html, service.Message) {
			return true, service
		}
	}
	return false, nil
}

func processOneAcc(account brahma.Account) ([]interface{}, error) {
	dnsRecordsFromInv := []interface{}{}
	route53wrapper, err := route53w.NewWrapper(&account)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	zones, err := route53wrapper.ListAllHostedZones()
	if err != nil {
		// failed
		log.Error(err)
		return nil, err
	}
	for _, zone := range zones {
		recordSets, err := route53wrapper.ListAllRecordSets(*zone.Id)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		for _, recordset := range recordSets {
			r := DNSRecord{
				Source:    *recordset.Name,
				Target:    route53wrapper.ParseTarget(recordset),
				Type:      *recordset.Type,
				Provider:  "AWS",
				AccountId: account.AccountNumber,
			}
			dnsRecordsFromInv = append(dnsRecordsFromInv, r)
		}
	}
	return dnsRecordsFromInv, nil
}

func isInLowRiskList(lowRiskList []*string, target string) bool {
	for _, l := range lowRiskList {
		matched, _ := regexp.Match(*l, []byte(target))
		if matched {
			return true
		}
	}
	return false
}

func fetchDNSRecords(conf config) {
	log.Info("fetching account details from brahma")
	brahmaInv := brahma.NewBrahma(conf.Brahma)
	// 1. get file from s3 and parse to json
	// 2. filter all the accounts
	accounts, err := brahmaInv.GetAccounts()
	if err != nil {
		log.Fatalf("error while loading accounts from brahma - %v", err)
	}
	log.Info(accounts)

	dnsRecordsFromInv := []interface{}{}
	ipsFromInv := []interface{}{}
	wg := sync.WaitGroup{}
	guardC := make(chan int, conf.Common.WorkerCount)
	mutex := &sync.Mutex{}
	for _, account := range accounts {
		wg.Add(1)
		guardC <- 1
		go func(account brahma.Account) {
			_dnsRecordsFromInv, err := processOneAcc(account)
			if err == nil {
				mutex.Lock()
				dnsRecordsFromInv = append(dnsRecordsFromInv, _dnsRecordsFromInv...)
				mutex.Unlock()
			}

			ec2Wrapper, err := ec2w.NewWrapper(&account)
			if err == nil {
				ips, err := ec2Wrapper.ListIPs()
				if err == nil {
					for _, v := range ips.Addresses {
						value := struct {
							IP            *string
							AssociationId *string
							AllocationId  *string
						}{
							IP:            v.PublicIp,
							AssociationId: v.AssociationId,
							AllocationId:  v.AllocationId,
						}
						mutex.Lock()
						ipsFromInv = append(ipsFromInv, value)
						mutex.Unlock()
					}
				}
			}
			wg.Done()
			<-guardC
		}(account)
	}

	wg.Wait()
	exportedDNS, err := util.WriteToCSV("testoutput.csv", dnsRecordsFromInv)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("Exported to %v", *exportedDNS)

	exportedIPS, err := util.WriteToCSV("ips.csv", ipsFromInv)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("Exported to %v", *exportedIPS)

}

func initLogging() {
	logger := log.StandardLogger()
	logger.SetReportCaller(true)
	appRootMarker := "subdomainTakeover/"
	appRootMarkerLen := len(appRootMarker)
	logger.Formatter = &log.TextFormatter{
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			filename := path.Base(f.File)
			funcName := f.Function[strings.Index(f.Function, appRootMarker)+appRootMarkerLen : len(f.Function)]
			return fmt.Sprintf("%s()", funcName), fmt.Sprintf("%s:%d", filename, f.Line)
		},
	}
	logstd.SetOutput(logger.Writer())
}
