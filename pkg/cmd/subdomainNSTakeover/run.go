package subdomainNSTakeover

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	logstd "log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/brahma"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/util"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/module/aws/route53w"
)

var subdoomainTakeoverStatusMap = struct {
	Vulnerable    int
	NonVulnerable int
	Suspect       int
}{
	Vulnerable:    1,
	NonVulnerable: 0,
	Suspect:       2,
}

var lowRiskList = []string{
	"*.acm-validations.aws",
	"*.rds.amazonaws.com",
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

	// log.Info("fetching account details from brahma")
	// brahmaInv := brahma.NewBrahma(conf.Brahma)
	// // 1. get file from s3 and parse to json
	// // 2. filter all the accounts
	// accounts, err := brahmaInv.GetAccounts()
	// if err != nil {
	// 	log.Fatalf("error while loading accounts from brahma - %v", err)
	// }
	// log.Info(accounts)

	// dnsRecordsFromInv := []interface{}{}
	// wg := sync.WaitGroup{}
	// guardC := make(chan int, conf.Common.WorkerCount)
	// mutex := &sync.Mutex{}
	// // recordsTypes := "A |AAAA | CNAME | NS"
	// for _, account := range accounts {
	// 	wg.Add(1)
	// 	guardC <- 1
	// 	go func(account brahma.Account) {
	// 		_dnsRecordsFromInv, err := processOneAcc(account)
	// 		if err == nil {
	// 			mutex.Lock()
	// 			dnsRecordsFromInv = append(dnsRecordsFromInv, _dnsRecordsFromInv...)
	// 			mutex.Unlock()
	// 		}
	// 		wg.Done()
	// 		<-guardC
	// 	}(account)
	// }

	// wg.Wait()
	// exported, _ := util.WriteToCSV("testoutput.csv", dnsRecordsFromInv)

	// log.Infof("Exported to %v", *exported)

	// Open the file
	servicesfile, err := os.Open("services.json")
	if err != nil {
		log.Fatalf("Couldn't open the service file", err)
	}
	defer servicesfile.Close()
	services := []*Service{}
	byteValue, _ := ioutil.ReadAll(servicesfile)
	err = json.Unmarshal(byteValue, &services)
	if err != nil {
		log.Fatalln("Couldn't parse the service file", err)
	}

	// Open the file
	csvfile, err := os.Open("testoutput.csv")
	if err != nil {
		log.Fatalln("Couldn't open the csv file", err)
	}
	defer csvfile.Close()
	// Parse records to map
	records, err := util.CSVToMap(csvfile)
	if err != nil {
		log.Fatalln("Couldn't open the csv file", err)
	}

	dnsRecords := []DNSRecord{}
	b, _ := json.Marshal(records)
	json.Unmarshal(b, &dnsRecords)

	results := []interface{}{}
	wg := sync.WaitGroup{}
	guardC := make(chan int, conf.Common.WorkerCount)
	mutex := &sync.Mutex{}
	for _, v := range dnsRecords {
		guardC <- 1
		wg.Add(1)
		go func(v DNSRecord) {
			if v.Type == "A" || v.Type == "AAAA" || v.Type == "CNAME" {
				if isSubdomainTakeover(v, services) {
					mutex.Lock()
					results = append(results, v)
					mutex.Unlock()
				}
			} else if v.Type == "NS" {
				if isNSTakeover(v) {
					mutex.Lock()
					results = append(results, v)
					mutex.Unlock()
				}
			}

			wg.Done()
			<-guardC
		}(v)
	}
	wg.Wait()
	exported, _ := util.WriteToCSV("scanresult.csv", results)

	log.Infof("Exported to %v", *exported)

	/*

		// config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
		c := new(dns.Client)
		m := new(dns.Msg)

		for _, v := range dnsRecords {
			// 1. try to resolve dns
			// 2. try to get response
			t := v.Target
			log.Info("=======================")
			log.Infof("Target: %v", t)
			m.RecursionDesired = true
			result, err := net.LookupHost(t)
			// Note the trailing dot. miekg/dns is very low-level and expects canonical names.
			// m.SetQuestion(t, dns.TypeA)
			// result, _, err := c.Exchange(m, "8.8.8.8:53")
			if err != nil {
				log.Infof("LookupHost Result: %v", err)
			} else {
				// if len(result.Answer) == 0 {
				// 	log.Infof("LookupHost Result: %v", "cannot fetch A record")
				// } else {
				// 	// log.Infof("LookupHost Result: %v", result.Answer[0].(*dns.A).A)
				// 	log.Infof("LookupHost Result: %v", result.Answer)
				// }

				log.Infof("LookupHost Result: %v", result)
			}

			// try cname
			m.SetQuestion(t, dns.TypeCNAME)
			result2, _, err := c.Exchange(m, "8.8.8.8:53")
			// result2, err := net.LookupCNAME(t)
			if err != nil {
				log.Infof("LookupCNAME Result: %v", err)
			} else {
				if len(result2.Answer) == 0 {
					log.Infof("LookupCNAME Result: %v", "cannot fetch CNAME record")
				} else {
					log.Infof("LookupCNAME Result: %v", result2.Answer[0].(*dns.CNAME).Target)
					// log.Infof("LookupCNAME Result: %v", result2.Answer)
				}
				// log.Infof("LookupCNAME Result: %v", result2)
				// log.Infof("LookupCNAME Result: %v", rtt)
			}

			// try ns
			result3, err := net.LookupNS(t)
			if err != nil {
				log.Infof("LookupNS Result: %v", err)
			} else {
				log.Infof("LookupNS Result: %v", result3)
			}
		}
	*/
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

func isSubdomainTakeover(record DNSRecord, services []*Service) bool {
	// 1. try to resolve a record
	log.Info("=======================")
	target := strings.Split(record.Target, ",")[0]
	log.Infof("Scanning: %v", target)
	result, err := net.LookupHost(target)
	if err != nil {
		log.Infof("LookupHost Result: %v", err)
		return true
	} else {
		if len(result) == 0 {
			log.Infof("LookupHost Result: %v", "cannot fetch A record")
		} else {
			log.Infof("LookupHost Result: %v", result)
			ip1 := result[0]
			// 2. check if it is private ip
			if !isPrivateIP(net.ParseIP(ip1)) {
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
						isVulnerable, service := isKnownResponse(string(html), []*Service{})
						if isVulnerable {
							log.Info(service)
							return true
						}
					}
				}
			}
		}
	}
	return false
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
	log.Info("================================")
	log.Info(account.Name)
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
