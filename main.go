package main

import (
	"flag"
	"fmt"
	dns "github.com/Focinfi/go-dns-resolver"
	//"log"
	"crypto/tls"
	"net/http"
	"os"
	"sync"
	"time"
)

type CommandLineConfig struct {
	host_name          *string
	use_ssl            *bool
	check_redirect_ssl *bool
	check_cert_date    *bool
}

func (*CommandLineConfig) Parse() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
}

var commandLineCfg = CommandLineConfig{
	host_name:          flag.String("host_name", "localhost", "An FQDN to check"),
	use_ssl:            flag.Bool("use_ssl", false, "Use SSL"),
	check_redirect_ssl: flag.Bool("check_redirect_ssl", false, "Check redirect from HTTP to HTTPS"),
	check_cert_date:    flag.Bool("check_cert_date", false, "Check SSL cert expiration date"),
}

func redirectChecker(req *http.Request, via []*http.Request) error {
	var err = http.ErrUseLastResponse
	if *commandLineCfg.check_redirect_ssl {
		if req.URL.Scheme != "https" {
			err = fmt.Errorf("There is no HTTP to HTTPS redirect for %s", via[0].URL.Host)
		}
	}
	return err
}

func main() {
	commandLineCfg.Parse()
	dns.Config.SetTimeout(uint(2))
	dns.Config.RetryTimes = uint(4)
	all_ips := make([]string, 0)
	dead_ips := make([]string, 0)
	var wg sync.WaitGroup

	if results, err := dns.Exchange(*commandLineCfg.host_name, "8.8.8.8:53", dns.TypeA); err == nil {
		for _, r := range results {
			all_ips = append(all_ips, r.Content)
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				redirected := false
				client := &http.Client{
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						redirected = true
						return redirectChecker(req, via)
					},
					Timeout: 2 * time.Second,
				}
				if *commandLineCfg.check_cert_date {
					tlsConfig := &tls.Config{
						InsecureSkipVerify: true,
					}
					conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", ip), tlsConfig)
					if err != nil {
						fmt.Printf("Err: %v\n", err)
						dead_ips = append(dead_ips, ip)
					} else {
						defer conn.Close()
					}

					timeNow := time.Now()
					checkedCerts := make(map[string]struct{})
					for _, cert := range conn.ConnectionState().PeerCertificates {
						if _, checked := checkedCerts[string(cert.Signature)]; checked {
							continue
						}
						checkedCerts[string(cert.Signature)] = struct{}{}

						// Check the expiration.
						if timeNow.AddDate(0, 0, 90).After(cert.NotAfter) {
							//expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
							dead_ips = append(dead_ips, ip)
							break
						}
					}

					return
				}
				if !*commandLineCfg.use_ssl {
					_, err := client.Get(fmt.Sprintf("http://%s/", ip))
					if err != nil {
						dead_ips = append(dead_ips, ip)
					} else {
						if *commandLineCfg.check_redirect_ssl && !redirected {
							dead_ips = append(dead_ips, ip)
						}
					}
				} else {
					_, err := client.Get(fmt.Sprintf("https://%s/", ip))
					if err != nil {
						fmt.Printf("err: %v\n", err)
						dead_ips = append(dead_ips, ip)
					}
				}
			}(r.Content)
		}
	} else {
		fmt.Printf("CRITICAL - %v\n", err)
		os.Exit(2)
	}
	wg.Wait()
	if len(dead_ips) != 0 {
		fmt.Printf("CRITICAL - some probes (%v/%v) failed\n", len(dead_ips), len(all_ips))
		os.Exit(2)
	} else {
		fmt.Printf("OK - all probes (%v/%v) succeeded\n", len(all_ips), len(all_ips))
		os.Exit(0)
	}
}
