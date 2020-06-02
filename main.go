package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/peterbourgon/ff"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config provides a deadline in days before actual expiration to consider a
// certificate as "expiring." Bundles are the actual bundles to check. If the
// bundle begins with "s3://" it will be retrieved from S3. Otherwise, the
// bundle will be treated as a local file path.
type Config struct {
	DeadlineDays uint64   `json:"deadline_days"`
	Bundles      []string `json:"bundles"`
}

func configure(configFile string, debug bool) (Config, error) {
	// Default to info level output
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		// Output debug level messages and everything in a human-friendly format
		// and allow logging from cfssl revocation check to output
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		// Discard output from cfssl logger
		stdlog.SetOutput(ioutil.Discard)
	}

	// Read in and parse json for the Config struct
	raw, err := ioutil.ReadFile(configFile)
	if err != nil {
		return Config{}, fmt.Errorf("reading file %v: %w", configFile, err)
	}
	var cfg Config
	err = json.Unmarshal(raw, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("processing config file %v: %w", configFile, err)
	}
	return cfg, nil
}

func getCerts(location string) ([]byte, error) {
	log.Info().Str("location", location).Msg("trying to load new bundle")
	if strings.HasPrefix(location, "s3://") {
		u, err := url.Parse(location)
		if err != nil {
			return []byte{}, fmt.Errorf("could not parse S3 url %v: %w", location, err)
		}
		bucket := u.Host
		// strip leading slash from path
		key := u.Path[1:]
		log.Debug().Str("bucket", bucket).Str("key", key).Msg("trying s3 location")

		cfg, err := external.LoadDefaultAWSConfig()
		if err != nil {
			return []byte{}, fmt.Errorf("failed to configure AWS client: %w", err)
		}
		cfg.Region = endpoints.UsEast1RegionID

		var raw []byte
		buf := aws.NewWriteAtBuffer(raw)

		downloader := s3manager.NewDownloader(cfg)
		_, err = downloader.Download(buf, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return []byte{}, fmt.Errorf("failed to download file, %w", err)
		}

		return buf.Bytes(), nil
	}

	// If not S3 then treat as a local file path
	raw, err := ioutil.ReadFile(location)
	if err != nil {
		return []byte{}, fmt.Errorf("reading file %v: %w", location, err)
	}
	return raw, nil

}

func checkCerts(raw []byte, config Config) []error {
	// Decode each PEM block present in the bundle file
	var errs []error
	rest := raw
	var blocks []*pem.Block
	var block *pem.Block
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			errs = append(errs, ErrNoCertificates)
			break
		} else if block.Type != "CERTIFICATE" {
			errs = append(errs, ErrParsing)
			continue
		}
		blocks = append(blocks, block)
	}

	// Now parse each into an x.509 certificate
	var certs []x509.Certificate
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || cert == nil {
			errs = append(errs, ErrParsing)
			continue
		}
		certs = append(certs, *cert)
	}

	now := time.Now()
	// How many days before expiration to begin failing
	softDeadline := now.AddDate(0, 0, int(config.DeadlineDays))
	// Check all certificates expirations
	for _, cert := range certs {
		if cert.NotAfter.Before(softDeadline) {
			errs = append(errs, ErrViolatesDeadline)
		}
		if cert.NotAfter.Before(now) {
			errs = append(errs, ErrExpired)
		}

		revoked, ok := revoke.VerifyCertificate(&cert)
		if !ok {
			log.Error().Str("subject", cert.Subject.CommonName).Msg("failed to verify revocation status, possibly retry")
			// We don't log this as a failure as some certificate may not include information needed to check on
			// revocation status, e.g., Digicert root certificate
		} else if revoked {
			errs = append(errs, ErrRevoked)
		}
		if len(errs) == 0 {
			log.Info().Str("subject", cert.Subject.CommonName).Time("expiration", cert.NotAfter).Msg("certificate not expired or revoked")
		} else {
			log.Error().Str("subject", cert.Subject.CommonName).Time("expiration", cert.NotAfter).Msg("certificate expired or revoked")
		}
	}

	if len(certs) == 3 {
		log.Info().Msg("found three certificates, attempting to verify proper chain")
		leaf := certs[0]
		intermediate := certs[1]
		root := certs[2]

		if len(leaf.DNSNames) == 0 {
			errs = append(errs, ErrParsing)
			return errs
		}

		roots := x509.NewCertPool()
		roots.AddCert(&root)

		intermediates := x509.NewCertPool()
		intermediates.AddCert(&intermediate)

		opts := x509.VerifyOptions{
			DNSName:       leaf.DNSNames[0],
			Intermediates: intermediates,
			Roots:         roots,
		}

		if _, err := leaf.Verify(opts); err != nil {
			e := fmt.Errorf("failed to verify certificate using bundled chain: %w", err)
			errs = append(errs, e)
		}

		if leaf.NotAfter.After(intermediate.NotAfter) || leaf.NotAfter.After(root.NotAfter) {
			errs = append(errs, ErrParentExpiresFirst)
		}
	}
	return errs
}

func main() {
	fs := flag.NewFlagSet("my-program", flag.ExitOnError)
	var (
		configFile = fs.String("config", "chkbundle.json", "location of configuration file")
		debug      = fs.Bool("debug", false, "log debug information")
	)
	ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("CHKBUNDLE"))

	config, err := configure(*configFile, *debug)
	if err != nil {
		log.Fatal().Err(err).Msg("could not configure")
	}

	ok := true
	for _, bundle := range config.Bundles {
		bytes, err := getCerts(bundle)
		if err != nil {
			log.Fatal().Err(err).Msg("could not get certificates")
		}
		errs := checkCerts(bytes, config)
		if len(errs) != 0 {
			ok = false
			for _, e := range errs {
				log.Error().Str("bundle", bundle).Err(e).Send()
			}
		}
	}

	if !ok {
		log.Fatal().Msg("one or more bundles failed validity checks")
	}
	log.Info().Msg("all bundles passed checks!")
}
