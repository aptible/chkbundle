package main

import "errors"

var (
	// ErrNoCertificates is returned when the given locations do not contain any PEM-encoded
	// certificates
	ErrNoCertificates = errors.New("no PEM blocks found at location")

	// ErrNoCertificates is returned when the given locations do not contain any PEM-encoded
	// certificates
	ErrParsing = errors.New("could not parse a PEM block to an X509 certificate")

	// ErrViolatesDeadline is returned when a certificate expires within DeadlineDays
	ErrViolatesDeadline = errors.New("certificate expires within deadline days")

	// ErrExpired is returned when the certificate is already expired
	ErrExpired = errors.New("certificate expired")

	// ErrRevoked is returned when the certificate is revoked or its times are invalid
	ErrRevoked = errors.New("certificate revoked")

	// ErrParentExpiresFirst is returned when either the intermediate or root certificates expires
	// before the leaf certificate
	ErrParentExpiresFirst = errors.New("part of trust chain expires before the leaf certificate")
)
