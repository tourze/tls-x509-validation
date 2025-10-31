# TLS-X509-Validation

[![PHP Version](https://img.shields.io/badge/php-%5E8.1-blue)](https://php.net)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Code Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)](#)

[English](README.md) | [中文](README.zh-CN.md)

This package implements comprehensive certificate chain validation logic for the TLS protocol.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Certificate Validation](#basic-certificate-validation)
  - [Certificate Chain Validation](#certificate-chain-validation)
  - [Cross-Signing Support](#cross-signing-support)
- [Advanced Usage](#advanced-usage)
  - [Custom Validation Rules](#custom-validation-rules)
  - [Certificate Chain Building](#certificate-chain-building)
  - [Custom Certificate Verifier](#custom-certificate-verifier)
  - [Validation Result Analysis](#validation-result-analysis)
- [Configuration](#configuration)
  - [Validation Options](#validation-options)
  - [Exception Handling](#exception-handling)
- [Requirements](#requirements)
- [Testing](#testing)
- [License](#license)

## Features

- **Certificate Chain Verification**: Complete validation of certificate trust chains
- **Certificate Validity Checking**: Automatic expiration and validity period verification
- **Trust Anchor Management**: Flexible trust anchor configuration and management
- **Certificate Policy Validation**: Support for certificate policy constraints and mappings
- **Cross-Signing Support**: Validation of cross-signed certificates for smooth CA transitions
- **Name Constraint Checking**: Domain and IP address constraint validation
- **Key Usage Validation**: Verification of certificate key usage restrictions
- **Revocation Checking**: Integration with CRL and OCSP validation
- **Detailed Error Reporting**: Comprehensive validation result reporting

## Installation

```bash
composer require tourze/tls-x509-validation
```

## Usage

### Basic Certificate Validation

```php
use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Validator\CertificateValidator;
use Tourze\TLSX509Validation\Validator\ValidationOptions;

// Create validation options
$options = new ValidationOptions();
$options->setValidateKeyUsage(true);
$options->setValidateExtendedKeyUsage(true);

// Create validator with trust anchors
$validator = new CertificateValidator($trustAnchors, $options);

// Validate a certificate
$certificate = new X509Certificate($certData);
$result = $validator->validate($certificate);

if ($result->isValid()) {
    echo "Certificate is valid";
} else {
    echo "Certificate validation failed: " . $result->getErrorMessage();
}
```

### Certificate Chain Validation

```php
use Tourze\TLSX509Validation\Chain\CertificateChain;

// Create certificate chain
$chain = new CertificateChain($certificates);

// Verify chain integrity
$isValid = $chain->verifyChainIntegrity();

if ($isValid) {
    echo "Certificate chain is valid";
} else {
    echo "Certificate chain validation failed";
}
```

### Cross-Signing Support

```php
use Tourze\TLSX509Validation\CrossSign\CrossSignValidator;

// Create cross-sign validator
$crossSignValidator = new CrossSignValidator();

// Validate cross-signed certificate
$result = $crossSignValidator->validate($crossSignedCertificate);

if ($result->isValid()) {
    echo "Cross-signed certificate is valid";
}
```

## Advanced Usage

### Custom Validation Rules

```php
use Tourze\TLSX509Validation\Policy\PolicyValidator;
use Tourze\TLSX509Validation\Policy\CertificatePolicy;

// Create custom policy validator
$policyValidator = new PolicyValidator();
$policyValidator->addExpectedPolicy('1.2.3.4.5');
$policyValidator->setRequireExplicitPolicy(true);

// Validate certificate against policies
$chain = new CertificateChain($certificates);
$result = new ValidationResult();
$isValid = $policyValidator->validate($chain, $result);
```

### Certificate Chain Building

```php
use Tourze\TLSX509Validation\Chain\CertificateChain;

// Automatically build certificate chain from unordered certificates
$leafCertificate = new X509Certificate($leafCertData);
$availableCertificates = [
    new X509Certificate($intermediateCert1),
    new X509Certificate($intermediateCert2),
    new X509Certificate($rootCert)
];

$chain = CertificateChain::buildFromCertificates($leafCertificate, $availableCertificates);

// Verify the built chain
$isValid = $chain->verifyChainIntegrity();
```

### Custom Certificate Verifier

```php
use Tourze\TLSX509Validation\Certificate\X509CertificateVerifier;

// Create verifier with custom CA path
$verifier = new X509CertificateVerifier('/path/to/trusted/ca.crt');

// Verify certificate with chain
$result = $verifier->verify($certificateData, $certificateChain);

if ($result->isValid()) {
    echo "Certificate verification successful";
} else {
    echo "Verification failed: " . $result->getErrorMessage();
}
```

### Validation Result Analysis

```php
use Tourze\TLSX509Validation\Validator\ValidationResult;

$result = $validator->validate($certificate);

// Check validation status
echo "Valid: " . ($result->isValid() ? 'Yes' : 'No') . "\n";

// Get detailed information
foreach ($result->getErrors() as $error) {
    echo "Error: " . $error . "\n";
}

foreach ($result->getWarnings() as $warning) {
    echo "Warning: " . $warning . "\n";
}

foreach ($result->getInfoMessages() as $info) {
    echo "Info: " . $info . "\n";
}
```

## Configuration

### Validation Options

- `validateCertificateChain`: Enable certificate chain validation
- `validateKeyUsage`: Enable key usage validation
- `validateExtendedKeyUsage`: Enable extended key usage validation
- `requireCompleteCertificateChain`: Require complete certificate chain
- `allowSelfSignedCertificates`: Allow self-signed certificates
- `checkRevocation`: Enable revocation checking

### Exception Handling

The package provides specific exceptions for different validation failures:

- `CertificateValidationException::certificateExpired()` - Certificate has expired
- `CertificateValidationException::certificateNotYetValid()` - Certificate is not yet valid
- `CertificateValidationException::signatureVerificationFailed()` - Signature verification failed
- `CertificateValidationException::issuerCertificateNotFound()` - Issuer certificate not found
- `CertificateValidationException::incompleteCertificateChain()` - Certificate chain is incomplete
- `CertificateValidationException::invalidKeyUsage()` - Invalid key usage

## Requirements

- PHP 8.1 or higher
- tourze/tls-common
- tourze/tls-crypto-asymmetric
- tourze/tls-x509-core

## Testing

```bash
vendor/bin/phpunit packages/tls-x509-validation/tests
```

## License

MIT