# TLS-X509-Validation

[![PHP Version](https://img.shields.io/badge/php-%5E8.1-blue)](https://php.net)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Code Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)](#)

[English](README.md) | [中文](README.zh-CN.md)

此包实现了 TLS 协议的全面证书链验证逻辑。

## 目录

- [特性](#特性)
- [安装](#安装)
- [使用方法](#使用方法)
  - [基本证书验证](#基本证书验证)
  - [证书链验证](#证书链验证)
  - [交叉签名支持](#交叉签名支持)
- [高级用法](#高级用法)
  - [自定义验证规则](#自定义验证规则)
  - [证书链构建](#证书链构建)
  - [自定义证书验证器](#自定义证书验证器)
  - [验证结果分析](#验证结果分析)
- [配置](#配置)
  - [验证选项](#验证选项)
  - [异常处理](#异常处理)
- [系统要求](#系统要求)
- [测试](#测试)
- [许可证](#许可证)

## 特性

- **证书链验证**: 完整的证书信任链验证
- **证书有效性检查**: 自动过期和有效期验证
- **信任锚管理**: 灵活的信任锚配置和管理
- **证书策略验证**: 支持证书策略约束和映射
- **交叉签名支持**: 交叉签名证书验证，支持平滑的 CA 转换
- **名称约束检查**: 域名和 IP 地址约束验证
- **密钥用途验证**: 证书密钥用途限制验证
- **撤销检查**: 与 CRL 和 OCSP 验证集成
- **详细错误报告**: 全面的验证结果报告

## 安装

```bash
composer require tourze/tls-x509-validation
```

## 使用方法

### 基本证书验证

```php
use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Validator\CertificateValidator;
use Tourze\TLSX509Validation\Validator\ValidationOptions;

// 创建验证选项
$options = new ValidationOptions();
$options->setValidateKeyUsage(true);
$options->setValidateExtendedKeyUsage(true);

// 创建验证器和信任锚
$validator = new CertificateValidator($trustAnchors, $options);

// 验证证书
$certificate = new X509Certificate($certData);
$result = $validator->validate($certificate);

if ($result->isValid()) {
    echo "证书有效";
} else {
    echo "证书验证失败: " . $result->getErrorMessage();
}
```

### 证书链验证

```php
use Tourze\TLSX509Validation\Chain\CertificateChain;

// 创建证书链
$chain = new CertificateChain($certificates);

// 验证链完整性
$isValid = $chain->verifyChainIntegrity();

if ($isValid) {
    echo "证书链有效";
} else {
    echo "证书链验证失败";
}
```

### 交叉签名支持

```php
use Tourze\TLSX509Validation\CrossSign\CrossSignValidator;

// 创建交叉签名验证器
$crossSignValidator = new CrossSignValidator();

// 验证交叉签名证书
$result = $crossSignValidator->validate($crossSignedCertificate);

if ($result->isValid()) {
    echo "交叉签名证书有效";
}
```

## 高级用法

### 自定义验证规则

```php
use Tourze\TLSX509Validation\Policy\PolicyValidator;
use Tourze\TLSX509Validation\Policy\CertificatePolicy;

// 创建自定义策略验证器
$policyValidator = new PolicyValidator();
$policyValidator->addExpectedPolicy('1.2.3.4.5');
$policyValidator->setRequireExplicitPolicy(true);

// 根据策略验证证书
$chain = new CertificateChain($certificates);
$result = new ValidationResult();
$isValid = $policyValidator->validate($chain, $result);
```

### 证书链构建

```php
use Tourze\TLSX509Validation\Chain\CertificateChain;

// 从无序证书自动构建证书链
$leafCertificate = new X509Certificate($leafCertData);
$availableCertificates = [
    new X509Certificate($intermediateCert1),
    new X509Certificate($intermediateCert2),
    new X509Certificate($rootCert)
];

$chain = CertificateChain::buildFromCertificates($leafCertificate, $availableCertificates);

// 验证构建的链
$isValid = $chain->verifyChainIntegrity();
```

### 自定义证书验证器

```php
use Tourze\TLSX509Validation\Certificate\X509CertificateVerifier;

// 使用自定义 CA 路径创建验证器
$verifier = new X509CertificateVerifier('/path/to/trusted/ca.crt');

// 使用证书链验证证书
$result = $verifier->verify($certificateData, $certificateChain);

if ($result->isValid()) {
    echo "证书验证成功";
} else {
    echo "验证失败: " . $result->getErrorMessage();
}
```

### 验证结果分析

```php
use Tourze\TLSX509Validation\Validator\ValidationResult;

$result = $validator->validate($certificate);

// 检查验证状态
echo "有效: " . ($result->isValid() ? '是' : '否') . "\n";

// 获取详细信息
foreach ($result->getErrors() as $error) {
    echo "错误: " . $error . "\n";
}

foreach ($result->getWarnings() as $warning) {
    echo "警告: " . $warning . "\n";
}

foreach ($result->getInfoMessages() as $info) {
    echo "信息: " . $info . "\n";
}
```

## 配置

### 验证选项

- `validateCertificateChain`: 启用证书链验证
- `validateKeyUsage`: 启用密钥用途验证
- `validateExtendedKeyUsage`: 启用扩展密钥用途验证
- `requireCompleteCertificateChain`: 需要完整的证书链
- `allowSelfSignedCertificates`: 允许自签名证书
- `checkRevocation`: 启用撤销检查

### 异常处理

该包为不同的验证失败提供特定的异常：

- `CertificateValidationException::certificateExpired()` - 证书已过期
- `CertificateValidationException::certificateNotYetValid()` - 证书尚未生效
- `CertificateValidationException::signatureVerificationFailed()` - 签名验证失败
- `CertificateValidationException::issuerCertificateNotFound()` - 找不到颁发者证书
- `CertificateValidationException::incompleteCertificateChain()` - 证书链不完整
- `CertificateValidationException::invalidKeyUsage()` - 无效的密钥用途

## 系统要求

- PHP 8.1 或更高版本
- tourze/tls-common
- tourze/tls-crypto-asymmetric
- tourze/tls-x509-core

## 测试

```bash
vendor/bin/phpunit packages/tls-x509-validation/tests
```

## 许可证

MIT