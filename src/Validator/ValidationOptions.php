<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Validator;

/**
 * 证书验证选项 - 配置证书验证过程中的行为
 */
class ValidationOptions
{
    /**
     * @var bool 是否验证证书链
     */
    private bool $validateCertificateChain = true;

    /**
     * @var bool 是否验证密钥用途
     */
    private bool $validateKeyUsage = true;

    /**
     * @var bool 是否验证扩展密钥用途
     */
    private bool $validateExtendedKeyUsage = true;

    /**
     * @var bool 是否需要完整的证书链
     */
    private bool $requireCompleteCertificateChain = true;

    /**
     * @var bool 是否允许自签名证书
     */
    private bool $allowSelfSignedCertificates = false;

    /**
     * @var array<string> 预期的密钥用途
     */
    private array $expectedKeyUsage = [];

    /**
     * @var array<string> 预期的扩展密钥用途
     */
    private array $expectedExtendedKeyUsage = [];

    /**
     * @var bool 是否验证证书撤销状态
     */
    private bool $checkRevocation = false;

    /**
     * @var bool 是否验证证书主题替代名称
     */
    private bool $validateSubjectAlternativeName = true;

    /**
     * @var string|null 预期的主机名（用于SAN验证）
     */
    private ?string $expectedHostname = null;

    /**
     * 构造函数
     */
    public function __construct()
    {
    }

    /**
     * 设置是否验证证书链
     */
    public function setValidateCertificateChain(bool $validateCertificateChain): void
    {
        $this->validateCertificateChain = $validateCertificateChain;
    }

    /**
     * 获取是否验证证书链
     */
    public function isValidateCertificateChain(): bool
    {
        return $this->validateCertificateChain;
    }

    /**
     * 设置是否验证密钥用途
     */
    public function setValidateKeyUsage(bool $validateKeyUsage): void
    {
        $this->validateKeyUsage = $validateKeyUsage;
    }

    /**
     * 获取是否验证密钥用途
     */
    public function isValidateKeyUsage(): bool
    {
        return $this->validateKeyUsage;
    }

    /**
     * 设置是否验证扩展密钥用途
     */
    public function setValidateExtendedKeyUsage(bool $validateExtendedKeyUsage): void
    {
        $this->validateExtendedKeyUsage = $validateExtendedKeyUsage;
    }

    /**
     * 获取是否验证扩展密钥用途
     */
    public function isValidateExtendedKeyUsage(): bool
    {
        return $this->validateExtendedKeyUsage;
    }

    /**
     * 设置是否需要完整的证书链
     */
    public function setRequireCompleteCertificateChain(bool $requireCompleteCertificateChain): void
    {
        $this->requireCompleteCertificateChain = $requireCompleteCertificateChain;
    }

    /**
     * 获取是否需要完整的证书链
     */
    public function isRequireCompleteCertificateChain(): bool
    {
        return $this->requireCompleteCertificateChain;
    }

    /**
     * 设置是否允许自签名证书
     */
    public function setAllowSelfSignedCertificates(bool $allowSelfSignedCertificates): void
    {
        $this->allowSelfSignedCertificates = $allowSelfSignedCertificates;
    }

    /**
     * 获取是否允许自签名证书
     */
    public function isAllowSelfSignedCertificates(): bool
    {
        return $this->allowSelfSignedCertificates;
    }

    /**
     * 设置预期的密钥用途
     *
     * @param array<string> $expectedKeyUsage
     */
    public function setExpectedKeyUsage(array $expectedKeyUsage): void
    {
        $this->expectedKeyUsage = $expectedKeyUsage;
    }

    /**
     * 获取预期的密钥用途
     * @return array<string>
     */
    public function getExpectedKeyUsage(): array
    {
        return $this->expectedKeyUsage;
    }

    /**
     * 设置预期的扩展密钥用途
     *
     * @param array<string> $expectedExtendedKeyUsage
     */
    public function setExpectedExtendedKeyUsage(array $expectedExtendedKeyUsage): void
    {
        $this->expectedExtendedKeyUsage = $expectedExtendedKeyUsage;
    }

    /**
     * 获取预期的扩展密钥用途
     * @return array<string>
     */
    public function getExpectedExtendedKeyUsage(): array
    {
        return $this->expectedExtendedKeyUsage;
    }

    /**
     * 设置是否验证证书撤销状态
     */
    public function setCheckRevocation(bool $checkRevocation): void
    {
        $this->checkRevocation = $checkRevocation;
    }

    /**
     * 获取是否验证证书撤销状态
     */
    public function isCheckRevocation(): bool
    {
        return $this->checkRevocation;
    }

    /**
     * 设置是否验证证书主题替代名称
     */
    public function setValidateSubjectAlternativeName(bool $validateSubjectAlternativeName): void
    {
        $this->validateSubjectAlternativeName = $validateSubjectAlternativeName;
    }

    /**
     * 获取是否验证证书主题替代名称
     */
    public function isValidateSubjectAlternativeName(): bool
    {
        return $this->validateSubjectAlternativeName;
    }

    /**
     * 设置预期的主机名
     */
    public function setExpectedHostname(?string $expectedHostname): void
    {
        $this->expectedHostname = $expectedHostname;
    }

    /**
     * 获取预期的主机名
     */
    public function getExpectedHostname(): ?string
    {
        return $this->expectedHostname;
    }
}
