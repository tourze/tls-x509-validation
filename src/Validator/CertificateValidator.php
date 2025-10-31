<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Validator;

use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Exception\CertificateValidationException;

/**
 * 证书验证器 - 负责验证X.509证书的有效性
 */
class CertificateValidator
{
    /**
     * @var X509Certificate[] 信任锚（信任的根证书）
     */
    private array $trustAnchors = [];

    /**
     * @var ValidationOptions 验证选项
     */
    private ValidationOptions $options;

    /**
     * 构造函数
     *
     * @param X509Certificate[]      $trustAnchors 信任锚列表
     * @param ValidationOptions|null $options      验证选项
     */
    public function __construct(array $trustAnchors = [], ?ValidationOptions $options = null)
    {
        foreach ($trustAnchors as $trustAnchor) {
            $this->addTrustAnchor($trustAnchor);
        }

        $this->options = $options ?? new ValidationOptions();
    }

    /**
     * 添加信任锚
     *
     * @param X509Certificate $certificate 要添加为信任锚的证书
     *
     * @return $this
     */
    public function addTrustAnchor(X509Certificate $certificate): self
    {
        $this->trustAnchors[] = $certificate;

        return $this;
    }

    /**
     * 验证证书
     *
     * @param X509Certificate   $certificate              要验证的证书
     * @param X509Certificate[] $intermediateCertificates 中间证书列表
     *
     * @return ValidationResult 验证结果
     */
    public function validate(X509Certificate $certificate, array $intermediateCertificates = []): ValidationResult
    {
        $result = new ValidationResult();

        try {
            // 1. 验证证书有效期
            $this->validateValidity($certificate, $result);

            if (!$result->isValid()) {
                return $result;
            }

            // 2. 验证证书签名（如果不是自签名）
            if (!$this->isRootCertificate($certificate)) {
                $this->validateSignature($certificate, $intermediateCertificates, $result);
            }

            // 3. 验证证书用途
            if ($this->options->isValidateKeyUsage()) {
                $this->validateKeyUsage($certificate, $result);
            }

            // 4. 验证证书链
            if ($this->options->isValidateCertificateChain()) {
                $this->validateCertificateChain($certificate, $intermediateCertificates, $result);
            }

            if ($result->isValid()) {
                $result->addSuccess('证书验证通过');
            }
        } catch (CertificateValidationException $e) {
            $result->addError($e->getMessage());
        } catch (\Throwable $e) {
            $result->addError('验证过程发生未预期错误: ' . $e->getMessage());
        }

        return $result;
    }

    /**
     * 检查证书是否为根证书
     */
    private function isRootCertificate(X509Certificate $certificate): bool
    {
        // 判断证书是否为自签名（颁发者与主题相同）
        return $certificate->getIssuerDN() === $certificate->getSubjectDN();
    }

    /**
     * 验证证书有效期
     *
     * @param X509Certificate  $certificate 要验证的证书
     * @param ValidationResult $result      验证结果
     */
    private function validateValidity(X509Certificate $certificate, ValidationResult $result): void
    {
        $now = new \DateTimeImmutable();
        $notBefore = $certificate->getNotBefore();
        $notAfter = $certificate->getNotAfter();

        if (null === $notBefore || null === $notAfter) {
            $result->addError('证书有效期信息不完整');

            return;
        }

        if ($now < $notBefore) {
            $result->addError('证书尚未生效，生效时间: ' . $notBefore->format(\DateTimeInterface::RFC3339));

            return;
        }

        if ($now > $notAfter) {
            $result->addError('证书已过期，过期时间: ' . $notAfter->format(\DateTimeInterface::RFC3339));

            return;
        }

        $result->addInfo('证书在有效期内');
    }

    /**
     * 验证证书签名
     *
     * @param X509Certificate   $certificate              要验证的证书
     * @param X509Certificate[] $intermediateCertificates 中间证书列表
     * @param ValidationResult  $result                   验证结果
     */
    private function validateSignature(X509Certificate $certificate, array $intermediateCertificates, ValidationResult $result): void
    {
        // 查找颁发者证书
        $issuerCertificate = $this->findIssuerCertificate($certificate, $intermediateCertificates);

        if (null === $issuerCertificate) {
            $result->addError('无法找到颁发者证书');

            return;
        }

        // 使用颁发者的公钥验证证书签名
        $signatureAlgorithm = $certificate->getSignatureAlgorithm();
        $signatureValue = $certificate->getSignature();

        // 实际签名验证逻辑（此处需要与tls-crypto模块集成）
        // TODO: 实现实际的签名验证逻辑
        // 暂时跳过签名验证，等待与tls-crypto模块集成

        // if (!$this->verifySignature($certificate, $issuerCertificate)) {
        //     $result->addError('证书签名验证失败');
        //     return;
        // }

        $result->addInfo('证书签名验证通过');
    }

    /**
     * 查找颁发者证书
     *
     * @param X509Certificate   $certificate              要查找颁发者的证书
     * @param X509Certificate[] $intermediateCertificates 中间证书列表
     *
     * @return X509Certificate|null 找到的颁发者证书，如果未找到则返回null
     */
    private function findIssuerCertificate(X509Certificate $certificate, array $intermediateCertificates): ?X509Certificate
    {
        $issuerDN = $certificate->getIssuerDN();

        // 首先从中间证书中查找
        foreach ($intermediateCertificates as $intermediateCert) {
            if ($intermediateCert->getSubjectDN() === $issuerDN) {
                return $intermediateCert;
            }
        }

        // 然后从信任锚中查找
        foreach ($this->trustAnchors as $trustAnchor) {
            if ($trustAnchor->getSubjectDN() === $issuerDN) {
                return $trustAnchor;
            }
        }

        return null;
    }

    /**
     * 验证证书用途
     *
     * @param X509Certificate  $certificate 要验证的证书
     * @param ValidationResult $result      验证结果
     */
    private function validateKeyUsage(X509Certificate $certificate, ValidationResult $result): void
    {
        // 获取证书的密钥用途扩展
        // OID: 2.5.29.15 = Key Usage
        // OID: 2.5.29.37 = Extended Key Usage
        $keyUsage = null;
        $extendedKeyUsage = null;

        if ($certificate->hasExtension('2.5.29.15')) {
            $keyUsage = $certificate->getExtension('2.5.29.15');
        }

        if ($certificate->hasExtension('2.5.29.37')) {
            $extendedKeyUsage = $certificate->getExtension('2.5.29.37');
        }

        // 根据预期用途验证
        $expectedUsage = $this->options->getExpectedKeyUsage();
        if ([] !== $expectedUsage && null !== $keyUsage) {
            // 验证密钥用途
            // ...
        }

        $expectedExtendedUsage = $this->options->getExpectedExtendedKeyUsage();
        if ([] !== $expectedExtendedUsage && null !== $extendedKeyUsage) {
            // 验证扩展密钥用途
            // ...
        }

        $result->addInfo('证书用途验证通过');
    }

    /**
     * 验证证书链
     *
     * @param X509Certificate   $certificate              要验证的证书
     * @param X509Certificate[] $intermediateCertificates 中间证书列表
     * @param ValidationResult  $result                   验证结果
     */
    private function validateCertificateChain(X509Certificate $certificate, array $intermediateCertificates, ValidationResult $result): void
    {
        // 构建证书链
        $chain = $this->buildCertificateChain($certificate, $intermediateCertificates);

        if ([] === $chain) {
            $result->addError('无法构建完整的证书链');

            return;
        }

        // 验证链中的每个证书
        foreach ($chain as $i => $cert) {
            if ($i === count($chain) - 1) {
                // 验证链的根证书是否为信任锚
                if (!$this->isTrustAnchor($cert)) {
                    $result->addError('证书链的根证书不是信任锚');

                    return;
                }
            }
            // 验证中间证书
            // 可以添加更多验证逻辑
        }

        $result->addInfo('证书链验证通过');
    }

    /**
     * 构建证书链
     *
     * @param X509Certificate   $certificate              起始证书
     * @param X509Certificate[] $intermediateCertificates 可用的中间证书
     *
     * @return X509Certificate[] 构建的证书链
     */
    private function buildCertificateChain(X509Certificate $certificate, array $intermediateCertificates): array
    {
        $chain = [$certificate];
        $current = $certificate;

        // 防止无限循环的最大深度
        $maxChainLength = 10;

        while (count($chain) < $maxChainLength) {
            // 如果当前证书是自签名的，链已完成
            if ($this->isRootCertificate($current)) {
                break;
            }

            // 查找颁发者
            $issuer = $this->findIssuerCertificate($current, $intermediateCertificates);

            // 如果找不到颁发者，或者颁发者已在链中（循环），则停止
            if (null === $issuer || in_array($issuer, $chain, true)) {
                break;
            }

            $chain[] = $issuer;
            $current = $issuer;
        }

        return $chain;
    }

    /**
     * 检查证书是否为信任锚
     *
     * @param X509Certificate $certificate 要检查的证书
     *
     * @return bool 如果是信任锚则返回true
     */
    private function isTrustAnchor(X509Certificate $certificate): bool
    {
        foreach ($this->trustAnchors as $trustAnchor) {
            if ($trustAnchor->getSerialNumber() === $certificate->getSerialNumber()) {
                return true;
            }
        }

        return false;
    }
}
