<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Chain;

use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Exception\CertificateValidationException;

/**
 * 证书链 - 表示X.509证书的信任链
 */
class CertificateChain
{
    /**
     * @var array<X509Certificate> 证书链中的证书列表，顺序从终端实体到信任锚
     */
    private array $certificates;

    /**
     * 构造函数
     *
     * @param array<X509Certificate> $certificates 证书列表
     */
    public function __construct(array $certificates = [])
    {
        $this->certificates = $certificates;
    }

    /**
     * 添加证书到链中
     *
     * @param X509Certificate $certificate 要添加的证书
     *
     * @return $this
     */
    public function addCertificate(X509Certificate $certificate): self
    {
        $this->certificates[] = $certificate;

        return $this;
    }

    /**
     * 获取证书链中的所有证书
     *
     * @return array<X509Certificate> 证书列表
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }

    /**
     * 获取证书链的长度
     *
     * @return int 证书链长度
     */
    public function getLength(): int
    {
        return count($this->certificates);
    }

    /**
     * 检查证书链是否为空
     *
     * @return bool 如果证书链为空则返回true
     */
    public function isEmpty(): bool
    {
        return [] === $this->certificates;
    }

    /**
     * 获取终端实体证书（链中的第一个证书）
     *
     * @return X509Certificate|null 终端实体证书，如果链为空则返回null
     */
    public function getEndEntityCertificate(): ?X509Certificate
    {
        if ([] === $this->certificates) {
            return null;
        }

        return $this->certificates[0];
    }

    /**
     * 获取信任锚证书（链中的最后一个证书）
     *
     * @return X509Certificate|null 信任锚证书，如果链为空则返回null
     */
    public function getTrustAnchorCertificate(): ?X509Certificate
    {
        if ([] === $this->certificates) {
            return null;
        }

        return $this->certificates[count($this->certificates) - 1];
    }

    /**
     * 获取中间证书（链中除了终端实体和信任锚之外的所有证书）
     *
     * @return array<X509Certificate> 中间证书列表
     */
    public function getIntermediateCertificates(): array
    {
        $count = count($this->certificates);

        if ($count <= 2) {
            return [];
        }

        return array_slice($this->certificates, 1, $count - 2);
    }

    /**
     * 验证证书链中的颁发者和主题关系
     *
     * @return bool 如果链中的所有证书都有正确的颁发者-主题关系则返回true
     */
    public function validateIssuerSubjectChain(): bool
    {
        $count = count($this->certificates);

        if ($count <= 1) {
            return true;
        }

        for ($i = 0; $i < $count - 1; ++$i) {
            $subject = $this->certificates[$i];
            $issuer = $this->certificates[$i + 1];

            if ($subject->getIssuerDN() !== $issuer->getSubjectDN()) {
                return false;
            }
        }

        return true;
    }

    /**
     * 验证链的完整性
     *
     * @param bool $verifySignatures 是否验证证书签名
     *
     * @return bool 如果链完整则返回true
     *
     * @throws CertificateValidationException 如果链不完整
     */
    public function verifyChainIntegrity(bool $verifySignatures = true): bool
    {
        if ($this->isEmpty()) {
            throw new CertificateValidationException('证书链为空');
        }

        // 检查每个证书是否正确链接到其颁发者
        for ($i = 0; $i < count($this->certificates) - 1; ++$i) {
            $current = $this->certificates[$i];
            $issuer = $this->certificates[$i + 1];

            // 检查颁发者名称
            $currentIssuerDN = $current->getIssuerDN();
            if ($currentIssuerDN !== $issuer->getSubjectDN()) {
                throw CertificateValidationException::issuerCertificateNotFound($currentIssuerDN ?? 'Unknown', $current->getSubjectDN(), $current->getSerialNumber());
            }

            // 验证签名
            if ($verifySignatures) {
                // TODO: 实现签名验证
                // 此处需要调用签名验证逻辑
            }
        }

        // 检查根证书是否为自签名
        $root = $this->getTrustAnchorCertificate();
        if (null !== $root && $root->getIssuerDN() !== $root->getSubjectDN()) {
            throw new CertificateValidationException('证书链的根证书不是自签名的');
        }

        return true;
    }

    /**
     * 从未排序的证书集合构建证书链
     *
     * @param X509Certificate   $leafCertificate 叶子证书
     * @param X509Certificate[] $certificates    可用于构建链的证书集合
     *
     * @return self 构建的证书链
     *
     * @throws CertificateValidationException 如果无法构建完整的链
     */
    public static function buildFromCertificates(X509Certificate $leafCertificate, array $certificates): self
    {
        $chain = new self([$leafCertificate]);
        $currentCertificate = $leafCertificate;
        $maxChainLength = 10;

        while (count($chain->getCertificates()) < $maxChainLength) {
            if (self::isSelfSigned($currentCertificate)) {
                break;
            }

            $issuerCertificate = self::findIssuer($currentCertificate, $certificates, $chain->getCertificates());

            if (null === $issuerCertificate) {
                throw CertificateValidationException::incompleteCertificateChain($leafCertificate->getSubjectDN(), $leafCertificate->getSerialNumber());
            }

            $chain->addCertificate($issuerCertificate);
            $currentCertificate = $issuerCertificate;
        }

        return $chain;
    }

    /**
     * 检查证书是否为自签名
     */
    private static function isSelfSigned(X509Certificate $certificate): bool
    {
        return $certificate->getIssuerDN() === $certificate->getSubjectDN();
    }

    /**
     * 查找颁发者证书
     *
     * @param X509Certificate[] $availableCertificates 可用证书集合
     * @param X509Certificate[] $chainCertificates     已在链中的证书
     */
    private static function findIssuer(
        X509Certificate $certificate,
        array $availableCertificates,
        array $chainCertificates,
    ): ?X509Certificate {
        foreach ($availableCertificates as $candidateCertificate) {
            if (self::containsCertificate($chainCertificates, $candidateCertificate)) {
                continue;
            }

            if (self::isIssuerOf($candidateCertificate, $certificate)) {
                return $candidateCertificate;
            }
        }

        return null;
    }

    /**
     * 检查证书A是否是证书B的颁发者
     */
    private static function isIssuerOf(X509Certificate $issuer, X509Certificate $subject): bool
    {
        return $issuer->getSubjectDN() === $subject->getIssuerDN();
    }

    /**
     * 检查证书是否已在列表中
     *
     * @param X509Certificate[] $certificates 证书列表
     * @param X509Certificate   $certificate  要检查的证书
     *
     * @return bool 如果证书已在列表中则返回true
     */
    private static function containsCertificate(array $certificates, X509Certificate $certificate): bool
    {
        foreach ($certificates as $cert) {
            if ($cert->getSerialNumber() === $certificate->getSerialNumber()) {
                return true;
            }
        }

        return false;
    }
}
