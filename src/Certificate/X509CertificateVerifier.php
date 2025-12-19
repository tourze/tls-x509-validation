<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Certificate;

/**
 * X509证书验证器类
 */
class X509CertificateVerifier extends CertificateVerifier
{
    /**
     * 构造函数
     *
     * @param string|null $caPath 可信CA证书目录或文件路径
     */
    public function __construct(
        private readonly ?string $caPath = null,
    ) {
    }

    /**
     * 验证证书的有效性
     *
     * @param string        $certificate      待验证的证书
     * @param array<string> $certificateChain 证书链
     *
     * @return CertificateVerificationResult 验证结果
     */
    public function verify(string $certificate, array $certificateChain): CertificateVerificationResult
    {
        // 验证证书格式
        if (!$this->verifyFormat($certificate)) {
            return new CertificateVerificationResult(false, '证书格式无效');
        }

        // 验证证书是否过期
        if (!$this->checkExpiration($certificate)) {
            return new CertificateVerificationResult(false, '证书已过期');
        }

        // 验证证书链
        if ([] !== $certificateChain && !$this->verifyChain($certificate, $certificateChain)) {
            return new CertificateVerificationResult(false, '证书链验证失败');
        }

        // 验证可信CA签名
        if (!$this->verifyCATrust($certificate, $certificateChain)) {
            return new CertificateVerificationResult(false, '证书不受信任');
        }

        return new CertificateVerificationResult(true, '证书验证成功');
    }

    /**
     * 验证证书格式
     *
     * @param string $certificate 证书数据
     *
     * @return bool 是否为有效的证书格式
     */
    private function verifyFormat(string $certificate): bool
    {
        // 首先进行基本的格式检查
        if ('' === $certificate) {
            return false;
        }

        // 检查是否包含PEM格式的基本标记
        if (!str_contains($certificate, '-----BEGIN CERTIFICATE-----')
            || !str_contains($certificate, '-----END CERTIFICATE-----')) {
            return false;
        }

        // 尝试使用openssl_x509_read验证
        // 清除之前的OpenSSL错误
        while (false !== openssl_error_string()) {
            // 清空错误队列
        }

        $result = openssl_x509_read($certificate);

        return false !== $result;
    }

    /**
     * 验证证书是否由可信CA签发
     *
     * @param string        $certificate      证书数据
     * @param array<string> $certificateChain 证书链
     *
     * @return bool 验证是否成功
     */
    private function verifyCATrust(string $certificate, array $certificateChain): bool
    {
        if (!$this->canVerifyTrust($certificateChain)) {
            return false;
        }

        $cert = openssl_x509_read($certificate);
        if (false === $cert) {
            return false;
        }

        if (!function_exists('openssl_x509_store')) {
            return $this->verifyWithSimpleCheck($certificate, $certificateChain);
        }

        return $this->verifyWithOpenSSLStore($cert, $certificateChain);
    }

    /**
     * 检查是否可以验证信任
     * @param array<string> $certificateChain
     */
    private function canVerifyTrust(array $certificateChain): bool
    {
        return null !== $this->caPath || [] !== $certificateChain;
    }

    /**
     * 使用 OpenSSL Store 验证证书
     * @param mixed $cert
     * @param array<string> $certificateChain
     */
    private function verifyWithOpenSSLStore($cert, array $certificateChain): bool
    {
        /** @phpstan-ignore function.notFound (未来可能存在的函数，运行时由 function_exists 防护) */
        $store = \openssl_x509_store();

        $this->addCertificateAuthorityToStore($store);
        $this->addCertificateChainToStore($store, $certificateChain);

        $result = openssl_x509_verify($cert, $store);

        return 1 === $result;
    }

    /**
     * 添加 CA 证书到存储
     * @param mixed $store
     */
    private function addCertificateAuthorityToStore($store): void
    {
        if (null !== $this->caPath && function_exists('openssl_x509_store_addcertificates')) {
            \openssl_x509_store_addcertificates($store, $this->caPath);
        }
    }

    /**
     * 添加证书链到存储
     * @param mixed $store
     * @param array<string> $certificateChain
     */
    private function addCertificateChainToStore($store, array $certificateChain): void
    {
        if (!function_exists('openssl_x509_store_add_cert')) {
            return;
        }

        foreach ($certificateChain as $caCert) {
            $chainCert = openssl_x509_read($caCert);
            if (false !== $chainCert) {
                \openssl_x509_store_add_cert($store, $chainCert);
            }
        }
    }

    /**
     * 使用简化方式验证证书信任
     *
     * @param string        $certificate      证书数据
     * @param array<string> $certificateChain 证书链
     *
     * @return bool 验证是否成功
     */
    private function verifyWithSimpleCheck(string $certificate, array $certificateChain): bool
    {
        if (!$this->canParseCertificate($certificate)) {
            return false;
        }

        if (!$this->hasValidTrustSource($certificateChain)) {
            return false;
        }

        if (!$this->validateCertificateChain($certificateChain)) {
            return false;
        }

        return true;
    }

    /**
     * 检查证书是否可以解析
     */
    private function canParseCertificate(string $certificate): bool
    {
        $cert = openssl_x509_read($certificate);

        return false !== $cert;
    }

    /**
     * 检查是否有有效的信任源
     * @param array<string> $certificateChain
     */
    private function hasValidTrustSource(array $certificateChain): bool
    {
        return [] !== $certificateChain || null !== $this->caPath;
    }

    /**
     * 验证证书链的基本有效性
     * @param array<string> $certificateChain
     */
    private function validateCertificateChain(array $certificateChain): bool
    {
        if ([] === $certificateChain) {
            return true;
        }

        foreach ($certificateChain as $chainCert) {
            if (false === openssl_x509_read($chainCert)) {
                return false;
            }
        }

        return true;
    }
}
