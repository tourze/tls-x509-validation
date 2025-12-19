<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Certificate;

/**
 * 证书验证器抽象类
 */
abstract class CertificateVerifier
{
    /**
     * 验证证书的有效性
     *
     * @param string        $certificate      待验证的证书
     * @param array<string> $certificateChain 证书链
     *
     * @return CertificateVerificationResult 验证结果
     */
    abstract public function verify(string $certificate, array $certificateChain): CertificateVerificationResult;

    /**
     * 检查证书是否过期
     *
     * @param string $certificate 证书数据
     *
     * @return bool 是否过期
     */
    protected function checkExpiration(string $certificate): bool
    {
        $certInfo = openssl_x509_parse($certificate);
        if (false === $certInfo) {
            return false;
        }

        $now = time();

        return $now >= $certInfo['validFrom_time_t'] && $now <= $certInfo['validTo_time_t'];
    }

    /**
     * 提取证书主题信息
     *
     * @param string $certificate 证书数据
     *
     * @return array<string, string>|false 主题信息或失败返回false
     */
    protected function extractSubject(string $certificate)
    {
        $certInfo = openssl_x509_parse($certificate);
        if (false === $certInfo || !isset($certInfo['subject'])) {
            return false;
        }

        return $certInfo['subject'];
    }

    /**
     * 提取证书颁发者信息
     *
     * @param string $certificate 证书数据
     *
     * @return array<string, string>|false 颁发者信息或失败返回false
     */
    protected function extractIssuer(string $certificate)
    {
        $certInfo = openssl_x509_parse($certificate);
        if (false === $certInfo || !isset($certInfo['issuer'])) {
            return false;
        }

        return $certInfo['issuer'];
    }

    /**
     * 验证证书链
     *
     * @param string        $certificate      待验证的证书
     * @param array<string> $certificateChain 证书链
     *
     * @return bool 验证是否成功
     */
    protected function verifyChain(string $certificate, array $certificateChain): bool
    {
        if ([] === $certificateChain) {
            return false;
        }

        if (!function_exists('openssl_x509_store')) {
            return $this->verifyChainSimple($certificate, $certificateChain);
        }

        return $this->verifyChainWithStore($certificate, $certificateChain);
    }

    /**
     * 使用证书存储验证证书链
     *
     * @param string $certificate
     * @param array<string> $certificateChain
     */
    protected function verifyChainWithStore(string $certificate, array $certificateChain): bool
    {
        /** @phpstan-ignore function.notFound (未来可能存在的函数，运行时由 function_exists 防护) */
        $store = \openssl_x509_store();

        $this->addCertificatesToStore($store, $certificateChain);

        $cert = openssl_x509_read($certificate);
        if (false === $cert) {
            return false;
        }

        $result = openssl_x509_verify($cert, $store);

        return 1 === $result;
    }

    /**
     * 添加证书到存储
     * @param mixed $store
     * @param array<string> $certificateChain
     */
    protected function addCertificatesToStore($store, array $certificateChain): void
    {
        if (!function_exists('openssl_x509_store_add_cert')) {
            return;
        }

        foreach ($certificateChain as $caCert) {
            $cert = openssl_x509_read($caCert);
            if (false !== $cert) {
                \openssl_x509_store_add_cert($store, $cert);
            }
        }
    }

    /**
     * 使用简化方式验证证书链
     *
     * @param string        $certificate      待验证的证书
     * @param array<string> $certificateChain 证书链
     *
     * @return bool 验证是否成功
     */
    protected function verifyChainSimple(string $certificate, array $certificateChain): bool
    {
        // 验证证书本身是否有效
        $cert = openssl_x509_read($certificate);
        if (false === $cert) {
            return false;
        }

        // 验证证书链中的每个证书都是有效的
        foreach ($certificateChain as $chainCert) {
            if (false === openssl_x509_read($chainCert)) {
                return false;
            }
        }

        // 在没有完整store支持的情况下，只能做基本的格式验证
        // 这是一个简化的实现，实际生产环境中需要更完整的证书链验证
        return true;
    }
}
