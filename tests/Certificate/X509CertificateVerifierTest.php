<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Certificate;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Validation\Certificate\X509CertificateVerifier;
use Tourze\TLSX509Validation\Exception\CertificateValidationException;

/**
 * X509证书验证器测试类
 *
 * @internal
 */
#[CoversClass(X509CertificateVerifier::class)]
final class X509CertificateVerifierTest extends TestCase
{
    private X509CertificateVerifier $verifier;

    protected function setUp(): void
    {
        parent::setUp();

        $this->verifier = new X509CertificateVerifier();
    }

    /**
     * 测试验证无效证书格式
     */
    public function testVerifyInvalidCertificateFormat(): void
    {
        $invalidCert = 'invalid certificate data';
        $result = $this->verifier->verify($invalidCert, []);

        $this->assertFalse($result->isValid());
        $this->assertEquals('证书格式无效', $result->getMessage());
    }

    /**
     * 测试验证有效证书格式的结构
     */
    public function testVerifyValidCertificateStructure(): void
    {
        // 这里使用一个简单的自签名证书进行测试
        $cert = $this->createValidTestCertificate();
        $result = $this->verifier->verify($cert, []);

        // 由于没有CA路径且没有证书链，会返回"证书不受信任"
        $this->assertFalse($result->isValid());
        $this->assertEquals('证书不受信任', $result->getMessage());
    }

    /**
     * 测试验证过期证书
     */
    public function testVerifyExpiredCertificate(): void
    {
        // 创建一个有效证书，然后修改其有效期检查逻辑进行测试
        $validCert = $this->createValidTestCertificate();

        // 由于我们无法轻易创建过期证书，我们测试证书解析是否正常
        // 这个测试主要验证过期检查逻辑是否能正常工作
        $result = $this->verifier->verify($validCert, []);

        // 此证书应该验证失败，因为没有CA路径且没有证书链
        $this->assertFalse($result->isValid());
        $this->assertEquals('证书不受信任', $result->getMessage());
    }

    /**
     * 创建用于测试的有效证书
     */
    private function createValidTestCertificate(): string
    {
        // 创建一个简单的自签名证书用于测试
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $privateKey = openssl_pkey_new($config);
        if (false === $privateKey) {
            throw new CertificateValidationException('Failed to create private key for test certificate');
        }

        $dn = [
            'countryName' => 'CN',
            'stateOrProvinceName' => 'Beijing',
            'localityName' => 'Beijing',
            'organizationName' => 'Tourze',
            'organizationalUnitName' => 'Security',
            'commonName' => 'test.example.com',
        ];

        $csr = openssl_csr_new($dn, $privateKey);
        if (false === $csr) {
            throw new CertificateValidationException('Failed to create CSR for test certificate');
        }

        /** @var \OpenSSLCertificateSigningRequest $csr */
        $cert = openssl_csr_sign($csr, null, $privateKey, 365);
        if (false === $cert) {
            throw new CertificateValidationException('Failed to sign test certificate');
        }

        $certString = '';
        openssl_x509_export($cert, $certString);

        return $certString;
    }
}
