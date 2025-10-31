<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Validation\Certificate\X509CertificateVerifier;

/**
 * 证书验证器测试类
 *
 * @internal
 */
#[CoversClass(X509CertificateVerifier::class)]
final class CertificateVerifierTest extends TestCase
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
     * 测试验证空证书
     */
    public function testVerifyEmptyCertificate(): void
    {
        $emptyCert = '';
        $result = $this->verifier->verify($emptyCert, []);

        $this->assertFalse($result->isValid());
        $this->assertEquals('证书格式无效', $result->getMessage());
    }

    /**
     * 测试验证缺少开始标记的证书
     */
    public function testVerifyCertificateWithoutBeginMarker(): void
    {
        $cert = "MIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";
        $result = $this->verifier->verify($cert, []);

        $this->assertFalse($result->isValid());
        $this->assertEquals('证书格式无效', $result->getMessage());
    }
}
