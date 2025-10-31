<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Validation\Validator\CertificateVerificationResult;
use Tourze\TLSX509Validation\Validator\CertificateVerifier;

/**
 * @internal
 */
#[CoversClass(CertificateVerifier::class)]
final class CertificateVerifierTest extends TestCase
{
    /**
     * 测试证书验证器基本实现
     */
    public function testAbstractVerifier(): void
    {
        // 创建模拟的具体验证器实现
        $verifier = new class extends CertificateVerifier {
            public function verify(array $certificates, array $options = []): CertificateVerificationResult
            {
                // 简单实现：只要有证书就视为验证通过
                if ([] === $certificates) {
                    return new CertificateVerificationResult(false, '没有提供证书');
                }

                return new CertificateVerificationResult(true, '测试验证通过');
            }
        };

        // 测试没有证书的情况
        $emptyCertResult = $verifier->verify([]);
        $this->assertFalse($emptyCertResult->isValid());
        $this->assertEquals('没有提供证书', $emptyCertResult->getMessage());

        // 测试有证书的情况
        $validCertResult = $verifier->verify(['certificate-data']);
        $this->assertTrue($validCertResult->isValid());
        $this->assertEquals('测试验证通过', $validCertResult->getMessage());
    }
}
