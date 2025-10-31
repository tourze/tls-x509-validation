<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Certificate;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Validation\Certificate\CertificateVerificationResult;

/**
 * 证书验证结果测试类
 *
 * @internal
 */
#[CoversClass(CertificateVerificationResult::class)]
final class CertificateVerificationResultTest extends TestCase
{
    /**
     * 测试有效的验证结果
     */
    public function testValidResult(): void
    {
        $result = new CertificateVerificationResult(true, '验证成功');

        $this->assertTrue($result->isValid());
        $this->assertEquals('验证成功', $result->getMessage());
    }

    /**
     * 测试无效的验证结果
     */
    public function testInvalidResult(): void
    {
        $result = new CertificateVerificationResult(false, '证书不受信任');

        $this->assertFalse($result->isValid());
        $this->assertEquals('证书不受信任', $result->getMessage());
    }
}
