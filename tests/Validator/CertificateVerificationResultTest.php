<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Validation\Validator\CertificateVerificationResult;

/**
 * @internal
 */
#[CoversClass(CertificateVerificationResult::class)]
final class CertificateVerificationResultTest extends TestCase
{
    public function testCanCreateWithValidState(): void
    {
        $result = new CertificateVerificationResult(true, '证书验证通过');

        $this->assertTrue($result->isValid());
        $this->assertEquals('证书验证通过', $result->getMessage());
    }

    public function testCanCreateWithInvalidState(): void
    {
        $result = new CertificateVerificationResult(false, '证书已过期');

        $this->assertFalse($result->isValid());
        $this->assertEquals('证书已过期', $result->getMessage());
    }

    public function testCanSwitchToInvalidState(): void
    {
        $result = new CertificateVerificationResult(true, '证书验证通过');
        $invalidResult = $result->withError('证书签名无效');

        // 原对象保持不变
        $this->assertTrue($result->isValid());
        $this->assertEquals('证书验证通过', $result->getMessage());

        // 新对象状态已更改
        $this->assertFalse($invalidResult->isValid());
        $this->assertEquals('证书签名无效', $invalidResult->getMessage());
    }

    public function testCanCreateEmptyMessage(): void
    {
        $result = new CertificateVerificationResult(true);

        $this->assertTrue($result->isValid());
        $this->assertEquals('', $result->getMessage());
    }

    public function testWithError(): void
    {
        $validResult = new CertificateVerificationResult(true, '验证通过');
        $errorResult = $validResult->withError('发生错误');

        $this->assertFalse($errorResult->isValid());
        $this->assertEquals('发生错误', $errorResult->getMessage());

        // 确保原对象未被修改
        $this->assertTrue($validResult->isValid());
        $this->assertEquals('验证通过', $validResult->getMessage());
    }
}
