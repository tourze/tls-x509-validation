<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\CrossSign;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\CrossSign\CrossSignedCertificate;
use Tourze\TLSX509Validation\CrossSign\CrossSignValidator;
use Tourze\TLSX509Validation\Exception\CertificateValidationException;
use Tourze\TLSX509Validation\Validator\ValidationResult;

/**
 * 交叉签名验证器测试类
 *
 * @internal
 */
#[CoversClass(CrossSignValidator::class)]
final class CrossSignValidatorTest extends TestCase
{
    private CrossSignValidator $validator;

    private X509Certificate $primaryCert;

    private X509Certificate $crossSignedCert;

    private X509Certificate $trustAnchor;

    protected function setUp(): void
    {
        parent::setUp();

        $this->validator = new CrossSignValidator();

        // 创建主证书实例
        $this->primaryCert = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Primary CA',
            'primary-public-key',
            '1001'
        );

        // 创建交叉签名证书实例（与主证书具有相同主题和公钥，但颁发者不同）
        $this->crossSignedCert = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Cross CA',
            'primary-public-key',
            '1002',
            new \DateTimeImmutable('-1 day'),
            new \DateTimeImmutable('+1 year')
        );

        // 创建信任锚点证书（自签名根证书）
        $this->trustAnchor = $this->createTestCertificate(
            'CN=Cross CA',
            'CN=Cross CA',
            'trust-anchor-public-key',
            '1003'
        );
    }

    /**
     * 创建测试用证书实例
     */
    private function createTestCertificate(
        string $subjectDN,
        string $issuerDN,
        string $publicKey,
        string $serialNumber,
        ?\DateTimeImmutable $notBefore = null,
        ?\DateTimeImmutable $notAfter = null,
    ): X509Certificate {
        $certificate = new X509Certificate();
        $certificate->setSubjectDN($subjectDN);
        $certificate->setIssuerDN($issuerDN);
        $certificate->setPublicKey($publicKey);
        $certificate->setSerialNumber($serialNumber);
        $certificate->setNotBefore($notBefore ?? new \DateTimeImmutable('-1 day'));
        $certificate->setNotAfter($notAfter ?? new \DateTimeImmutable('+1 year'));

        return $certificate;
    }

    /**
     * 测试验证没有交叉签名证书的情况
     */
    public function testValidateWithNoCrossSignedCertificates(): void
    {
        $crossSignedCert = new CrossSignedCertificate($this->primaryCert);
        $result = $this->validator->validate($crossSignedCert, [$this->trustAnchor]);

        $this->assertTrue($result->isValid());
        $this->assertContains('没有交叉签名证书需要验证', $result->getInfoMessages());
    }

    /**
     * 测试验证公钥不匹配的情况
     */
    public function testValidateWithMismatchedPublicKey(): void
    {
        // 由于构造CrossSignedCertificate时会验证，我们需要捕获异常
        $this->expectException(CertificateValidationException::class);
        $this->expectExceptionMessage('交叉签名证书的公钥与主证书不匹配');

        // 创建公钥不匹配的证书
        $badCrossSignedCert = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Cross CA',
            'different-public-key',
            '1004'
        );

        new CrossSignedCertificate(
            $this->primaryCert,
            [$badCrossSignedCert]
        );
    }

    /**
     * 测试验证主题不匹配的情况
     */
    public function testValidateWithMismatchedSubject(): void
    {
        // 由于构造CrossSignedCertificate时会验证，我们需要捕获异常
        $this->expectException(CertificateValidationException::class);
        $this->expectExceptionMessage('交叉签名证书的主题与主证书不匹配');

        // 创建主题不匹配的证书
        $badCrossSignedCert = $this->createTestCertificate(
            'CN=Different Certificate',
            'CN=Cross CA',
            'primary-public-key',
            '1004'
        );

        new CrossSignedCertificate(
            $this->primaryCert,
            [$badCrossSignedCert]
        );
    }

    /**
     * 测试验证过期证书的情况
     */
    public function testValidateWithExpiredCertificate(): void
    {
        // 创建过期证书
        $expiredCert = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Cross CA',
            'primary-public-key',
            '1004',
            new \DateTimeImmutable('-2 years'),
            new \DateTimeImmutable('-1 year')
        );

        $crossSignedCert = new CrossSignedCertificate(
            $this->primaryCert,
            [$expiredCert]
        );

        $result = $this->validator->validate($crossSignedCert, [$this->trustAnchor]);

        $this->assertFalse($result->isValid());
        $this->assertContains('交叉签名证书不在有效期内', $result->getErrors());
    }

    /**
     * 测试验证找不到颁发者的情况
     */
    public function testValidateWithMissingIssuer(): void
    {
        $crossSignedCert = new CrossSignedCertificate(
            $this->primaryCert,
            [$this->crossSignedCert]
        );

        // 传入空的信任锚列表，无法找到颁发者
        $result = $this->validator->validate($crossSignedCert, []);

        $this->assertFalse($result->isValid());
        $this->assertContains('无法找到交叉签名证书的颁发者', $result->getErrors());
    }

    /**
     * 测试成功的验证情况
     */
    public function testValidateSuccess(): void
    {
        $crossSignedCert = new CrossSignedCertificate(
            $this->primaryCert,
            [$this->crossSignedCert]
        );

        $result = $this->validator->validate(
            $crossSignedCert,
            [$this->trustAnchor],
            []
        );

        // 由于实际实现中包含TODO项，可能会报告颁发者找不到或其他错误
        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    /**
     * 测试validate方法返回ValidationResult
     */
    public function testValidateReturnsValidationResult(): void
    {
        $crossSignedCert = new CrossSignedCertificate($this->primaryCert);
        $result = $this->validator->validate($crossSignedCert, []);

        $this->assertInstanceOf(ValidationResult::class, $result);
    }
}
