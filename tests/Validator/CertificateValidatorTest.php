<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Validator\CertificateValidator;
use Tourze\TLSX509Validation\Validator\ValidationResult;

/**
 * 证书验证器测试类
 *
 * @internal
 */
#[CoversClass(CertificateValidator::class)]
final class CertificateValidatorTest extends TestCase
{
    private CertificateValidator $validator;

    private X509Certificate $certificate;

    private X509Certificate $trustAnchor;

    protected function setUp(): void
    {
        parent::setUp();

        // 创建真实的信任锚证书实例
        $this->trustAnchor = $this->createTestCertificate(
            'CN=Trust Anchor Root CA',
            'CN=Trust Anchor Root CA', // 自签名
            '100'
        );

        // 直接实例化验证器
        $this->validator = new CertificateValidator();
        // 添加信任锚
        $this->validator->addTrustAnchor($this->trustAnchor);

        // 创建真实的待验证的证书实例
        $this->certificate = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Trust Anchor Root CA',
            '200'
        );
    }

    /**
     * 创建测试用的证书实例
     *
     * @param string $subjectDN   主题专有名称
     * @param string $issuerDN    颁发者专有名称
     * @param string $serialNumber 序列号
     *
     * @return X509Certificate 证书实例
     */
    private function createTestCertificate(string $subjectDN, string $issuerDN, string $serialNumber): X509Certificate
    {
        $certificate = new X509Certificate();
        $certificate->setSubjectDN($subjectDN);
        $certificate->setIssuerDN($issuerDN);
        $certificate->setSerialNumber($serialNumber);

        // 设置基本的证书属性
        $certificate->setVersion(3);
        $certificate->setSignatureAlgorithm('sha256WithRSAEncryption');

        // 设置有效期（当前时间前后一年）
        $now = new \DateTimeImmutable();
        $certificate->setNotBefore($now->modify('-1 year'));
        $certificate->setNotAfter($now->modify('+1 year'));

        return $certificate;
    }

    /**
     * 测试验证方法返回ValidationResult
     */
    public function testValidateReturnsValidationResult(): void
    {
        $result = $this->validator->validate($this->certificate);

        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    /**
     * 测试验证带中间证书
     */
    public function testValidateWithIntermediateCertificates(): void
    {
        // 创建真实的中间证书实例
        $intermediateCert = $this->createTestCertificate(
            'CN=Intermediate CA',
            'CN=Trust Anchor Root CA',
            '150'
        );
        $result = $this->validator->validate($this->certificate, [$intermediateCert]);

        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    /**
     * 测试验证空的中间证书数组
     */
    public function testValidateWithEmptyIntermediateCertificates(): void
    {
        $result = $this->validator->validate($this->certificate, []);

        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    /**
     * 测试添加信任锚证书
     */
    public function testAddTrustAnchor(): void
    {
        // 创建一个信任锚证书
        $trustAnchor = $this->createTestCertificate(
            'CN=Trust Root CA',
            'CN=Trust Root CA',  // 自签名根证书
            '200'
        );

        // 测试添加信任锚并返回链式调用对象
        $result = $this->validator->addTrustAnchor($trustAnchor);
        $this->assertSame($this->validator, $result);

        // 创建另一个信任锚证书
        $anotherTrustAnchor = $this->createTestCertificate(
            'CN=Another Trust Root CA',
            'CN=Another Trust Root CA',  // 自签名根证书
            '201'
        );

        // 测试可以添加多个信任锚
        $result2 = $this->validator->addTrustAnchor($anotherTrustAnchor);
        $this->assertSame($this->validator, $result2);
    }
}
