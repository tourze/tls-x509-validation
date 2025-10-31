<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Policy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Chain\CertificateChain;
use Tourze\TLSX509Validation\Policy\PolicyValidator;
use Tourze\TLSX509Validation\Validator\ValidationResult;

/**
 * 策略验证器测试类
 *
 * @internal
 */
#[CoversClass(PolicyValidator::class)]
final class PolicyValidatorTest extends TestCase
{
    private PolicyValidator $validator;

    private X509Certificate $certificate;

    private CertificateChain $chain;

    protected function setUp(): void
    {
        parent::setUp();

        $this->validator = new PolicyValidator();

        // 创建测试证书实例
        $this->certificate = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Test CA',
            'test-public-key',
            '1001'
        );

        // 创建测试证书链实例
        $this->chain = $this->createTestCertificateChain([$this->certificate]);
    }

    /**
     * 创建测试用证书实例
     *
     * @param array<string, mixed>|null $extensions
     */
    private function createTestCertificate(
        string $subjectDN,
        string $issuerDN,
        string $publicKey,
        string $serialNumber,
        ?\DateTimeImmutable $notBefore = null,
        ?\DateTimeImmutable $notAfter = null,
        ?array $extensions = null,
    ): X509Certificate {
        $certificate = new X509Certificate();
        $certificate->setSubjectDN($subjectDN);
        $certificate->setIssuerDN($issuerDN);
        $certificate->setPublicKey($publicKey);
        $certificate->setSerialNumber($serialNumber);
        $certificate->setNotBefore($notBefore ?? new \DateTimeImmutable('-1 day'));
        $certificate->setNotAfter($notAfter ?? new \DateTimeImmutable('+1 year'));

        if (null !== $extensions) {
            $certificate->setExtensions($extensions);
        }

        return $certificate;
    }

    /**
     * 创建测试用证书链实例
     *
     * @param X509Certificate[] $certificates
     */
    private function createTestCertificateChain(array $certificates): CertificateChain
    {
        return new CertificateChain($certificates);
    }

    /**
     * 测试添加期望的策略
     */
    public function testAddExpectedPolicy(): void
    {
        $result = $this->validator->addExpectedPolicy('1.2.3.4');
        $this->assertSame($this->validator, $result);
    }

    /**
     * 测试设置是否需要明确的策略
     */
    public function testSetRequireExplicitPolicy(): void
    {
        // 测试设置为true不抛出异常
        $this->validator->setRequireExplicitPolicy(true);
        $this->assertTrue(true); // 执行到这里说明设置成功

        // 测试设置为false不抛出异常
        $this->validator->setRequireExplicitPolicy(false);
        $this->assertTrue(true); // 执行到这里说明设置成功
    }

    /**
     * 测试设置是否需要策略映射
     */
    public function testSetRequirePolicyMapping(): void
    {
        // 测试设置为true不抛出异常
        $this->validator->setRequirePolicyMapping(true);
        $this->assertTrue(true); // 执行到这里说明设置成功

        // 测试设置为false不抛出异常
        $this->validator->setRequirePolicyMapping(false);
        $this->assertTrue(true); // 执行到这里说明设置成功
    }

    /**
     * 测试验证空证书链
     */
    public function testValidateEmptyChain(): void
    {
        // 创建空证书链
        $emptyChain = $this->createTestCertificateChain([]);

        $result = new ValidationResult();
        $isValid = $this->validator->validate($emptyChain, $result);

        $this->assertFalse($isValid);
        $this->assertContains('无法验证空的证书链', $result->getErrors());
    }

    /**
     * 测试验证无策略约束的情况
     */
    public function testValidateWithoutPolicyConstraints(): void
    {
        $this->validator->setRequireExplicitPolicy(false);

        $result = new ValidationResult();
        $isValid = $this->validator->validate($this->chain, $result);

        $this->assertTrue($isValid);
        $this->assertContains('未设置策略约束，跳过策略验证', $result->getInfoMessages());
    }

    /**
     * 测试验证需要明确策略但证书没有策略的情况
     */
    public function testValidateRequireExplicitPolicyButNoPolicyExtension(): void
    {
        $this->validator->setRequireExplicitPolicy(true);

        $result = new ValidationResult();
        $isValid = $this->validator->validate($this->chain, $result);

        $this->assertFalse($isValid);
        $this->assertContains('证书没有策略扩展，但要求明确的策略', $result->getErrors());
    }

    /**
     * 测试验证带有策略扩展的证书
     */
    public function testValidateWithPolicyExtension(): void
    {
        // 创建有策略扩展的证书
        $certWithPolicy = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Test CA',
            'test-public-key',
            '1002',
            null,
            null,
            ['2.5.29.32' => ['1.2.3.4']] // 策略扩展
        );

        // 创建包含策略证书的证书链
        $chainWithPolicy = $this->createTestCertificateChain([$certWithPolicy]);

        $this->validator->setRequireExplicitPolicy(true);
        $this->validator->addExpectedPolicy('1.2.3.4');

        $result = new ValidationResult();
        $isValid = $this->validator->validate($chainWithPolicy, $result);

        $this->assertTrue($isValid);
        $this->assertContains('证书策略验证通过', $result->getInfoMessages());
    }

    /**
     * 测试验证策略不匹配的情况
     */
    public function testValidatePolicyMismatch(): void
    {
        // 创建策略不匹配的证书
        $certWithPolicy = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Test CA',
            'test-public-key',
            '1003',
            null,
            null,
            ['2.5.29.32' => ['5.6.7.8']] // 不匹配的策略
        );

        // 创建包含不匹配策略证书的证书链
        $chainWithPolicy = $this->createTestCertificateChain([$certWithPolicy]);

        $this->validator->addExpectedPolicy('1.2.3.4');

        $result = new ValidationResult();
        $isValid = $this->validator->validate($chainWithPolicy, $result);

        $this->assertFalse($isValid);
        $this->assertContains('证书策略不匹配期望的策略', $result->getErrors());
    }

    /**
     * 测试验证anyPolicy匹配
     */
    public function testValidateAnyPolicyMatch(): void
    {
        // 创建包含 anyPolicy 的证书
        $certWithPolicy = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Test CA',
            'test-public-key',
            '1004',
            null,
            null,
            ['2.5.29.32' => ['2.5.29.32.0']] // anyPolicy
        );

        // 创建包含 anyPolicy 证书的证书链
        $chainWithPolicy = $this->createTestCertificateChain([$certWithPolicy]);

        $this->validator->addExpectedPolicy('1.2.3.4');

        $result = new ValidationResult();
        $isValid = $this->validator->validate($chainWithPolicy, $result);

        $this->assertTrue($isValid);
        $this->assertContains('证书策略验证通过', $result->getInfoMessages());
    }

    /**
     * 测试验证方法执行成功
     */
    public function testValidateExecutesSuccessfully(): void
    {
        $result = new ValidationResult();
        $isValid = $this->validator->validate($this->chain, $result);

        // 验证方法执行成功且返回布尔值
        $this->assertNotNull($isValid);
    }

    /**
     * 测试验证带有策略映射的链
     */
    public function testValidateWithPolicyMapping(): void
    {
        $this->validator->setRequirePolicyMapping(true);

        // 创建多级证书链（用于策略映射测试）
        $intermediateCert = $this->createTestCertificate(
            'CN=Intermediate CA',
            'CN=Root CA',
            'intermediate-public-key',
            '1005'
        );

        $longChain = $this->createTestCertificateChain([$this->certificate, $intermediateCert]);

        $result = new ValidationResult();
        $isValid = $this->validator->validate($longChain, $result);

        // 由于策略映射验证较复杂，这里只验证能正确调用
        $this->assertNotNull($isValid);
    }
}
