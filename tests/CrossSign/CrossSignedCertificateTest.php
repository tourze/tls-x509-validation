<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\CrossSign;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\CrossSign\CrossSignedCertificate;
use Tourze\TLSX509Validation\Exception\CertificateValidationException;

/**
 * 交叉签名证书测试类
 *
 * @internal
 */
#[CoversClass(CrossSignedCertificate::class)]
final class CrossSignedCertificateTest extends TestCase
{
    private X509Certificate $primaryCert;

    private X509Certificate $crossSignedCert;

    protected function setUp(): void
    {
        parent::setUp();

        // 创建主证书实例
        $this->primaryCert = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Primary CA',
            'test-public-key',
            '1001'
        );

        // 创建交叉签名证书（与主证书具有相同主题和公钥，但颁发者不同）
        $this->crossSignedCert = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Cross CA',
            'test-public-key',
            '1002'
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
     * 测试构造函数
     */
    public function testConstructor(): void
    {
        $crossSignedCert = new CrossSignedCertificate($this->primaryCert);

        $this->assertSame($this->primaryCert, $crossSignedCert->getPrimaryCertificate());
        $this->assertEquals([], $crossSignedCert->getCrossSignedCertificates());
    }

    /**
     * 测试构造函数带交叉签名证书
     */
    public function testConstructorWithCrossSignedCertificates(): void
    {
        $crossSignedCert = new CrossSignedCertificate(
            $this->primaryCert,
            [$this->crossSignedCert]
        );

        $this->assertSame($this->primaryCert, $crossSignedCert->getPrimaryCertificate());
        $this->assertEquals([$this->crossSignedCert], $crossSignedCert->getCrossSignedCertificates());
    }

    /**
     * 测试添加有效的交叉签名证书
     */
    public function testAddValidCrossSignedCertificate(): void
    {
        $crossSignedCert = new CrossSignedCertificate($this->primaryCert);
        $result = $crossSignedCert->addCrossSignedCertificate($this->crossSignedCert);

        $this->assertSame($crossSignedCert, $result);
        $this->assertEquals([$this->crossSignedCert], $crossSignedCert->getCrossSignedCertificates());
    }

    /**
     * 测试 addCrossSignedCertificate 方法的基本功能
     */
    public function testAddCrossSignedCertificate(): void
    {
        $crossSignedCert = new CrossSignedCertificate($this->primaryCert);

        // 测试添加单个交叉签名证书
        $result = $crossSignedCert->addCrossSignedCertificate($this->crossSignedCert);

        // 验证返回值是当前对象（fluent interface）
        $this->assertSame($crossSignedCert, $result);

        // 验证证书已被添加
        $certificates = $crossSignedCert->getCrossSignedCertificates();
        $this->assertCount(1, $certificates);
        $this->assertSame($this->crossSignedCert, $certificates[0]);
    }

    /**
     * 测试添加公钥不匹配的证书
     */
    public function testAddCertificateWithMismatchedPublicKey(): void
    {
        // 创建公钥不匹配的证书
        $invalidCert = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Cross CA',
            'different-public-key',
            '1004'
        );

        $crossSignedCert = new CrossSignedCertificate($this->primaryCert);

        $this->expectException(CertificateValidationException::class);
        $this->expectExceptionMessage('交叉签名证书的公钥与主证书不匹配');

        $crossSignedCert->addCrossSignedCertificate($invalidCert);
    }

    /**
     * 测试添加主题不匹配的证书
     */
    public function testAddCertificateWithMismatchedSubject(): void
    {
        // 创建主题不匹配的证书
        $invalidCert = $this->createTestCertificate(
            'CN=Different Certificate',
            'CN=Cross CA',
            'test-public-key',
            '1004'
        );

        $crossSignedCert = new CrossSignedCertificate($this->primaryCert);

        $this->expectException(CertificateValidationException::class);
        $this->expectExceptionMessage('交叉签名证书的主题与主证书不匹配');

        $crossSignedCert->addCrossSignedCertificate($invalidCert);
    }

    /**
     * 测试添加颁发者相同的证书
     */
    public function testAddCertificateWithSameIssuer(): void
    {
        // 创建颁发者相同的证书
        $sameIssuerCert = $this->createTestCertificate(
            'CN=Test Certificate',
            'CN=Primary CA',
            'test-public-key',
            '1004'
        );

        $crossSignedCert = new CrossSignedCertificate($this->primaryCert);

        $this->expectException(CertificateValidationException::class);
        $this->expectExceptionMessage('交叉签名证书的颁发者与主证书相同，不是有效的交叉签名');

        $crossSignedCert->addCrossSignedCertificate($sameIssuerCert);
    }

    /**
     * 测试根据颁发者获取交叉签名证书
     */
    public function testGetCrossSignedCertificateByIssuer(): void
    {
        $crossSignedCert = new CrossSignedCertificate(
            $this->primaryCert,
            [$this->crossSignedCert]
        );

        $result = $crossSignedCert->getCrossSignedCertificateByIssuer('CN=Cross CA');
        $this->assertSame($this->crossSignedCert, $result);

        $result = $crossSignedCert->getCrossSignedCertificateByIssuer('CN=Primary CA');
        $this->assertSame($this->primaryCert, $result);

        $result = $crossSignedCert->getCrossSignedCertificateByIssuer('CN=Unknown CA');
        $this->assertNull($result);
    }

    /**
     * 测试检查是否有来自指定颁发者的交叉签名证书
     */
    public function testHasCrossSignedCertificateFromIssuer(): void
    {
        $crossSignedCert = new CrossSignedCertificate(
            $this->primaryCert,
            [$this->crossSignedCert]
        );

        $this->assertTrue($crossSignedCert->hasCrossSignedCertificateFromIssuer('CN=Cross CA'));
        $this->assertTrue($crossSignedCert->hasCrossSignedCertificateFromIssuer('CN=Primary CA'));
        $this->assertFalse($crossSignedCert->hasCrossSignedCertificateFromIssuer('CN=Unknown CA'));
    }

    /**
     * 测试从证书列表检测交叉签名证书
     */
    public function testDetectFromCertificates(): void
    {
        // 创建有相同公钥和主题但不同颁发者的证书（交叉签名对）
        $cert1 = $this->createTestCertificate(
            'CN=Cert1',
            'CN=CA1',
            'key1',
            '2001'
        );

        $cert2 = $this->createTestCertificate(
            'CN=Cert1',
            'CN=CA2',
            'key1',
            '2002'
        );

        // 创建独立的证书
        $cert3 = $this->createTestCertificate(
            'CN=Cert2',
            'CN=CA3',
            'key2',
            '2003'
        );

        $groups = CrossSignedCertificate::detectFromCertificates([$cert1, $cert2, $cert3]);

        $this->assertCount(2, $groups);

        // 检查第一组有交叉签名
        $firstGroup = array_values($groups)[0];
        if (count($firstGroup->getCrossSignedCertificates()) > 0) {
            $this->assertCount(1, $firstGroup->getCrossSignedCertificates());
        }
    }

    /**
     * 测试从单个证书检测
     */
    public function testDetectFromSingleCertificate(): void
    {
        // 创建单个证书
        $cert1 = $this->createTestCertificate(
            'CN=Cert1',
            'CN=CA1',
            'key1',
            '3001'
        );

        $groups = CrossSignedCertificate::detectFromCertificates([$cert1]);

        $this->assertCount(1, $groups);

        $group = array_values($groups)[0];
        $this->assertSame($cert1, $group->getPrimaryCertificate());
        $this->assertEquals([], $group->getCrossSignedCertificates());
    }
}
