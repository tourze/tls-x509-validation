<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Chain;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Chain\CertificateChain;
use Tourze\TLSX509Validation\Exception\CertificateValidationException;

/**
 * 证书链测试类
 *
 * @internal
 */
#[CoversClass(CertificateChain::class)]
final class CertificateChainTest extends TestCase
{
    private X509Certificate $cert1;

    private X509Certificate $cert2;

    private X509Certificate $cert3;

    protected function setUp(): void
    {
        parent::setUp();

        // 创建真实的 X509Certificate 实例替代Mock
        // 使用真实的证书实例可以更好地测试证书链的功能，同时符合PHPStan的要求
        $this->cert1 = $this->createTestCertificate(
            'CN=End Entity',
            'CN=Intermediate CA',
            '1001'
        );

        $this->cert2 = $this->createTestCertificate(
            'CN=Intermediate CA',
            'CN=Root CA',
            '1002'
        );

        // 根CA证书（自签名）
        $this->cert3 = $this->createTestCertificate(
            'CN=Root CA',
            'CN=Root CA',
            '1003'
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
     * 测试构造函数
     */
    public function testConstructor(): void
    {
        $chain = new CertificateChain();
        $this->assertTrue($chain->isEmpty());
        $this->assertEquals(0, $chain->getLength());

        $chain = new CertificateChain([$this->cert1]);
        $this->assertFalse($chain->isEmpty());
        $this->assertEquals(1, $chain->getLength());
    }

    /**
     * 测试添加证书
     */
    public function testAddCertificate(): void
    {
        $chain = new CertificateChain();
        $result = $chain->addCertificate($this->cert1);

        $this->assertSame($chain, $result);
        $this->assertEquals(1, $chain->getLength());
        $this->assertFalse($chain->isEmpty());
    }

    /**
     * 测试获取证书列表
     */
    public function testGetCertificates(): void
    {
        $certificates = [$this->cert1, $this->cert2];
        $chain = new CertificateChain($certificates);

        $this->assertEquals($certificates, $chain->getCertificates());
    }

    /**
     * 测试获取链长度
     */
    public function testGetLength(): void
    {
        $chain = new CertificateChain();
        $this->assertEquals(0, $chain->getLength());

        $chain->addCertificate($this->cert1);
        $this->assertEquals(1, $chain->getLength());

        $chain->addCertificate($this->cert2);
        $this->assertEquals(2, $chain->getLength());
    }

    /**
     * 测试检查是否为空
     */
    public function testIsEmpty(): void
    {
        $chain = new CertificateChain();
        $this->assertTrue($chain->isEmpty());

        $chain->addCertificate($this->cert1);
        $this->assertFalse($chain->isEmpty());
    }

    /**
     * 测试获取终端实体证书
     */
    public function testGetEndEntityCertificate(): void
    {
        $chain = new CertificateChain();
        $endEntity = $chain->getEndEntityCertificate();
        $this->assertNull($endEntity);

        $chain->addCertificate($this->cert1);
        $this->assertSame($this->cert1, $chain->getEndEntityCertificate());

        $chain->addCertificate($this->cert2);
        $this->assertSame($this->cert1, $chain->getEndEntityCertificate());
    }

    /**
     * 测试获取信任锚证书
     */
    public function testGetTrustAnchorCertificate(): void
    {
        $chain = new CertificateChain();
        $this->assertNull($chain->getTrustAnchorCertificate());

        $chain->addCertificate($this->cert1);
        $this->assertSame($this->cert1, $chain->getTrustAnchorCertificate());

        $chain->addCertificate($this->cert2);
        $this->assertSame($this->cert2, $chain->getTrustAnchorCertificate());
    }

    /**
     * 测试获取中间证书
     */
    public function testGetIntermediateCertificates(): void
    {
        $chain = new CertificateChain();
        $this->assertEquals([], $chain->getIntermediateCertificates());

        // 只有一个证书，没有中间证书
        $chain->addCertificate($this->cert1);
        $this->assertEquals([], $chain->getIntermediateCertificates());

        // 只有两个证书，没有中间证书
        $chain->addCertificate($this->cert2);
        $this->assertEquals([], $chain->getIntermediateCertificates());

        // 三个证书，中间有一个
        $chain->addCertificate($this->cert3);
        $this->assertEquals([$this->cert2], $chain->getIntermediateCertificates());
    }

    /**
     * 测试验证颁发者主题链
     */
    public function testValidateIssuerSubjectChain(): void
    {
        $chain = new CertificateChain();
        $this->assertTrue($chain->validateIssuerSubjectChain());

        // 单个证书
        $chain->addCertificate($this->cert1);
        $this->assertTrue($chain->validateIssuerSubjectChain());

        // 正确的链
        $chain->addCertificate($this->cert2);
        $this->assertTrue($chain->validateIssuerSubjectChain());

        // 创建不正确的链
        // 创建一个主题/颁发者不匹配的证书来验证链验证逻辑的正确性
        $wrongCert = $this->createTestCertificate(
            'CN=Wrong CA',
            'CN=Another CA',
            '9999'
        );

        $wrongChain = new CertificateChain([$this->cert1, $wrongCert]);
        $this->assertFalse($wrongChain->validateIssuerSubjectChain());
    }

    /**
     * 测试验证空链完整性
     */
    public function testVerifyChainIntegrityWithEmptyChain(): void
    {
        $chain = new CertificateChain();

        $this->expectException(CertificateValidationException::class);
        $this->expectExceptionMessage('证书链为空');

        $chain->verifyChainIntegrity();
    }

    /**
     * 测试验证链完整性成功
     */
    public function testVerifyChainIntegritySuccess(): void
    {
        $chain = new CertificateChain([$this->cert1, $this->cert2, $this->cert3]);

        $result = $chain->verifyChainIntegrity(false); // 跳过签名验证
        $this->assertTrue($result);
    }
}
