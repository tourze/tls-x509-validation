<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSX509Validation\Exception\CertificateValidationException;

/**
 * @internal
 */
#[CoversClass(CertificateValidationException::class)]
final class CertificateValidationExceptionTest extends AbstractExceptionTestCase
{
    public function testIssuerCertificateNotFoundCreatesCorrectException(): void
    {
        $issuerDN = 'CN=Issuer CA';
        $subjectDN = 'CN=Test Certificate';
        $serialNumber = '12345678';

        $exception = CertificateValidationException::issuerCertificateNotFound($issuerDN, $subjectDN, $serialNumber);

        $expectedMessage = '无法找到颁发者证书。颁发者: CN=Issuer CA, 主题: CN=Test Certificate, 序列号: 12345678';
        $this->assertEquals($expectedMessage, $exception->getMessage());
        $this->assertInstanceOf(CertificateValidationException::class, $exception);
    }

    public function testIncompleteCertificateChainCreatesCorrectException(): void
    {
        $subjectDN = 'CN=Test Certificate';
        $serialNumber = '12345678';

        $exception = CertificateValidationException::incompleteCertificateChain($subjectDN, $serialNumber);

        $expectedMessage = '证书链不完整。主题: CN=Test Certificate, 序列号: 12345678';
        $this->assertEquals($expectedMessage, $exception->getMessage());
        $this->assertInstanceOf(CertificateValidationException::class, $exception);
    }
}
