<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Validation\Validator\ValidationOptions;

/**
 * @internal
 */
#[CoversClass(ValidationOptions::class)]
final class ValidationOptionsTest extends TestCase
{
    private ValidationOptions $options;

    protected function setUp(): void
    {
        parent::setUp();

        $this->options = new ValidationOptions();
    }

    public function testDefaultValues(): void
    {
        $this->assertTrue($this->options->isValidateCertificateChain());
        $this->assertTrue($this->options->isValidateKeyUsage());
        $this->assertTrue($this->options->isValidateExtendedKeyUsage());
        $this->assertTrue($this->options->isRequireCompleteCertificateChain());
        $this->assertFalse($this->options->isAllowSelfSignedCertificates());
        $this->assertFalse($this->options->isCheckRevocation());
        $this->assertTrue($this->options->isValidateSubjectAlternativeName());
        $this->assertEmpty($this->options->getExpectedKeyUsage());
        $this->assertEmpty($this->options->getExpectedExtendedKeyUsage());
        $this->assertNull($this->options->getExpectedHostname());
    }

    public function testSetValidateCertificateChain(): void
    {
        $this->options->setValidateCertificateChain(false);
        $this->assertFalse($this->options->isValidateCertificateChain());
    }

    public function testSetValidateKeyUsage(): void
    {
        $this->options->setValidateKeyUsage(false);
        $this->assertFalse($this->options->isValidateKeyUsage());
    }

    public function testSetValidateExtendedKeyUsage(): void
    {
        $this->options->setValidateExtendedKeyUsage(false);
        $this->assertFalse($this->options->isValidateExtendedKeyUsage());
    }

    public function testSetRequireCompleteCertificateChain(): void
    {
        $this->options->setRequireCompleteCertificateChain(false);
        $this->assertFalse($this->options->isRequireCompleteCertificateChain());
    }

    public function testSetAllowSelfSignedCertificates(): void
    {
        $this->options->setAllowSelfSignedCertificates(true);
        $this->assertTrue($this->options->isAllowSelfSignedCertificates());
    }

    public function testSetExpectedKeyUsage(): void
    {
        $expectedUsage = ['digitalSignature', 'nonRepudiation'];
        $this->options->setExpectedKeyUsage($expectedUsage);
        $this->assertEquals($expectedUsage, $this->options->getExpectedKeyUsage());
    }

    public function testSetExpectedExtendedKeyUsage(): void
    {
        $expectedUsage = ['serverAuth', 'clientAuth'];
        $this->options->setExpectedExtendedKeyUsage($expectedUsage);
        $this->assertEquals($expectedUsage, $this->options->getExpectedExtendedKeyUsage());
    }

    public function testSetCheckRevocation(): void
    {
        $this->options->setCheckRevocation(true);
        $this->assertTrue($this->options->isCheckRevocation());
    }

    public function testSetValidateSubjectAlternativeName(): void
    {
        $this->options->setValidateSubjectAlternativeName(false);
        $this->assertFalse($this->options->isValidateSubjectAlternativeName());
    }

    public function testSetExpectedHostname(): void
    {
        $hostname = 'example.com';
        $this->options->setExpectedHostname($hostname);
        $this->assertEquals($hostname, $this->options->getExpectedHostname());
    }

    public function testSetterMethods(): void
    {
        $this->options->setValidateCertificateChain(false);
        $this->options->setValidateKeyUsage(false);
        $this->options->setExpectedHostname('example.com');

        $this->assertFalse($this->options->isValidateCertificateChain());
        $this->assertFalse($this->options->isValidateKeyUsage());
        $this->assertEquals('example.com', $this->options->getExpectedHostname());
    }
}
