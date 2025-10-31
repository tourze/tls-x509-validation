<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Policy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Validation\Policy\CertificatePolicy;

/**
 * @internal
 */
#[CoversClass(CertificatePolicy::class)]
final class CertificatePolicyTest extends TestCase
{
    public function testConstructorSetsProperties(): void
    {
        $policyOid = '1.2.3.4.5';
        $qualifier = 'test-qualifier';
        $policyInfoUri = 'https://example.com/policy';
        $displayText = 'Test Policy';

        $policy = new CertificatePolicy($policyOid, $qualifier, $policyInfoUri, $displayText);

        $this->assertEquals($policyOid, $policy->getPolicyOid());
        $this->assertEquals($qualifier, $policy->getQualifier());
        $this->assertEquals($policyInfoUri, $policy->getPolicyInfoUri());
        $this->assertEquals($displayText, $policy->getDisplayText());
    }

    public function testConstructorWithDefaultValues(): void
    {
        $policyOid = '1.2.3.4.5';

        $policy = new CertificatePolicy($policyOid);

        $this->assertEquals($policyOid, $policy->getPolicyOid());
        $this->assertNull($policy->getQualifier());
        $this->assertNull($policy->getPolicyInfoUri());
        $this->assertNull($policy->getDisplayText());
    }

    public function testMatchesWithSameOidReturnsTrue(): void
    {
        $policy1 = new CertificatePolicy('1.2.3.4.5');
        $policy2 = new CertificatePolicy('1.2.3.4.5');

        $this->assertTrue($policy1->matches($policy2));
    }

    public function testMatchesWithDifferentOidReturnsFalse(): void
    {
        $policy1 = new CertificatePolicy('1.2.3.4.5');
        $policy2 = new CertificatePolicy('5.4.3.2.1');

        $this->assertFalse($policy1->matches($policy2));
    }

    public function testMatchesWithAnyPolicyReturnsTrue(): void
    {
        $policy1 = new CertificatePolicy('1.2.3.4.5');
        $policy2 = new CertificatePolicy(CertificatePolicy::ANY_POLICY);

        $this->assertTrue($policy1->matches($policy2));
        $this->assertTrue($policy2->matches($policy1));
    }

    public function testAnyPolicyConstant(): void
    {
        $this->assertEquals('2.5.29.32.0', CertificatePolicy::ANY_POLICY);
    }

    public function testCreateAnyPolicyReturnsAnyPolicy(): void
    {
        $policy = CertificatePolicy::createAnyPolicy();

        $this->assertEquals(CertificatePolicy::ANY_POLICY, $policy->getPolicyOid());
    }
}
