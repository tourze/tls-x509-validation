<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Policy;

use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Chain\CertificateChain;
use Tourze\TLSX509Validation\Exception\CertificateValidationException;
use Tourze\TLSX509Validation\Validator\ValidationResult;

/**
 * 策略验证器 - 验证证书策略约束
 */
class PolicyValidator
{
    /**
     * @var string[] 期望的策略OID列表
     */
    private array $expectedPolicies = [];

    /**
     * @var bool 是否需要明确的策略
     */
    private bool $requireExplicitPolicy = true;

    /**
     * @var bool 是否需要策略映射
     */
    private bool $requirePolicyMapping = false;

    /**
     * 构造函数
     */
    public function __construct()
    {
    }

    /**
     * 添加期望的策略
     *
     * @param string $policyOid 策略OID
     *
     * @return $this
     */
    public function addExpectedPolicy(string $policyOid): self
    {
        $this->expectedPolicies[] = $policyOid;

        return $this;
    }

    /**
     * 设置是否需要明确的策略
     */
    public function setRequireExplicitPolicy(bool $requireExplicitPolicy): void
    {
        $this->requireExplicitPolicy = $requireExplicitPolicy;
    }

    /**
     * 设置是否需要策略映射
     */
    public function setRequirePolicyMapping(bool $requirePolicyMapping): void
    {
        $this->requirePolicyMapping = $requirePolicyMapping;
    }

    /**
     * 验证证书链的策略约束
     *
     * @param CertificateChain $chain  要验证的证书链
     * @param ValidationResult $result 验证结果
     *
     * @return bool 如果验证通过则返回true
     */
    public function validate(CertificateChain $chain, ValidationResult $result): bool
    {
        if (!$this->validateChainNotEmpty($chain, $result)) {
            return false;
        }

        try {
            $leafCertificate = $chain->getEndEntityCertificate();

            if ($this->shouldSkipPolicyValidation($result)) {
                return true;
            }

            if (null === $leafCertificate) {
                $result->addError('无法获取终端实体证书');

                return false;
            }

            $leafPolicies = $this->getCertificatePolicies($leafCertificate);

            if (!$this->validateExplicitPolicyRequirement($leafPolicies, $result)) {
                return false;
            }

            if (!$this->validatePolicyMatching($leafPolicies, $result)) {
                return false;
            }

            if (!$this->validatePolicyMappingIfRequired($chain, $result)) {
                return false;
            }

            $result->addInfo('证书策略验证通过');

            return true;
        } catch (CertificateValidationException $e) {
            $result->addError('策略验证失败: ' . $e->getMessage());

            return false;
        } catch (\Throwable $e) {
            $result->addError('策略验证时发生未预期错误: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * 验证证书链不为空
     */
    private function validateChainNotEmpty(CertificateChain $chain, ValidationResult $result): bool
    {
        if ($chain->isEmpty()) {
            $result->addError('无法验证空的证书链');

            return false;
        }

        return true;
    }

    /**
     * 检查是否应该跳过策略验证
     */
    private function shouldSkipPolicyValidation(ValidationResult $result): bool
    {
        if ([] === $this->expectedPolicies && !$this->requireExplicitPolicy) {
            $result->addInfo('未设置策略约束，跳过策略验证');

            return true;
        }

        return false;
    }

    /**
     * 验证明确策略要求
     *
     * @param CertificatePolicy[] $leafPolicies
     */
    private function validateExplicitPolicyRequirement(array $leafPolicies, ValidationResult $result): bool
    {
        if ($this->requireExplicitPolicy && [] === $leafPolicies) {
            $result->addError('证书没有策略扩展，但要求明确的策略');

            return false;
        }

        return true;
    }

    /**
     * 验证策略匹配
     *
     * @param CertificatePolicy[] $leafPolicies
     */
    private function validatePolicyMatching(array $leafPolicies, ValidationResult $result): bool
    {
        if ([] === $this->expectedPolicies) {
            return true;
        }

        foreach ($leafPolicies as $policy) {
            if ($this->isPolicyMatched($policy)) {
                return true;
            }
        }

        $result->addError('证书策略不匹配期望的策略');

        return false;
    }

    /**
     * 检查策略是否匹配
     */
    private function isPolicyMatched(CertificatePolicy $policy): bool
    {
        if (CertificatePolicy::ANY_POLICY === $policy->getPolicyOid()) {
            return true;
        }

        foreach ($this->expectedPolicies as $expectedPolicyOid) {
            if ($policy->getPolicyOid() === $expectedPolicyOid) {
                return true;
            }
        }

        return false;
    }

    /**
     * 如果需要，验证策略映射
     */
    private function validatePolicyMappingIfRequired(CertificateChain $chain, ValidationResult $result): bool
    {
        if ($this->requirePolicyMapping && $chain->getLength() > 1) {
            return $this->validatePolicyMapping($chain, $result);
        }

        return true;
    }

    /**
     * 从证书中提取证书策略
     *
     * @return array<CertificatePolicy>
     */
    private function getCertificatePolicies(X509Certificate $certificate): array
    {
        // OID: 2.5.29.32 = Certificate Policies
        if (!$certificate->hasExtension('2.5.29.32')) {
            return [];
        }

        $policyExtension = $certificate->getExtension('2.5.29.32');

        if (!is_array($policyExtension)) {
            return [];
        }

        return $this->extractPoliciesFromExtension($policyExtension);
    }

    /**
     * 从证书策略扩展中提取策略对象
     *
     * @param mixed[] $policyExtension
     * @return array<CertificatePolicy>
     */
    private function extractPoliciesFromExtension(array $policyExtension): array
    {
        $policies = [];

        foreach ($policyExtension as $policyData) {
            $policy = $this->createPolicyFromData($policyData);
            if (null !== $policy) {
                $policies[] = $policy;
            }
        }

        return $policies;
    }

    /**
     * 从策略数据创建策略对象
     */
    private function createPolicyFromData(mixed $policyData): ?CertificatePolicy
    {
        if (is_string($policyData)) {
            return new CertificatePolicy($policyData);
        }

        if (is_array($policyData) && isset($policyData['oid'])) {
            return new CertificatePolicy($policyData['oid']);
        }

        return null;
    }

    /**
     * 验证策略映射
     *
     * @param CertificateChain $chain  证书链
     * @param ValidationResult $result 验证结果
     *
     * @return bool 如果验证通过则返回true
     */
    private function validatePolicyMapping(CertificateChain $chain, ValidationResult $result): bool
    {
        $certificates = $chain->getCertificates();

        for ($i = 0; $i < count($certificates) - 1; ++$i) {
            if (!$this->validateCertificatePairPolicies($certificates[$i], $certificates[$i + 1], $result)) {
                return false;
            }
        }

        $result->addInfo('证书链的策略映射验证通过');

        return true;
    }

    /**
     * 验证证书对的策略兼容性
     */
    private function validateCertificatePairPolicies(
        X509Certificate $current,
        X509Certificate $issuer,
        ValidationResult $result,
    ): bool {
        $currentPolicies = $this->getCertificatePolicies($current);
        $issuerPolicies = $this->getCertificatePolicies($issuer);

        if ([] === $currentPolicies) {
            return true;
        }

        if ([] === $issuerPolicies) {
            $result->addError('证书链中的策略不一致：颁发者没有策略');

            return false;
        }

        return $this->validatePolicyCompatibility($currentPolicies, $issuerPolicies, $result);
    }

    /**
     * 验证策略兼容性
     *
     * @param array<CertificatePolicy> $currentPolicies
     * @param array<CertificatePolicy> $issuerPolicies
     */
    private function validatePolicyCompatibility(
        array $currentPolicies,
        array $issuerPolicies,
        ValidationResult $result,
    ): bool {
        foreach ($currentPolicies as $currentPolicy) {
            if (!$this->isPolicyCompatibleWithIssuerPolicies($currentPolicy, $issuerPolicies)) {
                $result->addError('证书链中的策略不一致：策略 ' . $currentPolicy->getPolicyOid() . ' 不兼容');

                return false;
            }
        }

        return true;
    }

    /**
     * 检查策略是否与颁发者策略兼容
     *
     * @param array<CertificatePolicy> $issuerPolicies
     */
    private function isPolicyCompatibleWithIssuerPolicies(
        CertificatePolicy $currentPolicy,
        array $issuerPolicies,
    ): bool {
        foreach ($issuerPolicies as $issuerPolicy) {
            if ($currentPolicy->matches($issuerPolicy)) {
                return true;
            }
        }

        return false;
    }
}
