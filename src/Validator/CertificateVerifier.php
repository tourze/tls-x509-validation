<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Validator;

/**
 * 证书验证器抽象类
 *
 * 提供证书验证的基础结构，具体验证逻辑由子类实现
 */
abstract class CertificateVerifier
{
    /**
     * 验证证书链
     *
     * @param array<string>        $certificates 证书链，第一个为实体证书，后续为中间CA证书
     * @param array<string, mixed> $options      验证选项
     *
     * @return CertificateVerificationResult 验证结果
     */
    abstract public function verify(array $certificates, array $options = []): CertificateVerificationResult;
}
