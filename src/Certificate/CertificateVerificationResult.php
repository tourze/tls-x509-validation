<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Certificate;

/**
 * 证书验证结果类
 */
class CertificateVerificationResult
{
    /**
     * 构造函数
     *
     * @param bool   $valid   验证结果是否有效
     * @param string $message 验证结果信息
     */
    public function __construct(
        private readonly bool $valid,
        private readonly string $message,
    ) {
    }

    /**
     * 获取验证结果是否有效
     *
     * @return bool 验证结果是否有效
     */
    public function isValid(): bool
    {
        return $this->valid;
    }

    /**
     * 获取验证结果信息
     *
     * @return string 验证结果信息
     */
    public function getMessage(): string
    {
        return $this->message;
    }
}
