<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Validator;

/**
 * 证书验证结果类
 *
 * 用于存储证书验证是否成功以及相关的错误消息
 */
class CertificateVerificationResult
{
    /**
     * @param bool   $isValid 验证是否成功
     * @param string $message 验证结果消息
     */
    public function __construct(
        private readonly bool $isValid,
        private readonly string $message = '',
    ) {
    }

    /**
     * 检查证书验证是否成功
     */
    public function isValid(): bool
    {
        return $this->isValid;
    }

    /**
     * 获取验证结果消息
     */
    public function getMessage(): string
    {
        return $this->message;
    }

    /**
     * 创建一个带有错误消息的新验证结果对象
     *
     * @param string $errorMessage 错误消息
     */
    public function withError(string $errorMessage): self
    {
        return new self(false, $errorMessage);
    }
}
