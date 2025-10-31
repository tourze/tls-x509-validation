<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Exception;

/**
 * 证书验证异常 - 当证书验证过程中发生错误时抛出
 */
class CertificateValidationException extends \Exception
{
    /**
     * 构造函数
     *
     * @param string          $message                 异常消息
     * @param int             $code                    异常代码
     * @param \Throwable|null $previous                前一个异常
     * @param string|null     $certificateSubject      证书主题
     * @param string|null     $certificateSerialNumber 证书序列号
     */
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        private readonly ?string $certificateSubject = null,
        private readonly ?string $certificateSerialNumber = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * 获取证书主题
     */
    public function getCertificateSubject(): ?string
    {
        return $this->certificateSubject;
    }

    /**
     * 获取证书序列号
     */
    public function getCertificateSerialNumber(): ?string
    {
        return $this->certificateSerialNumber;
    }

    /**
     * 创建证书过期异常
     *
     * @param string      $expirationDate          过期日期
     * @param string|null $certificateSubject      证书主题
     * @param string|null $certificateSerialNumber 证书序列号
     */
    public static function certificateExpired(
        string $expirationDate,
        ?string $certificateSubject = null,
        ?string $certificateSerialNumber = null,
    ): self {
        $message = "证书已过期，过期时间: {$expirationDate}";

        return new self($message, 1001, null, $certificateSubject, $certificateSerialNumber);
    }

    /**
     * 创建证书尚未生效异常
     *
     * @param string      $notBeforeDate           生效日期
     * @param string|null $certificateSubject      证书主题
     * @param string|null $certificateSerialNumber 证书序列号
     */
    public static function certificateNotYetValid(
        string $notBeforeDate,
        ?string $certificateSubject = null,
        ?string $certificateSerialNumber = null,
    ): self {
        $message = "证书尚未生效，生效时间: {$notBeforeDate}";

        return new self($message, 1002, null, $certificateSubject, $certificateSerialNumber);
    }

    /**
     * 创建证书签名验证失败异常
     *
     * @param string|null $certificateSubject      证书主题
     * @param string|null $certificateSerialNumber 证书序列号
     */
    public static function signatureVerificationFailed(
        ?string $certificateSubject = null,
        ?string $certificateSerialNumber = null,
    ): self {
        $message = '证书签名验证失败';

        return new self($message, 1003, null, $certificateSubject, $certificateSerialNumber);
    }

    /**
     * 创建找不到颁发者证书异常
     *
     * @param string      $issuerDN                颁发者名称
     * @param string|null $certificateSubject      证书主题
     * @param string|null $certificateSerialNumber 证书序列号
     */
    public static function issuerCertificateNotFound(
        string $issuerDN,
        ?string $certificateSubject = null,
        ?string $certificateSerialNumber = null,
    ): self {
        $message = "无法找到颁发者证书。颁发者: {$issuerDN}";
        if (null !== $certificateSubject) {
            $message .= ", 主题: {$certificateSubject}";
        }
        if (null !== $certificateSerialNumber) {
            $message .= ", 序列号: {$certificateSerialNumber}";
        }

        return new self($message, 1004, null, $certificateSubject, $certificateSerialNumber);
    }

    /**
     * 创建证书链不完整异常
     *
     * @param string|null $certificateSubject      证书主题
     * @param string|null $certificateSerialNumber 证书序列号
     */
    public static function incompleteCertificateChain(
        ?string $certificateSubject = null,
        ?string $certificateSerialNumber = null,
    ): self {
        $message = '证书链不完整';
        if (null !== $certificateSubject) {
            $message .= "。主题: {$certificateSubject}";
        }
        if (null !== $certificateSerialNumber) {
            $message .= ", 序列号: {$certificateSerialNumber}";
        }

        return new self($message, 1005, null, $certificateSubject, $certificateSerialNumber);
    }

    /**
     * 创建证书用途无效异常
     *
     * @param string      $expectedUsage           预期用途
     * @param string|null $certificateSubject      证书主题
     * @param string|null $certificateSerialNumber 证书序列号
     */
    public static function invalidKeyUsage(
        string $expectedUsage,
        ?string $certificateSubject = null,
        ?string $certificateSerialNumber = null,
    ): self {
        $message = "证书用途无效，期望用途: {$expectedUsage}";

        return new self($message, 1006, null, $certificateSubject, $certificateSerialNumber);
    }
}
