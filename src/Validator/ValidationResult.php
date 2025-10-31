<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Validator;

/**
 * 验证结果 - 存储证书验证过程中的结果和消息
 */
class ValidationResult
{
    /**
     * @var bool 验证是否通过
     */
    private bool $valid = true;

    /**
     * @var array<string> 错误消息列表
     */
    private array $errors = [];

    /**
     * @var array<string> 警告消息列表
     */
    private array $warnings = [];

    /**
     * @var array<string> 信息消息列表
     */
    private array $infoMessages = [];

    /**
     * @var array<string> 成功消息列表
     */
    private array $successMessages = [];

    /**
     * 构造函数
     *
     * @param bool $valid 初始验证状态
     */
    public function __construct(bool $valid = true)
    {
        $this->valid = $valid;
    }

    /**
     * 获取验证状态
     *
     * @return bool 如果验证通过则返回true
     */
    public function isValid(): bool
    {
        return $this->valid && [] === $this->errors;
    }

    /**
     * 设置验证状态
     *
     * @param bool $valid 验证状态
     */
    public function setValid(bool $valid): void
    {
        $this->valid = $valid;
    }

    /**
     * 添加错误消息
     *
     * @param string $message 错误消息
     *
     * @return $this
     */
    public function addError(string $message): self
    {
        $this->errors[] = $message;
        $this->valid = false;

        return $this;
    }

    /**
     * 添加警告消息
     *
     * @param string $message 警告消息
     *
     * @return $this
     */
    public function addWarning(string $message): self
    {
        $this->warnings[] = $message;

        return $this;
    }

    /**
     * 添加信息消息
     *
     * @param string $message 信息消息
     *
     * @return $this
     */
    public function addInfo(string $message): self
    {
        $this->infoMessages[] = $message;

        return $this;
    }

    /**
     * 添加成功消息
     *
     * @param string $message 成功消息
     *
     * @return $this
     */
    public function addSuccess(string $message): self
    {
        $this->successMessages[] = $message;

        return $this;
    }

    /**
     * 获取错误消息列表
     *
     * @return array<string> 错误消息列表
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * 获取警告消息列表
     *
     * @return array<string> 警告消息列表
     */
    public function getWarnings(): array
    {
        return $this->warnings;
    }

    /**
     * 获取信息消息列表
     *
     * @return array<string> 信息消息列表
     */
    public function getInfoMessages(): array
    {
        return $this->infoMessages;
    }

    /**
     * 获取成功消息列表
     *
     * @return array<string> 成功消息列表
     */
    public function getSuccessMessages(): array
    {
        return $this->successMessages;
    }

    /**
     * 获取成功消息列表（别名方法）
     *
     * @return array<string> 成功消息列表
     */
    public function getSuccesses(): array
    {
        return $this->successMessages;
    }

    /**
     * 获取信息消息列表（别名方法）
     *
     * @return array<string> 信息消息列表
     */
    public function getInfos(): array
    {
        return $this->infoMessages;
    }

    /**
     * 获取所有消息
     *
     * @return array<string, array<string>> 所有消息按类型分组
     */
    public function getAllMessages(): array
    {
        return [
            'successes' => $this->successMessages,
            'infos' => $this->infoMessages,
            'warnings' => $this->warnings,
            'errors' => $this->errors,
        ];
    }

    /**
     * 清除所有消息并重置验证状态
     *
     * @return $this
     */
    public function clear(): self
    {
        $this->valid = true;
        $this->errors = [];
        $this->warnings = [];
        $this->infoMessages = [];
        $this->successMessages = [];

        return $this;
    }

    /**
     * 合并另一个验证结果
     *
     * @param ValidationResult $other 要合并的验证结果
     *
     * @return $this
     */
    public function merge(ValidationResult $other): self
    {
        $this->valid = $this->valid && $other->isValid();
        $this->errors = array_merge($this->errors, $other->getErrors());
        $this->warnings = array_merge($this->warnings, $other->getWarnings());
        $this->infoMessages = array_merge($this->infoMessages, $other->getInfoMessages());
        $this->successMessages = array_merge($this->successMessages, $other->getSuccessMessages());

        return $this;
    }
}
