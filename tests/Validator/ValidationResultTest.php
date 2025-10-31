<?php

declare(strict_types=1);

namespace Tourze\TLSX509Validation\Tests\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSX509Validation\Validator\ValidationResult;

/**
 * @internal
 */
#[CoversClass(ValidationResult::class)]
final class ValidationResultTest extends TestCase
{
    private ValidationResult $result;

    protected function setUp(): void
    {
        parent::setUp();

        $this->result = new ValidationResult();
    }

    public function testAddSuccessAddsSuccessMessage(): void
    {
        $this->result->addSuccess('Test success');
        $this->assertCount(1, $this->result->getSuccesses());
        $this->assertEquals(['Test success'], $this->result->getSuccesses());
    }

    public function testAddInfoAddsInfoMessage(): void
    {
        $this->result->addInfo('Test info');
        $this->assertCount(1, $this->result->getInfos());
        $this->assertEquals(['Test info'], $this->result->getInfos());
    }

    public function testAddWarningAddsWarningMessage(): void
    {
        $this->result->addWarning('Test warning');
        $this->assertCount(1, $this->result->getWarnings());
        $this->assertEquals(['Test warning'], $this->result->getWarnings());
    }

    public function testAddErrorAddsErrorMessage(): void
    {
        $this->result->addError('Test error');
        $this->assertCount(1, $this->result->getErrors());
        $this->assertEquals(['Test error'], $this->result->getErrors());
    }

    public function testIsValidReturnsTrueWhenNoErrors(): void
    {
        $this->result->addSuccess('Test success');
        $this->result->addInfo('Test info');
        $this->result->addWarning('Test warning');
        $this->assertTrue($this->result->isValid());
    }

    public function testIsValidReturnsFalseWhenErrors(): void
    {
        $this->result->addError('Test error');
        $this->assertFalse($this->result->isValid());
    }

    public function testMergeCombinesMessages(): void
    {
        $this->result->addSuccess('Success 1');
        $this->result->addInfo('Info 1');

        $otherResult = new ValidationResult();
        $otherResult->addSuccess('Success 2');
        $otherResult->addWarning('Warning 2');
        $otherResult->addError('Error 2');

        $this->result->merge($otherResult);

        $this->assertEquals(['Success 1', 'Success 2'], $this->result->getSuccesses());
        $this->assertEquals(['Info 1'], $this->result->getInfos());
        $this->assertEquals(['Warning 2'], $this->result->getWarnings());
        $this->assertEquals(['Error 2'], $this->result->getErrors());
        $this->assertFalse($this->result->isValid());
    }

    public function testGetAllMessagesReturnsAllMessages(): void
    {
        $this->result->addSuccess('Test success');
        $this->result->addInfo('Test info');
        $this->result->addWarning('Test warning');
        $this->result->addError('Test error');

        $expected = [
            'successes' => ['Test success'],
            'infos' => ['Test info'],
            'warnings' => ['Test warning'],
            'errors' => ['Test error'],
        ];

        $this->assertEquals($expected, $this->result->getAllMessages());
    }

    public function testClearRemovesAllMessages(): void
    {
        $this->result->addSuccess('Test success');
        $this->result->addInfo('Test info');
        $this->result->addWarning('Test warning');
        $this->result->addError('Test error');

        $this->result->clear();

        $this->assertEmpty($this->result->getSuccesses());
        $this->assertEmpty($this->result->getInfos());
        $this->assertEmpty($this->result->getWarnings());
        $this->assertEmpty($this->result->getErrors());
        $this->assertTrue($this->result->isValid());
    }
}
