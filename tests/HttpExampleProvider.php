<?php
/**
 * @package Nexcess/Salesforce
 * @subpackage Tests
 * @author Nexcess.net <nocworx@nexcess.net>
 * @copyright 2021 LiquidWeb Inc.
 * @license MIT
 */

namespace Nexcess\Salesforce\Test;

class HttpExampleProvider {

  public const ARGS = 0;
  public const EXPECTATIONS = 1;
  public const RESPONSE = 2;

  public static function get(string $name) : array {
    if (! is_readable(self::RESOURCE_DIR . "/{$name}.json")) {
      throw new LogicException("bad test: no example {$name} exists");
    }

    $example = json_decode(file_get_contents(self::RESOURCE_DIR . "/{$name}.json"), true);
    if (
      ! is_array($example) ||
      count($example) !== 3 ||
      ! isset($example[self::ARGS], $example[self::EXPECTATIONS], $example[self::RESPONSE])
    ) {
      throw new LogicException("bad test: invalid example {$name}");
    }

    return $example;
  }
}