<?php
/**
 * @package Nexcess/Salesforce
 * @subpackage Tests
 * @author Nexcess.net <nocworx@nexcess.net>
 * @copyright 2021 LiquidWeb Inc.
 * @license MIT
 */

namespace Nexcess\Salesforce\Test;

use Nexcess\Salesforce\Test\ {
  MockResponse,
  TestCase
};

class CrudTest extends TestCase {

  public function testSimpleQuery() {
    $this->assertStringContainsString("foo","bar","custom message");
    // [$args, $expectations, $response] = HttpExampleProvider::get();
    // $client = $this->newClient();
  }
}