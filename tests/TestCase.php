<?php
/**
 * @package Nexcess/Salesforce
 * @subpackage Tests
 * @author Nexcess.net <nocworx@nexcess.net>
 * @copyright 2021 LiquidWeb Inc.
 * @license MIT
 */

namespace Nexcess\Salesforce\Test;

use Nexcess\Salesforce\ {
  Authentication\Authentication,
  Client,
  Error\Authentication as AuthenticationException
};

use GuzzleHttp\ {
  Client as HttpClient,
  Exception\RequestException,
  Handler\MockHandler,
  HandlerStack,
  Middleware,
  Psr7\Request,
  Psr7\Response
};

use PHPUnit\Framework\TestCase as PHPUnitTestCase;

/**
 * Base TestCase.
 */
abstract class TestCase extends PhpunitTestCase {

  /**
   * Sets expectations for an exception to be thrown, based on an example.
   *
   * @param Throwable $expected Exception the test expects to be thrown
   */
  public function expectError(Throwable $expected) : void {
    $this->expectException(get_class($expected));

    $code = $expected->getCode();
    if (! empty($code)) {
      $this->expectExceptionCode($code);
    }
  }

  /**
   * Builds a new Client with a mock http handler.
   *
   * @return Client Api Client for testing
   */
  protected function newClient() : Client {
    $this->mockHttpHandler = new MockHandler();
    $this->mockHttpHandlerStack = HandlerStack::create($this->mockHandler);
    $this->requestExpectations = null;
    $this->mockHttpHandlerStack->push(
      Middleware::mapRequest(function (Request $request) {
        if (isset($this->requestExpectations)) {
          ($this->requestExpectations)(clone $request);
        }
        return $request;
      })
    );

    $this->mockHttpClient =  new HttpClient([
      'handler' => $this->mockHttpHandlerStack,
      'http_errors' => false
    ]);

    return new Client(new class($this->mockHttpClient) implements Authentication {
      public HttpClient $httpClient;
      public function __construct(HttpClient $httpClient) {
        $this->httpClient = $httpClient;
      }
      public function authenticate(array $parameters) : Authentication {
        return $this;
      }
      public function httpClient() : HttpClient {
        return $this->httpClient;
      }
    });
  }

  /**
   * Sets expectations and the mock response for the test HttpClient's next request.
   *
   * @param Closure $expectations Callback that runs assertions: void (Request $request)
   * @param Response $response The Response the Client should return
   */
  protected function setRequestExpectations(array $expectations, Response $response) : void {
    $this->mockHandler->reset();
    $this->mockHandler->append($response);

    $this->requestExpectations = function ($request) use ($expectations) {
      if ($isset($expectations['method'])) {
        $this->assertEquals();
      }
    };
  }
}
