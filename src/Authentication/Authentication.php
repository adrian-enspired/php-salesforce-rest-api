<?php
/**
 * @package Nexcess/Salesforce
 * @author Nexcess.net <nocworx@nexcess.net>
 * @copyright 2021 LiquidWeb Inc.
 * @license MIT
 */

namespace Nexcess\Salesforce\Authentication;

use GuzzleHttp\Client as HttpClient;

use Nexcess\Salesforce\Error\Authentication as AuthenticationException;

/**
 * Handles Salesforce authentication.
 */
interface Authentication {

  /**
   * Authenticates with the Salesforce Api.
   *
   * @param array $parameters Authentication parameters
   * @throws AuthenticationException FAILED on failure
   * @return Authentication $this
   */
  public function authenticate(array $parameters) : Authentication;

  /**
   * Gets a new Http client using this authentication
   *
   * @throws AuthenticationException NOT_AUTHENTICATED if authentication has not yet succeeded
   */
  public function httpClient() : HttpClient;
}
