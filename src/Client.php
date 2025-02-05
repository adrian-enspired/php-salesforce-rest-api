<?php
/**
 * @package Nexcess/Salesforce
 * @author Nexcess.net <nocworx@nexcess.net>
 * @copyright 2021 LiquidWeb Inc.
 * @license MIT
 */

namespace Nexcess\Salesforce;

use Closure,
  Throwable;

use Nexcess\Salesforce\ {
  Authentication\Authentication,
  Error\Salesforce as SalesforceException,
  Error\Usage as UsageException,
  Result,
  SalesforceObject
};

use GuzzleHttp\Client as HttpClient;

use Psr\Http\Message\ {
  ResponseInterface as Response,
  StreamInterface as Stream
};

class Client {

  /** @var string Target Salesforce Api version. */
  public const API_VERSION = 'v51.0';

  /**
   * Supported SOQL data types.
   *
   * @var string TYPE_STRING
   * @var string TYPE_INTEGER
   * @var string TYPE_FLOAT
   * @var string TYPE_DECIMAL
   * @var string TYPE_BOOLEAN
   * @var string TYPE_NULL
   */
  public const TYPE_STRING = 'string';
  public const TYPE_INTEGER = 'integer';
  public const TYPE_FLOAT = 'double';
  public const TYPE_DECIMAL = 'decimal';
  public const TYPE_BOOLEAN = 'boolean';
  public const TYPE_NULL = 'NULL';

  /** @var string Base path for Api requests. */
  protected const API_PATH = '/services/data/' . self::API_VERSION;

  /**
   * @var string[] Literal value:escaped value map.
   *
   * @see https://developer.salesforce.com/docs/atlas.en-us.soql_sosl.meta/
   *  soql_sosl/sforce_api_calls_soql_select_quotedstringescapes.htm
   */
  protected const ESCAPE_MAP = [
    "\n" => '\n',
    "\r" => '\r',
    "\t" => '\t',
    "\x07" => '\b',
    "\f" => '\f',
    '"' => '\"',
    '\'' => '\\\'',
    '\\' => '\\\\'
  ];

  /**
   * Relevant HTTP status codes.
   *
   * @internal
   *
   * @var int HTTP_OK
   * @var int HTTP_CREATED
   * @var int HTTP_NO_CONTENT
   */
  public const HTTP_OK = 200;
  public const HTTP_CREATED = 201;
  public const HTTP_NO_CONTENT = 204;

  /** @var HttpClient Api client. */
  private HttpClient $httpClient;

  /* @var string[] Map of salesforce object type:fully qualified SalesforceObject classnames. */
  protected array $objectMap = [];

  /**
   * @param Authentication $auth Authentication details
   * @param string[] $object_map Map of salesforce object type:fully qualified classnames
   */
  public function __construct(Authentication $auth, array $object_map = []) {
    $this->httpClient = $auth->httpClient();
    $this->mapObjects($object_map);
  }

  /**
   * Creates a new Salesforce record.
   *
   * @param SalesforceObject $object The object to create
   * @throws SalesforceException CREATE_FAILED on failure
   */
  public function create(SalesforceObject $object) : SalesforceObject {
    $response = $this->request('POST', "/sobjects/{$object->type()}", ['json' => $object->toArray()]);
    if ($response->getStatusCode() !== self::HTTP_CREATED) {
      throw SalesforceException::create(
        SalesforceException::CREATE_FAILED,
        $this->getResponseContext($response)
      );
    }

    $created = clone $object;
    $created->Id = $this->getResultFrom($response)->lastId();
    return $created;
  }

  /**
   * Deletes an existing record in Salesforce.
   *
   * @param SalesforceObject $object The object to create
   * @throws SalesforceException DELETE_FAILED on failure
   */
  public function delete(SalesforceObject $object) : SalesforceObject {
    $this->deleteByExternalId($object->type(), 'Id', $object->Id);

    $deleted = clone $object;
    $deleted->Id = null;
    return $deleted;
  }

  /**
   * Deletes an existing record in Salesforce given its type and an External Id.
   *
   * @param string $type Salesforce object type
   * @param string $id_field The External Id field to look up by
   * @param string $id 18-character Salesforce Id
   * @throws SalesforceException DELETE_FAILED on failure
   */
  public function deleteByExternalId(string $type, string $id_field, string $id) : Result {
    $response = $this->request('DELETE', "/sobjects/{$type}/{$id_field}/{$id}");
    if ($response->getStatusCode() !== self::HTTP_NO_CONTENT) {
      throw SalesforceException::create(
        SalesforceException::DELETE_FAILED,
        $this->getResponseContext($response)
      );
    }

    return $this->getResultFrom($response);
  }

  /**
   * Gets a Salesforce record given its type and Id.
   *
   * @param string $type Salesforce object type
   * @param string $id 18-character Salesforce Id
   * @throws SalesforceException GET_FAILED on failure
   */
  public function get(string $type, string $id) : SalesforceObject {
    return $this->getByExternalId($type, 'Id', $id)->first();
  }

  /**
   * Gets a Salesforce record given its type and an External Id.
   *
   * @param string $type Salesforce object type
   * @param string $id_field The External Id field to look up by
   * @param string $id 18-character Salesforce Id
   * @throws SalesforceException GET_FAILED on failure
   */
  public function getByExternalId(string $type, string $id_field, string $id) : Result {
    $response = $this->request('GET', "/sobjects/{$type}/{$id_field}/{$id}");
    if ($response->getStatusCode() !== self::HTTP_OK) {
      throw SalesforceException::create(
        SalesforceException::GET_FAILED,
        $this->getResponseContext($response)
      );
    }

    return $this->getResultFrom($response);
  }

  /**
   * Maps Salesforce object types to desired php classnames.
   *
   * @param string[] $object_map Map of salesforce object type:fully qualified classnames
   */
  public function mapObjects(array $object_map) : void {
    foreach ($object_map as $type => $fqcn) {
      if (! is_a($fqcn, SalesforceObject::class, true)) {
        throw UsageException::create(UsageException::BAD_SFO_CLASSNAME, ['fqcn' => $fqcn]);
      }

      $this->objectMap[$type] = $fqcn;
    }
  }

  /**
   * Performs a SOQL query.
   *
   * @param string $template SOQL query with optional {tokens} for parameters
   * @param array $parameters Parameter values (escaped prior to formatting)
   * @throws UsageException On error
   */
  public function query(string $template, array $parameters = []) : Result {
    $response = $this->request(
      'GET',
      '/query',
      ['query' => ['q' => $this->prepare($template, $parameters)]]
    );
    if ($response->getStatusCode() !== self::HTTP_OK) {
      throw SalesforceException::create(
        SalesforceException::GET_FAILED,
        $this->getResponseContext($response)
      );
    }

    return $this->getResultFrom($response);
  }

  /**
   * Streams the raw http response from the given path (useful for, e.g., downloading Attachments).
   *
   * @param string $path The Api path to request
   */
  public function stream(string $path) : Stream {
    try {
      return $this->httpClient->get($path)->getBody();
    } catch (Throwable $e) {
      throw SalesforceException::create(
        SalesforceException::HTTP_REQUEST_FAILED,
        ['method' => 'GET', 'path' => $path],
        $e
      );
    }
  }

  /**
   * Updates an existing record in Salesforce.
   *
   * @param SalesforceObject $object The object to update from
   * @throws SalesforceException UPDATE_FAILED on failure
   * @throws UsageException NO_SUCH_FIELD If the object does not contain the given id_field
   */
  public function update(
    SalesforceObject $object,
    string $id_field = "Id",
    string $id = null
  ) : SalesforceObject {
    if (! property_exists($object, $id_field)) {
      throw UsageException::create(
        UsageException::NO_SUCH_FIELD,
        ['type' => $object->type(), 'field' => $id_field]
      );
    }

    $id ??= $object->$id_field;
    if (empty($id)) {
      throw UsageException::create(
        UsageException::EMPTY_ID,
        ['type' => $object->type(), 'id_field' => $id_field]
      );
    }

    $fields = $object->toArray();
    unset($fields['Id']);
    $response = $this->request(
      'PATCH',
      "/sobjects/{$object->type()}/{$id_field}/{$id}",
      ['json' => $fields]
    );

    if ($response->getStatusCode() !== self::HTTP_OK) {
      throw SalesforceException::create(
        SalesforceException::UPDATE_FAILED,
        $this->getResponseContext($response)
      );
    }

    return $this->get($object->type(), $object->Id);
  }

  /**
   * Gets a new Result object for the next page of results.
   *
   * @param string $url Url for the page
   * @return Result New Result object on success
   */
  protected function getMoreResultsFrom(string $url) : Result {
    return $this->getResultFrom($this->httpClient->get($url));
  }

  /**
   * Gets a new Result object for an Api Response.
   *
   * @param Response $response The Salesforce Api Response
   * @return Result New Result object on success
   */
  protected function getResultFrom(Response $response) : Result {
    return Result::from(
      $response,
      $this->objectMap,
      Closure::fromCallable([$this, 'getMoreResultsFrom'])
    );
  }

  /**
   * Gets error context from an Api response.
   *
   * @param Response $response Http response to get context from
   */
  protected function getResponseContext(Response $response) : array {
    $payload = json_decode($response->getBody()->__toString() ?: '[]')[0] ?? [];

    return array_filter(
      [
        'response' => $response,
        'status' => $response->getStatusCode(),
        'reason' => $response->getReasonPhrase(),
        'sf_id' => $payload->id ?? null,
        'sf_errors' => $payload->errors ?? null,
        'sf_success' => $payload->success ?? null,
        'sf_created' => $payload->created ?? null,
        'sf_error_code' => $payload->errorCode ?? null,
        'sf_error_message' => isset($payload->errors) ?
          join("\n", $payload->errors) :
          ($payload->message ?? null)
      ],
      fn ($value) => isset($value)
    );
  }

  /**
   * Quotes and interpolates parameter values into an SOQL template.
   *
   * @param string $template SOQL template with value {tokens}
   * @param array $parameters Parameter token:value map
   * @throws UsageException On error
   * @return string Interpolated SOQL on success
   */
  protected function prepare(string $template, array $parameters) : string {
    if (! empty($parameters)) {
      $replacements = [];
      foreach ($parameters as $field => $value) {
        $replacements["{{$field}}"] = $this->quote($value);
      }

      $template = strtr($template, $replacements);
    }

    return $template;
  }

  /**
   * Quotes a value for use in a SOQL query.
   *
   * @param mixed $value The value to quote
   * @throws UsageException UNSUPPORTED_DATATTYPE if the given type is not one of self::TYPE_*
   * @throws UsageException UNQUOTABLE_VALUE if the value cannot be quoted as the given type
   * @param string $type The intended datatype
   */
  protected function quote($value, string $type = null) : string {
    $actual_type = gettype($value);
    switch ($type ?? $actual_type) {
      case self::TYPE_STRING:
        if (! in_array($actual_type, [self::TYPE_STRING, self::TYPE_INTEGER, self::TYPE_FLOAT])) {
          throw UsageException::create(
            UsageException::UNQUOTABLE_VALUE,
            ['type' => $type, 'actual_type' => $actual_type, 'value' => $value]
          );
        }

        return '\'' . strtr($value, self::ESCAPE_MAP) . '\'';
      case self::TYPE_INTEGER:
        $integer = filter_var($value, FILTER_VALIDATE_INT);
        if ($integer === false) {
          throw UsageException::create(
            UsageException::UNQUOTABLE_VALUE,
            ['type' => $type, 'actual_type' => $actual_type, 'value' => $value]
          );
        }

        return $integer;
      case self::TYPE_FLOAT:
        $float = filter_var($value, FILTER_VALIDATE_FLOAT);
        if ($float === false) {
          throw UsageException::create(
            UsageException::UNQUOTABLE_VALUE,
            ['type' => $type, 'actual_type' => $actual_type, 'value' => $value]
          );
        }

        return $float;
      case self::TYPE_DECIMAL:
        if (
          $actual_type !== self::TYPE_INTEGER &&
          ! ($actual_type === self::TYPE_FLOAT && filter_var($value, FILTER_VALIDATE_INT) !== false) &&
          ! ($actual_type === self::TYPE_STRING && filter_var($value, FILTER_VALIDATE_FLOAT) !== false)
        ) {
          throw UsageException::create(
            UsageException::UNQUOTABLE_VALUE,
            ['type' => $type, 'actual_type' => $actual_type, 'value' => $value]
          );
        }

        return (string) $value;
      case self::TYPE_BOOLEAN:
        if ($actual_type !== self::TYPE_BOOLEAN) {
          throw UsageException::create(
            UsageException::UNQUOTABLE_VALUE,
            ['type' => $type, 'actual_type' => $actual_type, 'value' => $value]
          );
        }

        return json_encode($value);
      case self::TYPE_NULL:
        if ($actual_type !== self::TYPE_NULL) {
          throw UsageException::create(
            UsageException::UNQUOTABLE_VALUE,
            ['type' => $type, 'actual_type' => $actual_type, 'value' => $value]
          );
        }

        return json_encode($value);
      default:
        throw UsageException::create(UsageException::UNSUPPORTED_DATATYPE, ['type' => $type]);
    }
  }

  /**
   * Performs an HTTP request and returns the Api Response.
   *
   * @param string $method One of GET|POST|PATCH|DELETE
   * @param string $path URI, without base API_PATH
   * @param array $options Guzzle options
   */
  protected function request(string $method, string $path, array $options = []) : Response {
    try {
      $path = self::API_PATH . $path;
      return $this->httpClient->request($method, $path, $options);
    } catch (Throwable $e) {
      throw SalesforceException::create(
        SalesforceException::HTTP_REQUEST_FAILED,
        ['method' => $method, 'path' => $path, 'options' => $options],
        $e
      );
    }
  }
}
