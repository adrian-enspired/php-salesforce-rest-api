<?php

namespace bjsmasth\Salesforce;

use GuzzleHttp\Client;
use bjsmasth\Salesforce\Exception\Salesforce as SalesforceException;
use Psr\Http\Message\StreamInterface;

class CRUD
{
    const API_VERSION = 'v51.0';

    protected $instance_url;
    protected $access_token;

    public function __construct()
    {
        if (!isset($_SESSION) and !isset($_SESSION['salesforce'])) {
            throw new SalesforceException('Access Denied', 403);
        }

        $this->instance_url = $_SESSION['salesforce']['instance_url'];
        $this->access_token = $_SESSION['salesforce']['access_token'];
    }

    public function getApiBaseUrl()
    {
        return $this->instance_url;
    }

    public function getApiPath()
    {
        return "/services/data/" . self::API_VERSION;
    }

    public function getApiUrl()
    {
        return $this->getApiBaseUrl() . $this->getApiPath();
    }

    public function query($query)
    {
        $url = "{$this->getApiUrl()}/query";

        $client = new Client();
        $request = $client->request('GET', $url, [
            'headers' => [
                'Authorization' => "OAuth {$this->access_token}"
            ],
            'query' => [
                'q' => $query
            ]
        ]);

        return json_decode($request->getBody(), true);
    }

    public function get($object, $field, $id)
    {
        $url = "{$this->getApiUrl()}/sobjects/{$object}/{$field}/{$id}";

        $client = new Client();

        $request = $client->request('GET', $url, [
            'headers' => [
                'Authorization' => "OAuth {$this->access_token}",
            ]
        ]);

        return json_decode($request->getBody(), true);
    }

    public function streamPath($path) : StreamInterface {
        $url = $this->getApiBaseUrl() . $path;
        $client = new Client();

        $request = $client->request('GET', $url, [
            'headers' => [
                'Authorization' => "OAuth {$this->access_token}",
            ]
        ]);

        return $request->getBody();
    }

    public function create($object, array $data)
    {
        $url = "{$this->getApiUrl()}/sobjects/{$object}/";

        $client = new Client();

        $headers = [
            'Authorization' => "OAuth {$this->access_token}",
            'Content-type' => 'application/json'
        ];
        
        // if the object type is a Comment__c, assign a header
        // that prevents SF from auto-assigning
        // @see MAD-12977
        if ($object === 'Comment__c') {
            $headers['Sforce-Auto-Assign'] = 'FALSE';
        }

        $request = $client->request('POST', $url, [
            'headers' => $headers,
            'json' => $data
        ]);

        $status = $request->getStatusCode();

        if ($status != 201) {
            throw new SalesforceException(
                "Error: call to URL {$url} failed with status {$status}, response: {$request->getReasonPhrase()}"
            );
        }

        return json_decode($request->getBody(), true);
    }

    public function update($object, $id, array $data)
    {
        $url = "{$this->getApiUrl()}/sobjects/{$object}/{$id}";

        $client = new Client();

        $request = $client->request('PATCH', $url, [
            'headers' => [
                'Authorization' => "OAuth $this->access_token",
                'Content-type' => 'application/json'
            ],
            'json' => $data
        ]);

        $status = $request->getStatusCode();

        if ($status != 204) {
            throw new SalesforceException(
                "Error: call to URL {$url} failed with status {$status}, response: {$request->getReasonPhrase()}"
            );
        }

        return json_decode($request->getBody(), true);
    }

    public function upsert($object, $field, $id, array $data)
    {
        $url = "{$this->getApiUrl()}/sobjects/{$object}/{$field}/{$id}";

        $client = new Client();

        $request = $client->request('PATCH', $url, [
            'headers' => [
                'Authorization' => "OAuth {$this->access_token}",
                'Content-type' => 'application/json'
            ],
            'json' => $data
        ]);

        $status = $request->getStatusCode();

        if ($status != 204 && $status != 201) {
            throw new SalesforceException(
                "Error: call to URL {$url} failed with status {$status}, response: {$request->getReasonPhrase()}"
            );
        }

        return json_decode($request->getBody(), true);
    }

    public function delete($object, $field, $id)
    {
        $url = "{$this->getApiUrl()}/sobjects/{$object}/{$field}/{$id}";

        $client = new Client();
        $request = $client->request('DELETE', $url, [
            'headers' => [
                'Authorization' => "OAuth {$this->access_token}",
            ]
        ]);

        $status = $request->getStatusCode();

        if ($status != 204) {
            throw new SalesforceException(
                "Error: call to URL {$url} failed with status {$status}, response: {$request->getReasonPhrase()}"
            );
        }

        return true;
    }
}
