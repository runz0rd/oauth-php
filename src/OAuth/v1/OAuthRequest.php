<?php

/**
 * Created by PhpStorm.
 * User: milos.pejanovic
 * Date: 5/12/2016
 * Time: 9:50 PM
 */
namespace OAuth\v1;

class OAuthRequest {

    /**
     * @var string
     */
    private $url;

    /**
     * @var string
     */
    private $absolutePath;

    /**
     * @var array
     */
    private $query;

    /**
     * @var array
     */
    private $oAuthAuthorization;

    /**
     * @var string
     */
    private $method;

    /**
     * @param string $url
     * @param string $authorizationHeader
     * @param string $method
     */
    public function __construct(string $url, string $authorizationHeader = '', string $method = 'GET') {
        $this->url = $url;
        $this->absolutePath = $this->parseAbsolutePath($url);
        $this->query = $this->parseQuery($url);
        $this->oAuthAuthorization = self::toArray($authorizationHeader);
        $this->method = $method;
    }

    /**
     * @param array|null $serverGlobals
     * @return OAuthRequest
     */
    public static function createFromGlobals(array $serverGlobals = null) {
        if(is_null($serverGlobals)) {
            $serverGlobals = $_SERVER;
        }
        $scheme = 'http';
        $port = '';
        if($serverGlobals['SERVER_PORT'] != '80' && $serverGlobals['SERVER_PORT'] != '443') {
            $port = ":" . $serverGlobals['SERVER_PORT'];
        }

        if(isset($serverGlobals['HTTP_X_FORWARDED_PROTO']) && 'https' == $serverGlobals['HTTP_X_FORWARDED_PROTO']) {
            // this case occurs when the server is behind a loadbalancer, in which case the lb should forward this data
            $scheme = 'https';
        }
        elseif(isset($serverGlobals['HTTPS']) && 'on' == $serverGlobals['HTTPS']) {
            // a regular case when the server schema is on https
            $scheme = 'https';
        }

        $authorizationHeader = '';
        if(function_exists('apache_request_headers') && !empty(apache_request_headers()['Authorization'])) {
            $authorizationHeader = apache_request_headers()['Authorization'];
        }
        elseif(isset($serverGlobals['HTTP_AUTHORIZATION'])) {
            $authorizationHeader = $serverGlobals['HTTP_AUTHORIZATION'];
        }
        $url = $scheme . '://' . $serverGlobals['SERVER_NAME'] . $port . $serverGlobals['REQUEST_URI'];
        $method = $serverGlobals['REQUEST_METHOD'];

        return new OAuthRequest($url, $authorizationHeader, $method);
    }

    /**
     * @param string $url
     * @return string
     */
    private function parseAbsolutePath(string $url) {
        $urlPieces = explode('?', $url);

        $absolutePath = $url;
        if(!empty($urlPieces)) {
            $absolutePath = $urlPieces[0];
        }

        return $absolutePath;
    }

    /**
     * @param string $url
     * @return array
     */
    private function parseQuery(string $url) {
        $query = array();

        $urlPieces = explode('?', $url);
        if(isset($urlPieces[1])) {
            parse_str($urlPieces[1], $query);
        }

        return $query;
    }

    /**
     * @param string $authorization
     * @return array
     * @throws OAuthException
     */
    public static function toArray(string $authorization) {
        $oAuthArray = array();
        $authorization = str_replace("OAuth", "", $authorization);
        $authorization = str_replace('"', '', $authorization);
        $oAuthPieces = explode(",", $authorization);

        if(empty($oAuthPieces)) {
            throw new OAuthException('OAuth: Invalid authorization header provided');
        }

        foreach ($oAuthPieces as $oAuthParam) {
            $oAuthParamPieces = explode("=", $oAuthParam);
            if(!empty($oAuthParamPieces) && count($oAuthParamPieces) > 1) {
                if('realm' == trim($oAuthParamPieces[0])) {
                    continue;
                }
                $oAuthArray[trim($oAuthParamPieces[0])] = rawurldecode(trim($oAuthParamPieces[1]));
            }
        }

        return $oAuthArray;
    }

    /**
     * @param array $oAuthArray
     * @return string
     */
    public static function toHeader(array $oAuthArray) {
        $authorizationHeader = 'OAuth ';
        foreach($oAuthArray as $key => $value) {
            $authorizationHeader .= $key . '="' . $value . '", ';
        }

        return rtrim($authorizationHeader, ', ');
    }

    /**
     * @return string
     * @throws OAuthException
     */
    public function getAbsolutePath() {
        if(!isset($this->absolutePath) || empty($this->absolutePath)) {
            throw new OAuthException('Invalid absolute path provided.');
        }

        return $this->absolutePath;
    }

    /**
     * @return array
     * @throws OAuthException
     */
    public function getQuery() {
        if(!isset($this->query)) {
            throw new OAuthException('OAuth: No query set.');
        }
        return $this->query;
    }

    /**
     * @return array
     * @throws OAuthException
     */
    public function getOAuthArray() {
        if(!isset($this->oAuthAuthorization) || empty($this->oAuthAuthorization)) {
            throw new OAuthException('OAuth: Authorization header not found in the request.');
        }

        return $this->oAuthAuthorization;
    }

    /**
     * @param string $name
     * @return string
     * @throws OAuthException
     */
    public function getOAuthParam(string $name) {
        $oAuthArray = $this->getOAuthArray();
        if(!isset($oAuthArray[$name])) {
            throw new OAuthException('OAuth: Parameter ' . $name . ' not found in the authorization header.');
        }

        return $oAuthArray[$name];
    }

    /**
     * @return string
     * @throws OAuthException
     */
    public function getMethod() {
        if(!isset($this->method)) {
            throw new OAuthException('OAuth: method not set.');
        }
        return $this->method;
    }

    /**
     * @return string
     * @throws OAuthException
     */
    public function getUrl() {
        if(!isset($this->url) || empty($this->url)) {
            throw new OAuthException('OAuth: Invalid url provided.');
        }
        return $this->url;
    }
}