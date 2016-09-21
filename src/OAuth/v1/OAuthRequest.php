<?php

/**
 * Created by PhpStorm.
 * User: milos.pejanovic
 * Date: 5/12/2016
 * Time: 9:50 PM
 */
namespace OAuth\v1;

class OAuthRequest {

    private $url;
    private $absolutePath;
    private $query;
    private $authorization;
    private $method;

    /**
     * @param string $url
     * @param array $authorizationArray
     * @param string $method
     */
    public function __construct(string $url, array $authorizationArray = array(), string $method = 'GET') {
        $this->url = $url;
        $this->absolutePath = $this->parseAbsolutePath($url);
        $this->query = $this->parseQuery($url);
        $this->authorization = $authorizationArray;
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
        $authorizationArray = self::parseOAuthString($authorizationHeader);
        $method = $serverGlobals['REQUEST_METHOD'];

        return new OAuthRequest($url, $authorizationArray, $method);
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
        if(!empty($urlPieces)) {
            parse_str($urlPieces[1], $query);
        }

        return $query;
    }

    /**
     * @param string $oAuthString
     * @return array
     */
    public static function parseOAuthString(string $oAuthString) {
        $oAuthArray = array();
        $oAuthString = str_replace("OAuth", "", $oAuthString);
        $oAuthString = str_replace('"', '', $oAuthString);
        $oAuthPieces = explode(",", $oAuthString);

        if(!empty($oAuthPieces)) {
            foreach ($oAuthPieces as $oAuthParam) {
                $oAuthParamPieces = explode("=", $oAuthParam);
                if(!empty($oAuthParamPieces) && count($oAuthParamPieces) > 1) {
                    if('realm' == trim($oAuthParamPieces[0])) {
                        continue;
                    }
                    $oAuthArray[trim($oAuthParamPieces[0])] = rawurldecode(trim($oAuthParamPieces[1]));
                }
            }
        }

        return $oAuthArray;
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
     * @param string $key
     * @return string
     * @throws OAuthException
     */
    public function getAuthorizationParameter(string $key) {
        if(empty($key) || !isset($this->authorization[$key])) {
            throw new OAuthException('OAuth: Parameter "' . $key . '" not found in the authorization header.');
        }

        return $this->authorization[$key];
    }

    /**
     * @return array
     * @throws OAuthException
     */
    public function getAuthorization() {
        if(!isset($this->authorization) || empty($this->authorization)) {
            throw new OAuthException('OAuth: Authorization header not found in the request.');
        }

        return $this->authorization;
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