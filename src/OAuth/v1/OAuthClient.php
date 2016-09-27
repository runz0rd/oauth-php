<?php
/**
 * Created by PhpStorm.
 * User: milos.pejanovic
 * Date: 5/13/2016
 * Time: 12:05 AM
 */

namespace OAuth\v1;

class OAuthClient {

    const SHA1 = 'sha1';
    const HMAC_SHA1 = 'HMAC-SHA1';
    const SIGNATURE = 'oauth_signature';
    const CONSUMER_KEY = 'oauth_consumer_key';
    const NONCE = 'oauth_nonce';
    const SIGNATURE_METHOD = 'oauth_signature_method';
    const TIMESTAMP = 'oauth_timestamp';
    const VERSION = 'oauth_version';
    const VERSION_NUMBER = '1.0';
    const NONCE_BEGIN = 123400;
    const NONCE_END = 9999999;

    private $consumerKey;
    private $consumerSecret;
    private $tokenSecret;

    /**
     * OAuthClient constructor.
     * @param string $consumerKey
     * @param string $consumerSecret
     * @param string $tokenSecret
     */
    public function __construct(string $consumerKey, string $consumerSecret, string $tokenSecret = '') {
        $this->consumerKey = $consumerKey;
        $this->consumerSecret = $consumerSecret;
        $this->tokenSecret = $tokenSecret;
    }

    /**
     * @param OAuthRequest $request
     * @return string
     */
    public function generateSignature(OAuthRequest $request) {
        $baseString = $this->generateBaseString($request);
        $key = rawurlencode($this->consumerSecret) . "&" . rawurlencode($this->tokenSecret);
        $signature = base64_encode(hash_hmac(self::SHA1, $baseString, $key, true));

        return $signature;
    }

    /**
     * @param OAuthRequest $request
     * @throws OAuthException
     */
    public function verifySignature(OAuthRequest $request) {
        $actualSignature = $request->getOAuthParam(self::SIGNATURE);
        $expectedSignature = $this->generateSignature($request);

        if($actualSignature !== $expectedSignature) {
            throw new OAuthException('OAuth: Signatures do not match.');
        }
    }

    /**
     * @param OAuthRequest $request
     * @return string
     */
    public function createAuthorizationHeader(OAuthRequest $request) {
        $oAuthArray = $this->createOAuthArray($request);

        return OAuthRequest::toHeader($oAuthArray);
    }

    /**
     * @param OAuthRequest $request
     * @return string
     */
    public function createOAuthRequestUrl(OAuthRequest $request) {
        $parameterArray = array_merge($request->getQuery(), $this->createOAuthArray($request));

        $oAuthRequestUrl = $request->getAbsolutePath() . '?';
        foreach($parameterArray as $k => $v) {
            $oAuthRequestUrl .= $k . '=' . $v . '&';
        }

        return rtrim($oAuthRequestUrl, '&');
    }

    /**
     * @param OAuthRequest $request
     * @return string
     */
    protected function generateBaseString(OAuthRequest $request) {
        $parameterString = "";
        $parameters = array_merge($request->getOAuthArray(), $request->getQuery());
        if(isset($parameters[self::SIGNATURE])) {
            unset($parameters[self::SIGNATURE]);
        }
        ksort($parameters);

        foreach($parameters as $k => $v) {
            $parameterString .= rawurlencode($k) . "=" . rawurlencode($v) . "&";
        }
        $parameterString = rawurlencode(rtrim($parameterString, '&'));

        $baseString = $request->getMethod() . "&" . rawurlencode($request->getAbsolutePath()) . "&" . $parameterString;

        return $baseString;
    }

    /**
     * @param OAuthRequest $request
     * @return array
     */
    protected function createOAuthArray(OAuthRequest $request) {
        $oAuthArray[self::CONSUMER_KEY] = $this->consumerKey;
        $oAuthArray[self::NONCE] = $this->generateNonce();
        $oAuthArray[self::SIGNATURE_METHOD] = self::HMAC_SHA1;
        $oAuthArray[self::TIMESTAMP] = $this->getTimestamp();
        $oAuthArray[self::VERSION] = self::VERSION_NUMBER;

        $newRequest = new OAuthRequest($request->getUrl(), OAuthRequest::toHeader($oAuthArray), $request->getMethod());
        $oAuthArray[self::SIGNATURE] = rawurlencode($this->generateSignature($newRequest));

        return $oAuthArray;
    }

    /**
     * @return int
     */
    protected function generateNonce() {
        return rand(self::NONCE_BEGIN, self::NONCE_END);
    }

    /**
     * @return int
     */
    protected function getTimestamp() {
        return time();
    }
}