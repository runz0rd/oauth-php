<?php

/**
 * Created by PhpStorm.
 * User: milos.pejanovic
 * Date: 5/12/2016
 * Time: 10:44 AM
 */

use OAuth\v1\OAuthClient;
use OAuth\v1\OAuthRequest;

class OAuthClientTest extends \PHPUnit_Framework_TestCase {
	/**
	 * @var OAuthClient
	 */
	private $oAuth;

	public function setUp() {
		$this->oAuth = new OAuthClient('testKey', 'testSecret');
		parent::setUp();
	}

	public function testGenerateSignature() {
		$authorization = 'OAuth realm="http://example.test/testing",oauth_consumer_key="testKey",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1463125730",oauth_nonce="B72xmh",oauth_version="1.0",oauth_signature="EN0%2FppVbr0qonk2cw%2BlP3EoNDcg%3D"';
		$authorizationArray = OAuthRequest::parseOAuthString($authorization);
		$request = new OAuthRequest('http://example.test/testing?mock=yes', $authorizationArray);
		$signature = $this->oAuth->generateSignature($request);
		$this->assertEquals($request->getAuthorizationParameter(OAuthClient::SIGNATURE), $signature);
	}

	public function testCreateAuthorizationHeader() {
		$authorization = 'OAuth realm="http://example.test/testing",mock="yes",oauth_consumer_key="testKey",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1463125730",oauth_nonce="B72xmh",oauth_version="1.0",oauth_signature="EN0%2FppVbr0qonk2cw%2BlP3EoNDcg%3D"';
		$authorizationArray = OAuthRequest::parseOAuthString($authorization);
		$request = new OAuthRequest('http://example.test/testing?mock=yes', $authorizationArray);
		$oAuthString = $this->oAuth->createAuthorizationHeader($request);

		$this->assertArrayHasKey(OAuthClient::SIGNATURE, OAuthRequest::parseOAuthString($oAuthString));
	}

	public function testCreateOAuthRequestUrl() {
		$authorization = 'OAuth realm="http://example.test/testing",mock="yes",oauth_consumer_key="testKey",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1463125730",oauth_nonce="B72xmh",oauth_version="1.0",oauth_signature="EN0%2FppVbr0qonk2cw%2BlP3EoNDcg%3D"';
		$authorizationArray = OAuthRequest::parseOAuthString($authorization);
		$request = new OAuthRequest('http://localhost/testXml/loadXml.php?type=subscription_cancel&accountIdentifier=APPDIRECT_devtech_1463394127_t33189', $authorizationArray);

		$requestUrl = $this->oAuth->createOAuthRequestUrl($request);

		$this->assertContains(OAuthClient::SIGNATURE, $requestUrl);
	}
}