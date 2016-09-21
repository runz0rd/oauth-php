<?php

/**
 * Created by PhpStorm.
 * User: milos.pejanovic
 * Date: 5/12/2016
 * Time: 10:44 AM
 */

use OAuth\v1\OAuthRequest;

class OAuthRequestTest extends \PHPUnit_Framework_TestCase {

	public function testConstruct() {
		$authorization = 'OAuth realm="http://example.test/testing",mock="yes",oauth_consumer_key="testKey",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1463125730",oauth_nonce="B72xmh",oauth_version="1.0",oauth_signature="EN0%2FppVbr0qonk2cw%2BlP3EoNDcg%3D"';
		$request = new OAuthRequest('http://example.test/testing?mock=yes', $authorization);

		$this->assertEquals('http://example.test/testing', $request->getAbsolutePath());
		$this->assertEquals('http://example.test/testing?mock=yes', $request->getUrl());
		$this->assertEquals(array('mock' => 'yes'), $request->getQuery());
//		$this->assertEquals(rawurldecode('EN0%2FppVbr0qonk2cw%2BlP3EoNDcg%3D'), $request->getAuthorizationParameter('oauth_signature'));
	}

	public function testCreateFromGlobal() {
		$serverGlobal = array(
			'SERVER_PORT' => '80',
			'HTTP_X_FORWARDED_PROTO' => 'http',
			'SERVER_NAME' => 'example.test',
			'REQUEST_URI' => '/testing?mock=yes',
			'REQUEST_METHOD' => 'GET',
			'HTTP_AUTHORIZATION' => 'OAuth realm="http://example.test/testing",oauth_consumer_key="testKey",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1463125730",oauth_nonce="B72xmh",oauth_version="1.0",oauth_signature="EN0%2FppVbr0qonk2cw%2BlP3EoNDcg%3D"'
		);
		$request = OAuthRequest::createFromGlobals($serverGlobal);

		$this->assertEquals('http://example.test/testing', $request->getAbsolutePath());
		$this->assertEquals('http://example.test/testing?mock=yes', $request->getUrl());
		$this->assertEquals(array('mock' => 'yes'), $request->getQuery());
//		$this->assertEquals(rawurldecode('EN0%2FppVbr0qonk2cw%2BlP3EoNDcg%3D'), $request->getAuthorizationParameter('oauth_signature'));
	}

	/**
	 * @expectedException OAuth\v1\OAuthException
	 */
	public function testCreateFromGlobalUnauthorized() {
		$serverGlobal = array(
			'SERVER_PORT' => '80',
			'HTTP_X_FORWARDED_PROTO' => 'http',
			'SERVER_NAME' => 'example.test',
			'REQUEST_URI' => '/testing?mock=yes',
			'REQUEST_METHOD' => 'GET',
			'HTTP_AUTHORIZATION' => ''
		);
		$request = OAuthRequest::createFromGlobals($serverGlobal);
		$request->getOAuthArray();
	}

	public function testOAuthStringToArray() {
		$oAuthString = 'OAuth realm="http://example.test/testing",mock="yes",oauth_consumer_key="testKey",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1463125730",oauth_nonce="B72xmh",oauth_version="1.0",oauth_signature="EN0%2FppVbr0qonk2cw%2BlP3EoNDcg%3D"';
		$oAuthArray = OAuthRequest::parseAuthorization($oAuthString);

		$this->assertEquals(rawurldecode('EN0%2FppVbr0qonk2cw%2BlP3EoNDcg%3D'), $oAuthArray['oauth_signature']);
	}
}