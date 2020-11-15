<?php

namespace EcmXperts;

use Crypt_RSA;
use Exception;
use GuzzleHttp\Psr7;
use RuntimeException;
use GuzzleHttp\Client;
use phpseclib\Crypt\RSA;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Auth\GenericUser;
use EcmXperts\Exception\LumenOauth2Exception;
use GuzzleHttp\Exception\BadResponseException;

class LumenOauth2Client
{
    /**
     * @var mixed
     */
    protected $accessToken;

    /**
     * @var string
     */
    protected $audience;

    /**
     * @var object
     */
    protected $claims;

    /**
     * @var Client|null
     */
    protected $client;

    /**
     * @var int
     */
    protected $connectionTimeout = 300;

    /**
     * @var callable validator function for issuer claim
     */
    protected $issuerValidator;

    /**
     * @var callable[]
     */
    protected $middleWares = [];

    /**
     * @var array holds the provider configuration
     */
    protected $providerConfig = [];

    /**
     * @var string
     */
    protected $providerUrl;

    /**
     * @var mixed holds well-known openid server properties
     */
    protected $wellKnown = false;

    /**
     * Create a new Lumen Oauth2 authenticator.
     *
     * @param string|null $providerUrl
     * @return void
     */
    public function __construct($providerUrl = null)
    {
        $this->providerUrl = $providerUrl;

        $this->issuerValidator = function ($iss) {
            return ($iss === $this->getWellKnownIssuer() || $iss === $this->getWellKnownIssuer(true));
        };
    }

    /**
     * Verify the token and return user object.
     *
     * @param string $token
     * @return Illuminate\Auth\GenericUser|null;
     *
     * @throws EcmXperts\Exception\LumenOauth2Exception
     */
    public function authenticate($token)
    {
        $this->accessToken = $token;

        if ($this->verifyJWTSignature()) {
            // verify claims
            $this->claims = $this->decodeJWTPayload();

            if ($this->verifyJWTClaims()) {
                // return user object
                return new GenericUser(get_object_vars($this->claims));
            }
        }
    }

    /**
     * Get the provider url.
     *
     * @return string
     */
    public function getProviderUrl()
    {
        return $this->providerUrl;
    }

    /**
     * Set the expected audience.
     *
     * @param string $audience
     * @return $this
     */
    public function setAudience($audience)
    {
        $this->audience = $audience;

        return $this;
    }

    /**
     * Set the provider url.
     *
     * @param string
     * @return $this
     */
    public function setProviderUrl($providerUrl)
    {
        $this->providerUrl = $providerUrl;

        return $this;
    }

    /**
     * Get the provider issuer.
     *
     * @param bool $appendSlash
     * @return string|null
     */
    public function getWellKnownIssuer($appendSlash = false)
    {
        return $this->getWellKnownConfigValue('issuer') . ($appendSlash ? '/' : '');
    }

    /**
     * Get http client.
     *
     * @return GuzzleHttp\Client
     */
    protected function client()
    {
        if ($this->client) {
            return $this->client;
        }

        $handlerStack = HandlerStack::create();
        foreach ($this->middleWares as $middleWare) {
            $handlerStack->push($middleWare);
        }

        $this->client = new Client([
            'http_errors' => true,
            'handler'     => $handlerStack,
            'expect'      => false,
            'timeout'     => $this->connectionTimeout,
        ]);

        return $this->client;
    }

    /**
     * Verifies the jwt token against the provider.
     *
     * @return bool
     *
     * @throws EcmXperts\Exception\LumenOauth2Exception
     */
    protected function verifyJWTSignature()
    {
        if (!\is_string($this->accessToken)) {
            throw new LumenOauth2Exception('Error token is not a string');
        }

        $parts = explode('.', $this->accessToken);

        if (!isset($parts[0])) {
            throw new LumenOauth2Exception('Error missing part 0 in token');
        }

        $signature = base64url_decode(array_pop($parts));

        if (false === $signature || '' === $signature) {
            throw new LumenOauth2Exception('Error decoding signature from token');
        }

        $header = json_decode(base64url_decode($parts[0]));

        if (null === $header || !\is_object($header)) {
            throw new LumenOauth2Exception('Error decoding JSON from token header');
        }

        if (!isset($header->alg)) {
            throw new LumenOauth2Exception('Error missing signature type in token header');
        }

        try {
            $response = $this->client()->get($this->getProviderConfigValue('jwks_uri'));

            $jwks = $this->parseResponse($response);
        } catch (Exception $e) {
            $this->parseExceptionFromMessage($e);
        }

        $payload = implode('.', $parts);

        switch ($header->alg) {
            case 'RS256':
            case 'PS256':
            case 'RS384':
            case 'RS512':
                $hashtype = 'sha' . substr($header->alg, 2);
                $signatureType = $header->alg === 'PS256' ? 'PSS' : '';

                $verified = $this->verifyRSAJWTsignature(
                    $hashtype,
                    get_key_for_header($jwks->keys, $header),
                    $payload,
                    $signature,
                    $signatureType
                );
                break;
            default:
                throw new LumenOauth2Exception('No support for signature type: ' . $header->alg);
        }

        return $verified;
    }


    /**
     * Verfies the RSA JWT Signature.
     *
     * @param string $hashtype
     * @param object $key
     * @param string $payload
     * @param string $signature
     * @param string $signatureType
     * @return bool
     *
     * @throws EcmXperts\Exception\LumenOauth2Exception
     */
    private function verifyRSAJWTsignature($hashtype, $key, $payload, $signature, $signatureType)
    {
        if (!class_exists('\phpseclib\Crypt\RSA') && !class_exists('Crypt_RSA')) {
            throw new LumenOauth2Exception('Crypt_RSA support unavailable.');
        }

        if (!(property_exists($key, 'n') && property_exists($key, 'e'))) {
            throw new LumenOauth2Exception('Malformed key object');
        }

        /* We already have base64url-encoded data, so re-encode it as
           regular base64 and use the XML key format for simplicity.
        */
        $public_key_xml = "<RSAKeyValue>\r\n" .
            '  <Modulus>' . b64url2b64($key->n) . "</Modulus>\r\n" .
            '  <Exponent>' . b64url2b64($key->e) . "</Exponent>\r\n" .
            '</RSAKeyValue>';

        if (class_exists('Crypt_RSA', false)) {
            $rsa = new Crypt_RSA();
            $rsa->setHash($hashtype);

            if ($signatureType === 'PSS') {
                $rsa->setMGFHash($hashtype);
            }

            $rsa->loadKey($public_key_xml, Crypt_RSA::PUBLIC_FORMAT_XML);
            $rsa->signatureMode = $signatureType === 'PSS' ? Crypt_RSA::SIGNATURE_PSS : Crypt_RSA::SIGNATURE_PKCS1;
        } else {
            $rsa = new RSA();
            $rsa->setHash($hashtype);

            if ($signatureType === 'PSS') {
                $rsa->setMGFHash($hashtype);
            }

            $rsa->loadKey($public_key_xml, RSA::PUBLIC_FORMAT_XML);
            $rsa->signatureMode = $signatureType === 'PSS' ? RSA::SIGNATURE_PSS : RSA::SIGNATURE_PKCS1;
        }

        return $rsa->verify($payload, $signature);
    }

    /**
     * Get the provider config value.
     *
     * @param string $param
     * @param mixed $default
     * @return mixed
     *
     * @throws EcmXperts\Exception\LumenOauth2Exception
     */
    protected function getProviderConfigValue($param, $default = null)
    {
        if (!isset($this->providerConfig[$param])) {
            $this->providerConfig[$param] = $this->getWellKnownConfigValue($param, $default);
        }

        return $this->providerConfig[$param];
    }

    /**
     * Get the provider well known config value.
     *
     * @param string $param
     * @param mixed $default
     * @return mixed
     *
     * @throws EcmXperts\Exception\LumenOauth2Exception
     */
    protected function getWellKnownConfigValue($param, $default = null)
    {
        if (!$this->wellKnown) {
            try {
                $response = $this->client()->get(implode('/', [$this->getProviderUrl(), '.well-known/openid-configuration']));

                Psr7\rewind_body($response);
                $body = json_decode($response->getBody()->getContents());

                if (json_last_error() === JSON_ERROR_NONE) {
                    $this->wellKnown = $body;
                } else {
                    throw new LumenOauth2Exception('Could not get well known configuration, json decode failed. Got response: ' . $response->getBody()->getContents());
                }
            } catch (Exception $e) {
                $this->parseExceptionFromMessage($e);
            }
        }

        if (isset($this->wellKnown->{$param})) {
            return $this->wellKnown->{$param};
        }

        return $default;
    }

    /**
     * Parse the reponse in the Exception to return the error messages.
     *
     * @param \Exception $e
     *
     * @throws EcmXperts\Exception\LumenOauth2Exception
     */
    protected function parseExceptionFromMessage(Exception $e)
    {
        if (!$e instanceof BadResponseException) {
            throw new LumenOauth2Exception($e->getMessage());
        }

        $response = $e->getResponse();

        Psr7\rewind_body($response);
        $responseBody = $response->getBody()->getContents();
        $decodedResponseBody = json_decode($responseBody, true);

        if (!is_null($decodedResponseBody) && isset($decodedResponseBody['error']['message']['value'])) {
            $errorMessage = $decodedResponseBody['error']['message']['value'];
        } else {
            $errorMessage = $responseBody;
        }

        throw new LumenOauth2Exception('Error ' . $response->getStatusCode() . ': ' . $errorMessage, $response->getStatusCode());
    }

    /**
     * Parse the response and return the json content.
     *
     * @param GuzzleHttp\Psr7\Response $response
     * @return mixed
     *
     * @throws EcmXperts\Exception\LumenOauth2Exception
     */
    protected function parseResponse(Response $response)
    {
        try {
            if ($response->getStatusCode() === 204) {
                return [];
            }

            Psr7\rewind_body($response);
            $json = json_decode($response->getBody()->getContents());

            if (is_null($json)) {
                throw new LumenOauth2Exception('Json decode failed. Got response: ' . $response->getBody()->getContents());
            }

            return $json;
        } catch (RuntimeException $e) {
            throw new LumenOauth2Exception($e->getMessage());
        }
    }

    /**
     * Decode the JWT payload.
     *
     * @return object
     */
    protected function decodeJWTPayload()
    {
        $parts = explode('.', $this->accessToken);
        return json_decode(base64_decode($parts[1]));
    }

    /**
     * Verify the JWT claims.
     *
     * @return bool
     */
    protected function verifyJWTClaims()
    {
        $validIssuer = (call_user_func($this->issuerValidator, $this->claims->iss));

        if (!$validIssuer) {
            throw new LumenOauth2Exception('Invalid issuer');
        }

        $validAudience = ($this->claims->aud === $this->audience) || in_array($this->audience, $this->claims->aud, true);

        if (!$validAudience) {
            throw new LumenOauth2Exception('Invalid audience: ' . $this->audience);
        }

        $isExpired = (isset($this->claims->exp) && gettype($this->claims->exp) === 'integer' && $this->claims->exp < time() - 300);

        if ($isExpired) {
            throw new LumenOauth2Exception('Token has expired on ' . date('Y/m/d', $this->claims->exp));
        }

        $isNotBefore = (isset($this->claims->nbf) && gettype($this->claims->nbf) === 'integer' && $this->claims->nbf > time() + 300);

        if ($isNotBefore) {
            throw new LumenOauth2Exception('Token can not be used before: ' . date('Y/m/d', $this->claims->nbf));
        }

        return $validIssuer && $validAudience && !$isExpired && !$isNotBefore;
    }
}
