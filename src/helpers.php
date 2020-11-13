<?php

use EcmXperts\Exception\LumenOauth2Exception;

if (! function_exists('base64url_decode')) {
    /**
     * A wrapper around base64_decode which decodes Base64URL-encoded data,
     * which is not the same alphabet as base64.
     *
     * @param string $base64url
     * @return bool|string
     */
    function base64url_decode($base64url) {
        return base64_decode(b64url2b64($base64url));
    }
}

if (! function_exists('b64url2b64')) {
    /**
     * Per RFC4648, "base64 encoding with URL-safe and filename-safe
     * alphabet". This just replaces characters 62 and 63. None of the
     * reference implementations seem to restore the padding if necessary,
     * but we'll do it anyway.
     *
     * @param string $base64url
     * @return string
     */
    function b64url2b64($base64url) {
        // "Shouldn't" be necessary, but why not
        $padding = strlen($base64url) % 4;

        if ($padding > 0) {
            $base64url .= str_repeat('=', 4 - $padding);
        }

        return strtr($base64url, '-_', '+/');
    }
}

if (! function_exists('get_key_for_header')) {
    /**
     * Get the key algo header.
     *
     * @param array $keys
     * @param array|object $header
     * @return object
     *
     * @throws EcmXperts\Exception\LumenOauth2Exception
     */
    function get_key_for_header($keys, $header) {
        foreach ($keys as $key) {
            if ($key->kty === 'RSA') {
                if (!isset($header->kid) || $key->kid === $header->kid) {
                    return $key;
                }
            } else {
                if (isset($key->alg) && $key->alg === $header->alg && $key->kid === $header->kid) {
                    return $key;
                }
            }
        }

        if (isset($header->kid)) {
            throw new LumenOauth2Exception('Unable to find a key for (algorithm, kid):' . $header->alg . ', ' . $header->kid . ')');
        }
    }
}
