<?php

namespace Spatie\UrlSigner;

class MD5UrlSigner extends BaseUrlSigner
{
    /**
     * Generate a token to identify the secure action.
     *
     * @param \League\Uri\Uri|string $uri
     * @param string                          $expiration
     *
     * @return string
     */
    protected function createSignature($uri, $expiration)
    {
        $uri = (string) $uri;

        return md5("{$uri}::{$expiration}::{$this->signatureKey}");
    }
}
