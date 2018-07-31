<?php

namespace Spatie\UrlSigner;

use DateTime;
use League\Uri\Uri;
use League\Uri\Components\Query;
use League\Uri\QueryBuilder;
use Spatie\UrlSigner\Exceptions\InvalidExpiration;
use Spatie\UrlSigner\Exceptions\InvalidSignatureKey;

abstract class BaseUrlSigner implements UrlSigner
{
    /**
     * The key that is used to generate secure signatures.
     *
     * @var string
     */
    protected $signatureKey;

    /**
     * The URL's query parameter name for the expiration.
     *
     * @var string
     */
    protected $expiresParameter;

    /**
     * The URL's query parameter name for the signature.
     *
     * @var string
     */
    protected $signatureParameter;

    /**
     * @param string $signatureKey
     * @param string $expiresParameter
     * @param string $signatureParameter
     *
     * @throws InvalidSignatureKey
     */
    public function __construct($signatureKey, $expiresParameter = 'expires', $signatureParameter = 'signature')
    {
        if ($signatureKey == '') {
            throw new InvalidSignatureKey('The signature key is empty');
        }

        $this->signatureKey = $signatureKey;
        $this->expiresParameter = $expiresParameter;
        $this->signatureParameter = $signatureParameter;
    }

    abstract protected function createSignature($uri, $expiration);

    /**
     * Get a secure URI to a controller action.
     *
     * @param string        $uri
     * @param \DateTime|int $expiration
     * @throws InvalidExpiration
     * @return string
     */
    public function sign($uri, $expiration)
    {
        $uri = Uri::createFromString($uri);

        $expiration = $this->getExpirationTimestamp($expiration);
        $signature = $this->createSignature((string) $uri, $expiration);

        return (string) $this->signUri($uri, $expiration, $signature);
    }

    /**
     * Add expiration and signature query parameters to an uri.
     *
     * @param \League\Uri\Uri $url
     * @param string                   $expiration
     * @param string                   $signature
     *
     * @return \League\Uri\Uri
     */
    protected function signUri(Uri $uri, $expiration, $signature)
    {
        $builder = new QueryBuilder();
        $query = new Query($uri->getQuery());

        $signed = $builder->build([
            $this->expiresParameter   => $expiration,
            $this->signatureParameter => $signature,
        ]);

        $query = $query->merge($signed);

        $urlSigner = $uri->withQuery((string) $query);

        return $urlSigner;
    }

    /**
     * Validate a signed uri.
     *
     * @param string $uri
     *
     * @return bool
     */
    public function validate($uri)
    {
        $uri = Uri::createFromString($uri);

        $query = new Query($uri->getQuery());

        if ($this->isMissingAQueryParameter($query)) {
            return false;
        }

        $expiration = $query->getPair($this->expiresParameter);

        if (!$this->isFuture($expiration)) {
            return false;
        }

        if (!$this->hasValidSignature($uri)) {
            return false;
        }

        return true;
    }

    /**
     * Check if a query is missing a necessary parameter.
     *
     * @param \League\Uri\Components\Query $query
     *
     * @return bool
     */
    protected function isMissingAQueryParameter(Query $query)
    {
        $pairs = $query->getPairs();

        if (!isset($pairs[$this->expiresParameter])) {
            return true;
        }

        if (!isset($pairs[$this->signatureParameter])) {
            return true;
        }

        return false;
    }

    /**
     * Check if a timestamp is in the future.
     *
     * @param int $timestamp
     *
     * @return bool
     */
    protected function isFuture($timestamp)
    {
        return ((int) $timestamp) >= (new DateTime())->getTimestamp();
    }

    /**
     * Retrieve the intended URL by stripping off the UrlSigner specific parameters.
     *
     * @param \League\Uri\Uri $uri
     *
     * @return \League\Uri\Uri $uri
     */
    protected function getIntendedUrl(Uri $uri)
    {
        $query = new Query($uri->getQuery());

        $intendedQuery = $query->withoutPairs([
            $this->expiresParameter,
            $this->signatureParameter,
        ]);

        $intendedUri = $uri->withQuery((string) $intendedQuery);

        return $intendedUri;
    }

    /**
     * Retrieve the expiration timestamp for a link based on an absolute DateTime or a relative number of days.
     *
     * @param \DateTime|int $expiration The expiration date of this link.
     *                                  - DateTime: The value will be used as expiration date
     *                                  - int: The expiration time will be set to X days from now
     *
     * @throws \Spatie\UrlSigner\Exceptions\InvalidExpiration
     *
     * @return string
     */
    protected function getExpirationTimestamp($expiration)
    {
        if (is_int($expiration)) {
            $expiration = (new DateTime())->modify((int) $expiration.' days');
        }

        if (!$expiration instanceof DateTime) {
            throw new InvalidExpiration('Expiration date must be an instance of DateTime or an integer');
        }

        if (!$this->isFuture($expiration->getTimestamp())) {
            throw new InvalidExpiration('Expiration date must be in the future');
        }

        return (string) $expiration->getTimestamp();
    }

    /**
     * Determine if the url has a forged signature.
     *
     * @param \League\Uri\Uri $uri
     *
     * @return bool
     */
    protected function hasValidSignature(Uri $uri)
    {
        $query = new Query($uri->getQuery());

        $expiration = $query->getPair($this->expiresParameter);
        $providedSignature = $query->getPair($this->signatureParameter);

        $intendedUrl = $this->getIntendedUrl($uri);

        $validSignature = $this->createSignature($intendedUrl, $expiration);

        return hash_equals($validSignature, $providedSignature);
    }
}
