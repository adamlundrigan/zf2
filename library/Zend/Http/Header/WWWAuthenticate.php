<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2012 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 * @package   Zend_Http
 */

namespace Zend\Http\Header;

/**
 * @throws Exception\InvalidArgumentException
 * @see http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.47
 */
class WWWAuthenticate implements MultipleHeaderInterface
{

    protected $realm;

    protected $nonce;

    protected $algorithm;

    protected $domain;

    protected $qop;

    protected $opaque;

    protected $stale;

    public static function fromString($headerLine)
    {
        /* @var $wwwAuthenticateProcessor Closure */
        static $wwwAuthenticateProcessor = null;

        if ($wwwAuthenticateProcessor === null) {
            $wwwAuthenticateClass = get_called_class();
            $wwwAuthenticateProcessor = function($headerLine) use ($wwwAuthenticateClass) {
                $header = new $wwwAuthenticateClass();
                $header->value = preg_replace('#^Digest #', '', $headerLine);
                $keyValuePairs = preg_split('#,\s*#', $header->getFieldValue());
                foreach ($keyValuePairs as $keyValue) {
                    // Extract the key and value
                    if (strpos($keyValue, '=')) {
                        list($headerKey, $headerValue) = preg_split('#=\s*#', $keyValue, 2);
                    } else {
                        $headerKey = $keyValue;
                        $headerValue = null;
                    }
                    // Strip off quotes around string literals
                    $headerValue = preg_replace('#^"(.*)"$#', '\1', $headerValue);

                    // Store the value in the header object by key
                    switch (str_replace(array('-', '_'), '', strtolower($headerKey))) {
                        case 'realm'     : $header->setRealm($headerValue); break;
                        case 'nonce'     : $header->setNonce($headerValue); break;
                        case 'algorithm' : $header->setAlgorithm($headerValue); break;
                        case 'domain'    : $header->setDomain($headerValue); break;
                        case 'qop'       : $header->setQop($headerValue); break;
                        case 'opaque'    : $header->setOpaque($headerValue); break;
                        case 'stale'     : $header->setStale($headerValue); break;
                        default:
                            // Intentionally omitted
                    }
                }

                return $header;
            };
        }

        list($name, $value) = explode(': ', $headerLine, 2);

        // check to ensure proper header type for this factory
        if (strtolower($name) !== 'www-authenticate') {
            throw new Exception\InvalidArgumentException('Invalid header line for WWW-Authenticate string: "' . $name . '"');
        }

        // @todo how to split multiple headers?
        return $wwwAuthenticateProcessor($value);
    }

    public function getFieldName()
    {
        return 'WWW-Authenticate';
    }

    public function getFieldValue()
    {
        return $this->value;
    }

    public function getRealm()
    {
        return $this->realm;
    }

    public function setRealm($realm)
    {
        $this->realm = $realm;
        return $this;
    }

    public function getNonce()
    {
        return $this->nonce;
    }

    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
        return $this;
    }

    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    public function setAlgorithm($alg)
    {
        $this->algorithm = $alg;
        return $this;
    }

    public function getDomain()
    {
        return $this->domain;
    }

    public function setDomain($domain)
    {
        $this->domain = $domain;
        return $this;
    }

    public function getQop()
    {
        return $this->qop;
    }

    public function setQop($qop)
    {
        $this->qop = $qop;
        return $this;
    }

    public function getOpaque()
    {
        return $this->opaque;
    }

    public function setOpaque($opaque)
    {
        $this->opaque = $opaque;
        return $this;
    }

    public function getStale()
    {
        return $this->stale;
    }

    public function setStale($stale)
    {
        $this->stale = $stale;
        return $this;
    }

    public function toString()
    {
        return 'WWW-Authenticate: ' . $this->getFieldValue();
    }

    public function toStringMultipleHeaders(array $headers)
    {
        $strings = array($this->toString());
        foreach ($headers as $header) {
            if (!$header instanceof WWWAuthenticate) {
                throw new Exception\RuntimeException(
                    'The WWWAuthenticate multiple header implementation can only accept an array of WWWAuthenticate headers'
                );
            }
            $strings[] = $header->toString();
        }
        return implode("\r\n", $strings);
    }
}
