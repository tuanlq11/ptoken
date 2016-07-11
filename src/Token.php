<?php

namespace tuanlq11\ptoken;

use Phalcon\Cache\Backend;
use Phalcon\DiInterface;
use Phalcon\Exception;
use Phalcon\Http\Request;
use Phalcon\Security;
use tuanlq11\ptoken\helper\Cipher;
use tuanlq11\ptoken\helper\Str;
use tuanlq11\ptoken\signer\Signer;

/**
 * Class Token
 *
 * @author  tuanlq11
 * @package tuanlq11\ptoken
 */
class Token
{
    /** @var String */
    protected $remember_token;

    /** @var Signer */
    protected $signer;

    /** @var  JWT */
    protected $jwt;

    /** @var  String */
    protected $alg;

    /** @var  String */
    protected $identify;

    /** @var  String */
    protected $secret;

    /** @var  Integer */
    protected $ttl;

    /** @var  Integer */
    protected $blacklist_ttl;

    /** @var  bool */
    protected $encrypt;

    /** @var  Cipher */
    protected $cipher;

    /** @var  DiInterface */
    protected $di;

    /** Static prefix cache key */
    const PREFIX_CACHE_KEY = 'tuanlq11.token.blacklist.';

    /** @var  Token */
    private static $instance;

    /**
     * @return Signer
     */
    public function getSigner()
    {
        return $this->signer;
    }

    /**
     * @param Signer $signer
     */
    public function setSigner($signer)
    {
        $this->signer = $signer;
    }

    /**
     * @return JWT
     */
    public function getJwt()
    {
        return $this->jwt;
    }

    /**
     * @param JWT $jwt
     */
    public function setJwt($jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * @return String
     */
    public function getAlg()
    {
        return $this->alg;
    }

    /**
     * @param String $alg
     */
    public function setAlg($alg)
    {
        $this->alg = $alg;
    }

    /**
     * @return String
     */
    public function getIdentify()
    {
        return $this->identify;
    }

    /**
     * @param String $identify
     */
    public function setIdentify($identify)
    {
        $this->identify = $identify;
    }

    /**
     * @return String
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * @param String $secret
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * @return int
     */
    public function getTtl()
    {
        return $this->ttl;
    }

    /**
     * @param int $ttl
     */
    public function setTtl($ttl)
    {
        $this->ttl = $ttl;
    }

    /**
     * @return boolean
     */
    public function isEncrypt()
    {
        return $this->encrypt;
    }

    /**
     * @param boolean $encrypt
     */
    public function setEncrypt($encrypt)
    {
        $this->encrypt = $encrypt;
    }

    /**
     * @return String
     */
    public function getRememberToken()
    {
        return $this->remember_token;
    }

    /**
     * @param $remember_token
     *
     * @return $this
     */
    public function setRememberToken($remember_token)
    {
        $this->remember_token = $remember_token;

        return $this;
    }

    /**
     * @return int
     */
    public function getBlacklistTtl()
    {
        return $this->blacklist_ttl;
    }

    /**
     * @param int $blacklist_ttl
     */
    public function setBlacklistTtl($blacklist_ttl)
    {
        $this->blacklist_ttl = $blacklist_ttl;
    }

    /**
     * Generate remember token
     *
     * @param string $uid
     *
     * @return string
     */
    public function generateRememberToken($uid = '')
    {
        $this->setRememberToken(md5(microtime() . $uid . Str::str_random()));

        return $this->getRememberToken();
    }

    /**
     * Token constructor.
     *
     * @param $alg
     * @param $identify
     * @param $secret
     * @param $ttl_blacklist
     * @param $encrypt
     */
    function __construct($alg, $identify, $secret, $ttl, $ttl_blacklist, $encrypt)
    {
        $this->setAlg($alg);
        $this->setIdentify($identify);
        $this->setSecret($secret);
        $this->setTtl($ttl);
        $this->setBlacklistTtl($ttl_blacklist);
        $this->setEncrypt($encrypt);

        $this->request = new Request();

        return $this;
    }

    /**
     * Generate instance for static
     *
     * @return Token
     */
    public static function getInstance()
    {
        if (self::$instance == null) {
            self::$instance = new Token();
        }

        return self::$instance;
    }

    /**
     * Generate token from UID
     *
     * @param $uid mixed
     *
     * @return bool
     */
    public function attempt($uid)
    {
        /** Remember Token */
        $remember_token = $this->generateRememberToken($uid);
        /** End */

        $payload = new Payload($uid, time() + $this->getTtl(), null, null, null, $remember_token);
        $payload->generateSalt($this->getSecret());

        return $this->toToken($payload);
    }

    /**
     * Response User from token
     *
     * @param $token
     *
     * @deprecated
     *
     * @return bool
     */
    public function fromToken($token = null)
    {
        if (!($token = $token ? $token : $this->request->getHeader('token'))) {
            $token = $this->request->get('token');
        }


        try {
            $token = $this->isEncrypt() ? $this->cipher->decrypt($token) : $token;
        } catch (Exception $e) {
            return false;
        }

        $key = self::PREFIX_CACHE_KEY . $token;

        if ($this->di["cache"]->exists($key)) {
            return false;
        }

        if (!($signer = Signer::getInstance($token))) {
            return false;
        }

        $result = $signer->verify($this->getSecret());
        /** @var Payload $payload */
        $payload = $result['data'];
        if ($result['error'] == 0) {
            return $payload->getUid();
        }

        return false;
    }

    /**
     * Response User && Remember Token from token
     * error code: 0 - pass; 1 - invalid; 2 - remember; 3 - Decrypt problem; 4 - Blacklist; 5 - Signer error
     *
     * @param $token
     *
     * @return bool
     */
    public function fromTokenFull($token = null)
    {
        $key    = self::PREFIX_CACHE_KEY . $token;
        $result = ['error' => 1, 'uid' => null, 'token' => null];

        if (!($token = $token ? $token : $this->request->get('token'))) {
            $token = $this->request->get('token');
        }
        $remember_token = $this->request->get('remember_token', null, false);

        try {
            $token = $this->isEncrypt() ? $this->cipher->decrypt($token) : $token;
        } catch (Exception $e) {
            $result['error'] = 3;

            return $result;
        }

        if ($this->di["cache"]->exists($key)) {
            $result['error'] = 4;

            return $result;
        }

        if (!($signer = Signer::getInstance($token))) {
            $result['error'] = 5;

            return $result;
        }

        $payloadResult = $signer->verify($this->getSecret(), $remember_token);
        /** @var Payload $payload */
        $payload = $payloadResult['data'];
        if ($payloadResult['error'] == 0) {
            $result['error'] = 0;
            $result['uid']   = $payload->getUid();
            $result['token'] = $token;

            return $result;
        }

        /** Use remember token */
        if ($payloadResult['error'] == 2) {
            $result['error'] = 2;
            $result['uid']   = $payload->getUid();
            $result['token'] = $token;

            return $result;
        }

        /** End */

        return $result;
    }

    /**
     * @param $rawToken
     *
     * @return bool
     */
    public function refresh($rawToken)
    {
        $data = $this->fromTokenFull($rawToken);

        if ($data['error'] != 1) {
            $token = $data['token'];
            $uid   = $data['uid'];

            /** Remember Token */
            $remember_token = $this->generateRememberToken($uid);
            /** End */

            $payload = new Payload($uid, time() + $this->getTtl(), null, null, null, $remember_token);
            $payload->generateSalt($this->getSecret());
            $newToken = $this->toToken($payload);

            // Blacklist
            $key = self::PREFIX_CACHE_KEY . $token;
            $this->di["cache"]->save($key, [], time() + $this->getBlacklistTtl());

            // End

            return $newToken;
        }


        return false;
    }

    /**
     * Block token
     *
     * @param $token
     *
     * @return boolean
     */
    public function block($token)
    {
        $data = $this->fromTokenFull($token);

        if ($data['error'] != 1) {
            $token = $data['token'];

            // Blacklist
            $key = self::PREFIX_CACHE_KEY . $token;
            $this->di["cache"]->save($key, [], time() + $this->getBlacklistTtl());

            // End

            return true;
        }

        return false;
    }

    /**
     * @param $payload Payload
     *
     * @return string
     */
    protected function toToken($payload)
    {
        $signer = new Signer();
        $signer->setHeader(['alg' => $this->getAlg()]);
        $signer->setEncoder($signer->getEncoderInstance());
        $signer->setPayload($payload);
        $signer->sign($this->getSecret());

        $token = $signer->getTokenString();
        $token = $this->isEncrypt() ? $this->cipher->encrypt($token) : $token;

        return $token;
    }

}