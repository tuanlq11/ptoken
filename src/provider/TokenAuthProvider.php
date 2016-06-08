<?php
namespace tuanlq11\ptoken\provider;

use Phalcon\Config;
use Phalcon\Config\Adapter\Yaml;
use Phalcon\Di;
use Phalcon\DiInterface;
use Phalcon\Security;
use tuanlq11\ptoken\helper\Cipher;
use tuanlq11\ptoken\Token;

/**
 * Class TokenAuthServiceProvider
 *
 * @author  tuanlq11
 * @package tuanlq11\ptoken\providers
 */
class TokenAuthProvider extends Token
{
    /**
     * TokenAuthServiceProvider constructor.
     *
     */
    public function __construct(DiInterface $di)
    {
        $config = new Yaml(__DIR__ . "/../config/config.yaml");
        $config->merge($di["config"]->get("tuanlq11", new Config(["tuanlq11" => ["token" => []]])));

        $this->cipher = new Cipher($config->tuanlq11->token->secret_cipher);
        $this->di     = $di;

        return parent::__construct(
            $config->tuanlq11->token->alg,
            $config->tuanlq11->token->identify,
            $config->tuanlq11->token->secret,
            $config->tuanlq11->token->ttl,
            $config->tuanlq11->token->ttl_blacklist,
            $config->tuanlq11->token->encrypt
        );
    }
}