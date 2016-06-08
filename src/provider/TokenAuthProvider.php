<?php
namespace tuanlq11\token\provider;

use Phalcon\Config;
use Phalcon\Config\Adapter\Yaml;
use tuanlq11\token\Token;

/**
 * Class TokenAuthServiceProvider
 *
 * @author  tuanlq11
 * @package tuanlq11\token\providers
 */
class TokenAuthProvider extends Token
{
    /**
     * TokenAuthServiceProvider constructor.
     *
     * @param $globalConfig Config
     */
    public function __construct($globalConfig)
    {
        $config = new Yaml(__DIR__ . "/../config/config.yaml");
        $config->merge($globalConfig->tuanlq11->token);

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