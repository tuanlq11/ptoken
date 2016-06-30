<?php

namespace tuanlq11\ptoken\middleware;

use Phalcon\Config;
use Phalcon\Events\Event;
use Phalcon\Mvc\Dispatcher;
use Phalcon\Mvc\User\Plugin;
use Phalcon\Config\Adapter\Yaml;

/**
 * Class TokenMiddleware
 *
 * GuardPlugin check token valid
 *
 * @package tuanlq11\ptoken\middleware
 */
class TokenMiddleware extends Plugin
{
    /**
     * Middleware gateway check token authenticate
     *
     * @param $event      Event
     * @param $dispatcher Dispatcher
     *
     * @return bool
     */
    public function beforeExecuteRoute($event, $dispatcher)
    {
        $config = new Yaml(__DIR__ . "/../config/config.yaml");
        $config->tuanlq11->merge($this->config->get("tuanlq11", new Config(["tuanlq11" => ["token" => []]])));

        $this->response->setContentType("application/json");

        $result = [
            'error'   => $config->tuanlq11->token->error_code,
            'message' => '',
        ];

        $token = $this->request->getHeader('token');

        if (!$token) {
            $result['message'] = 'Token is empty';

            $this->response->setJsonContent($result)->send();

            return false;
        }

        if (!($uid = $this->token->fromToken($token))) {
            $result['message'] = 'Token is invalid or exired';

            $this->response->setJsonContent($result)->send();

            return false;
        }

        return $uid;
    }
}