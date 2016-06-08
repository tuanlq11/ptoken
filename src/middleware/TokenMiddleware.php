<?php

namespace tuanlq11\token\middleware;

use Phalcon\Dispatcher;
use Phalcon\Events\Event;
use Phalcon\Mvc\User\Plugin;
use tuanlq11\token\Token;
use Phalcon\Config\Adapter\Yaml;

/**
 * Class TokenMiddleware
 *
 * GuardPlugin check token valid
 *
 * @package tuanlq11\token\middleware
 */
class TokenMiddleware extends Plugin
{
    public function beforeExecuteRoute(Event $event, Dispatcher $dispatcher)
    {
        $config = new Yaml(__DIR__ . "/../config/config.yaml");
        $config->merge($this->config->tuanlq11->token);

        $this->response->setContentType("application/json");

        $result = [
            'error'   => $config->tuanlq11->token->error_code,
            'message' => '',
        ];

        $token = $this->request->get('token');

        if (!$token) {
            $result['message'] = 'Token is empty';

            $this->response->setJsonContent($result)->send();

            return false;
        }

        $tokenMgr = new Token();
        if (!$tokenMgr->fromToken($token)) {
            $result['message'] = 'Token is invalid or exired';

            $this->response->setJsonContent($result)->send();

            return false;
        }
    }
}