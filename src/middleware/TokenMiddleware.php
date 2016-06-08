<?php

namespace tuanlq11\token\middleware;

use Phalcon\Mvc\User\Plugin;
use tuanlq11\token\Token;
use Closure;

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
        $this->response->setContentType("application/json");

        $result = [
            'error'   => \Config::get('token.error-code'),
            'message' => '',
        ];

        $token = $request->get('token', false);

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