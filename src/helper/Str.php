<?php
namespace tuanlq11\ptoken\helper;

use Phalcon\Exception;

class Str
{
    /**
     * Generate a more truly "random" alpha-numeric string.
     *
     * @param  int $length
     *
     * @return string
     *
     * @throws Exception
     */
    public static function str_random($length = 16)
    {
        $string = '';

        while (($len = strlen($string)) < $length) {
            $size = $length - $len;

            $bytes = static::randomBytes($size);

            $string .= substr(str_replace(['/', '+', '='], '', base64_encode($bytes)), 0, $size);
        }

        return $string;
    }

    /**
     * Generate a more truly "random" bytes.
     *
     * @param  int $length
     *
     * @return string
     *
     * @throws Exception
     */
    public static function randomBytes($length = 16)
    {
        if (PHP_MAJOR_VERSION >= 7 || defined('RANDOM_COMPAT_READ_BUFFER')) {
            $bytes = random_bytes($length);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes($length, $strong);

            if ($bytes === false || $strong === false) {
                throw new Exception('Unable to generate random string.');
            }
        } else {
            throw new Exception('OpenSSL extension or paragonie/random_compat is required for PHP 5 users.');
        }

        return $bytes;
    }
}