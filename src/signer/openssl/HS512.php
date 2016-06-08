<?php

namespace tuanlq11\ptoken\signer\openssl;
/**
 * Created by PhpStorm.
 * User: tuanlq11
 * Date: 9/11/15
 * Time: 10:43 AM
 */
class HS512 extends HMac
{
  public function getAlg()
  {
    return 'sha512';
  }

}