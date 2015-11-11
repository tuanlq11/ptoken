<?php
return [
  'secret' => env('TOKEN_SECRET', 'BupsNIvC$YE00495anfYz32&f19km43ymJ83b!ilT6tNgk5hNzFZKV&a$vqOEkdlA5ZfrS252flphjsIyusWbO7GTX%$v6c3rePR'),
  'alg'  => env('TOKEN_ALG', 'HS256'),
  'identify' => env('TOKEN_IDENTIFY', 'email'),
  'ttl' => env('TOKEN_TTL', 300), // Second,
  'ttl_blacklist' => env('TOKEN_BLACKLIST_TTL', 86400), // Second,
  'encrypt' => env('TOKEN_ENCRYPT', true),
  'error-code' => env('TOKEN_ERROR_CODE', 1)
];