<?php

namespace App\Services\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;

class JwtGuard implements Guard
{
    protected $jwtSecret;
    protected $user;

    public function __construct($jwtSecret, $user)
    {
        $this->jwtSecret = $jwtSecret;
        $this->user = $user;
    }

    public function check()
    {
        return !is_null($this->user());
    }

    public function guest()
    {
        return !$this->check();
    }

    public function user()
    {
        if ($this->provider) {
            return $this->provider->getJWTCustomClaims();
        }
    }

    public function id()
    {
        if ($this->provider instanceof JWTSubject) {
            return $this->provider->getJWTIdentifier();
        }
    }

    public function validate(array $credentials = [])
    {
        if (empty($credentials) || !isset($credentials['token'])) {
            return false;
        }

        try {
            $user = JWTAuth::setToken($credentials['token'])->authenticate();
            return !is_null($user);
        } catch (\Exception $e) {
            return false;
        }
    }

    public function hasUser()
    {
        return !is_null($this->provider->user());
    }

    public function setUser(Authenticatable $user)
    {
        $this->provider = $user;
        return $this;
    }

    public function getProvider()
    {
        return $this->provider;
    }

    public function setProvider($provider)
    {
        $this->provider = $provider;
        return $this;
    }

    public function getTokenForRequest()
    {
        // Logic to retrieve token from the request (e.g., headers, cookies, etc.)
    }
}
