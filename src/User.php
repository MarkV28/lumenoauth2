<?php

namespace EcmXperts;

use Illuminate\Auth\GenericUser;
use EcmXperts\Contracts\User as UserContract;

class User extends GenericUser implements UserContract
{
    /**
     * Get the global unique identifier for the user.
     *
     * @return string
     */
    public function guid()
    {
        return $this->attributes['guid'];
    }

    /**
     * Get the firstname for the user.
     *
     * @return string
     */
    public function firstname()
    {
        return $this->attributes['firstname'];
    }

    /**
     * Get the surname for the user.
     *
     * @return string
     */
    public function surname()
    {
        return $this->attributes['surname'];
    }

    /**
     * Get the fullname for the user.
     *
     * @return string
     */
    public function fullname()
    {
        return $this->attributes['fullname'];
    }

    /**
     * Get the tenant global identifier for the user.
     *
     * @return string
     */
    public function tenant()
    {
        return $this->attributes['tenant'];
    }
}