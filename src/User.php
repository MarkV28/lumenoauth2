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
     * Get the lastname for the user.
     *
     * @return string
     */
    public function lastname()
    {
        return $this->attributes['lastname'];
    }

    /**
     * Get the middlename for the user.
     *
     * @return string
     */
    public function middlename()
    {
        return $this->attributes['middlename'];
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

    /**
     * Get the groups for the user.
     *
     * @return array
     */
    public function groups()
    {
        return $this->attributes['groups'];
    }

    /**
     * Get the permissions for the user.
     *
     * @return array
     */
    public function permissions()
    {
        return $this->attributes['permissions'];
    }
}