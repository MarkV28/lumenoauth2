<?php

namespace EcmXperts\Contracts;

interface User
{
    /**
     * Get the global unique identifier for the user.
     *
     * @return string
     */
    public function guid();

    /**
     * Get the firstname for the user.
     *
     * @return string
     */
    public function firstname();

    /**
     * Get the surname for the user.
     *
     * @return string
     */
    public function surname();

    /**
     * Get the fullname for the user.
     *
     * @return string
     */
    public function fullname();

    /**
     * Get the tenant global identifier for the user.
     *
     * @return string
     */
    public function tenant();
}