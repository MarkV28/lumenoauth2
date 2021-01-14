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
     * Get the lastname for the user.
     *
     * @return string
     */
    public function lastname();

    /**
     * Get the middlename for the user.
     *
     * @return string
     */
    public function middlename();

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

    /**
     * Get the groups for the user.
     *
     * @return array
     */
    public function groups();

    /**
     * Get the permissions for the user.
     *
     * @return array
     */
    public function permissions();
}