<?php

namespace EcmXperts;

class LumenOauth2
{
    /**
     * Handle dynamic, static calls to the object.
     *
     * @param string $method
     * @param array $arguments
     * @return mixed
     */
    public static function __callStatic($method, $arguments)
    {
        return (new LumenOauth2Client)->$method(...$arguments);
    }
}
