<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Api;

use Ephraitech\Auth\Entities\AccessToken;
use Ephraitech\Auth\Entities\User;

/**
 * Shapes the "user" object returned by the API. Implementations are built
 * as `new YourTransformer(Ephraitech\Auth\Config\Auth $config)`.
 */
interface UserTransformerInterface
{
    /**
     * @param AccessToken|null $token The token the request is authenticated
     *                                with (or was just issued), if any.
     *
     * @return array<string, mixed>
     */
    public function transform(User $user, ?AccessToken $token = null): array;
}
