<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authentication\Guards;

use Ephraitech\Auth\Entities\User;

interface GuardInterface
{
    public function name(): string;

    public function check(): bool;

    public function user(): ?User;

    public function id(): ?int;

    public function logout(): void;
}
