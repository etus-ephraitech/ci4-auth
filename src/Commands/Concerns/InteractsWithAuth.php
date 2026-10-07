<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Commands\Concerns;

use CodeIgniter\CLI\CLI;
use CodeIgniter\Config\Factories;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Models\UserModel;

/**
 * Shared helpers for the auth:* commands.
 */
trait InteractsWithAuth
{
    /**
     * @param array<int|string, string|null> $params
     */
    protected function hasOption(array $params, string $name): bool
    {
        return array_key_exists($name, $params) || array_key_exists($name, CLI::getOptions());
    }

    /**
     * Option value; NULL when absent or given as a bare flag.
     *
     * @param array<int|string, string|null> $params
     */
    protected function option(array $params, string $name): ?string
    {
        $value = $params[$name] ?? CLI::getOption($name);

        return is_string($value) ? $value : null;
    }

    /**
     * @param array<int|string, string|null> $params
     */
    protected function interactive(array $params): bool
    {
        return ! $this->hasOption($params, 'no-interaction');
    }

    /**
     * --tenant=<id> targets that tenant; --tenant=global (or empty) targets
     * global scope. Absent = NULL (global in CLI, where no tenant context exists).
     *
     * @param array<int|string, string|null> $params
     */
    protected function tenantOption(array $params): ?string
    {
        if (! $this->hasOption($params, 'tenant')) {
            return null;
        }

        $value = trim((string) ($this->option($params, 'tenant') ?? ''));

        return $value === '' || strtolower($value) === 'global' ? '' : $value;
    }

    /**
     * Comma-separated option as a list, or NULL when absent.
     *
     * @param array<int|string, string|null> $params
     *
     * @return list<string>|null
     */
    protected function listOption(array $params, string $name): ?array
    {
        $value = $this->option($params, $name);

        if ($value === null) {
            return null;
        }

        return array_values(array_filter(
            array_map('trim', explode(',', $value)),
            static fn(string $item): bool => $item !== ''
        ));
    }

    /**
     * Find a user by numeric ID, UUID, or any enabled identifier
     * (email, username, phone). Purely numeric input is treated as an ID.
     */
    protected function resolveUser(?string $reference): ?User
    {
        $reference = trim((string) $reference);

        if ($reference === '') {
            return null;
        }

        /** @var Auth $config */
        $config = config(Auth::class);

        /** @var UserModel $users */
        $users = Factories::models($config->userModel, ['preferApp' => false]);

        if (ctype_digit($reference)) {
            $user = $users->find((int) $reference);

            return $user instanceof User ? $user : null;
        }

        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $reference) === 1) {
            return $users->findByUuid($reference);
        }

        foreach ($config->identifiers as $type) {
            $user = $users->findByIdentifier($type, $reference);

            if ($user !== null) {
                return $user;
            }
        }

        return null;
    }

    /**
     * Read a line without echoing it (hidden on Linux/macOS terminals).
     */
    protected function promptSecret(string $label): string
    {
        $canHide = PHP_OS_FAMILY !== 'Windows'
            && function_exists('shell_exec')
            && stream_isatty(STDIN);

        if (! $canHide) {
            CLI::write('Note: input will be visible on this terminal.', 'yellow');
        }

        CLI::print($label . ': ');

        if ($canHide) {
            shell_exec('stty -echo');
        }

        $value = fgets(STDIN);

        if ($canHide) {
            shell_exec('stty echo');
            CLI::newLine();
        }

        return $value === false ? '' : rtrim($value, "\r\n");
    }

    protected function describeUser(User $user): string
    {
        $label = $user->email ?? $user->username ?? $user->phone ?? 'no identifiers';

        return "#{$user->id} ({$label})";
    }
}
