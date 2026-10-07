<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ephraitech\Auth\Commands\Concerns\InteractsWithAuth;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;
use Ephraitech\Auth\Exceptions\RegistrationException;

class AuthUserCreate extends BaseCommand
{
    use InteractsWithAuth;

    private const MAX_PASSWORD_TRIES = 3;

    protected $group       = 'Ephraitech Auth';
    protected $name        = 'auth:user:create';
    protected $description = 'Creates a user (e.g. the first superadmin). Prompts for anything not given.';
    protected $usage       = 'auth:user:create [--email=] [--username=] [--phone=] [--role=a,b] [options]';
    protected $options     = [
        '--email'          => 'Email address.',
        '--username'       => 'Username.',
        '--phone'          => 'Phone number (local formats accepted).',
        '--password'       => 'Password (avoid: may be stored in shell history).',
        '--generate'       => 'Generate a strong password and print it once.',
        '--role'           => 'Comma-separated roles (default: Config\Auth::$defaultRoles).',
        '--tenant'         => 'Tenant for the roles; "global" for all tenants.',
        '--verified'       => 'Mark the given identifiers as verified.',
        '--skip-policy'    => 'Skip password policy checks (trusted setups only).',
        '--no-interaction' => 'Never prompt; fail if required input is missing.',
    ];

    /**
     * @param array<int|string, string|null> $params
     */
    public function run(array $params)
    {
        /** @var Auth $config */
        $config      = config(Auth::class);
        $interactive = $this->interactive($params);
        $identifiers = $this->collectIdentifiers($params, $config, $interactive);
        $generated   = false;

        if ($this->hasOption($params, 'generate')) {
            $password  = $this->generatePassword($identifiers);
            $generated = true;
        } elseif (($given = $this->option($params, 'password')) !== null && $given !== '') {
            $password = $given;
            CLI::write('Warning: passwords given as options may be saved in your shell history.', 'yellow');
        } elseif (! $interactive) {
            CLI::error('Provide --password or --generate when using --no-interaction.');

            return EXIT_ERROR;
        } else {
            $password = $this->askPassword();

            if ($password === null) {
                CLI::error('Passwords did not match. No user was created.');

                return EXIT_ERROR;
            }
        }

        $roles = $this->listOption($params, 'role');

        if ($roles === null && $interactive) {
            $answer = CLI::prompt('Roles (comma-separated)', implode(',', $config->defaultRoles));
            $roles  = array_values(array_filter(array_map('trim', explode(',', $answer))));
        }

        try {
            $user = service('authRegistrar')->register(
                $identifiers,
                $password,
                [],
                [
                    'roles'         => $roles ?? $config->defaultRoles,
                    'tenant'        => $this->tenantOption($params),
                    'verified'      => $this->hasOption($params, 'verified') ? array_keys($identifiers) : [],
                    'enforcePolicy' => ! $this->hasOption($params, 'skip-policy'),
                ]
            );
        } catch (RegistrationException $e) {
            CLI::error('The user could not be created:');

            foreach ($e->getErrors() as $field => $messages) {
                foreach ($messages as $message) {
                    CLI::write("  {$field}: {$message}", 'red');
                }
            }

            return EXIT_ERROR;
        } catch (AuthException $e) {
            CLI::error($e->getMessage());

            return EXIT_ERROR;
        }

        CLI::write('User created: ' . $this->describeUser($user), 'green');
        CLI::write('UUID:  ' . ($user->uuid ?? '-'));
        CLI::write('Roles: ' . (implode(', ', service('authAuthorizer')->rolesFor($user, $this->tenantOption($params))) ?: '-'));

        if ($generated) {
            CLI::newLine();
            CLI::write('Generated password (shown once, store it now):', 'yellow');
            CLI::write($password, 'light_green');
        }

        return EXIT_SUCCESS;
    }

    /**
     * @param array<int|string, string|null> $params
     *
     * @return array<string, string>
     */
    private function collectIdentifiers(array $params, Auth $config, bool $interactive): array
    {
        $identifiers = [];

        foreach ($config->identifiers as $type) {
            $value = trim((string) ($this->option($params, $type) ?? ''));

            if ($value === '' && $interactive) {
                $required = $config->isIdentifierRequired($type);
                $label    = ucfirst(InvalidIdentifierException::label($type)) . ($required ? '' : ' (optional)');
                $value    = trim($required ? CLI::prompt($label, null, 'required') : CLI::prompt($label));
            }

            if ($value !== '') {
                $identifiers[$type] = $value;
            }
        }

        return $identifiers;
    }

    private function askPassword(): ?string
    {
        for ($try = 1; $try <= self::MAX_PASSWORD_TRIES; $try++) {
            $password = $this->promptSecret('Password');
            $confirm  = $this->promptSecret('Confirm password');

            if ($password !== '' && hash_equals($password, $confirm)) {
                return $password;
            }

            CLI::write('Passwords were empty or did not match, try again.', 'red');
        }

        return null;
    }

    /**
     * A random password that satisfies the configured policy.
     *
     * @param array<string, string> $identifiers
     */
    private function generatePassword(array $identifiers): string
    {
        $policy = service('authPasswords')->policy();

        for ($i = 0; $i < 50; $i++) {
            $candidate = rtrim(strtr(base64_encode(random_bytes(15)), '+/', '-_'), '=') . random_int(10, 99) . '!';

            if ($policy->errors($candidate, $identifiers) === []) {
                return $candidate;
            }
        }

        throw new AuthException('Could not generate a password that satisfies the policy; use --password.');
    }
}
