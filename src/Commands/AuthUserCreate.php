<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use CodeIgniter\Config\Factories;
use Ephraitech\Auth\Commands\Concerns\InteractsWithAuth;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Config\ConfigResolver;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;
use Ephraitech\Auth\Exceptions\RegistrationException;
use Ephraitech\Auth\Models\UserModel;

class AuthUserCreate extends BaseCommand
{
    use InteractsWithAuth;

    private const MAX_PASSWORD_TRIES = 3;

    protected $group       = 'Ephraitech Auth';
    protected $name        = 'auth:user:create';
    protected $description = 'Creates a user (e.g. the first superadmin). Prompts for anything not given.';
    protected $usage       = 'auth:user:create [--email=] [--username=] [--phone=] [--role=a,b] [--first-name=...] [options]';
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
        '--<column>'       => 'Any user profile column from $userAllowedFields, e.g. --first-name=Jane --job-title="Director".',
    ];

    /**
     * @param array<int|string, string|null> $params
     */
    public function run(array $params)
    {
        $config        = ConfigResolver::resolve();
        $profileFields = $this->profileFields($config);
        $unknown       = $this->unknownOptions($params, $config, $profileFields);

        if ($unknown !== []) {
            CLI::error('Unknown option(s): --' . implode(', --', $unknown) . '.');
            CLI::write(
                'Profile columns you can set: '
                    . ($profileFields === [] ? '(none; add them to Config\Auth::$userAllowedFields)' : '--' . implode(', --', array_map(
                        static fn (string $f): string => str_replace('_', '-', $f),
                        $profileFields
                    ))),
                'yellow'
            );

            return EXIT_ERROR;
        }

        $interactive = $this->interactive($params);
        $identifiers = $this->collectIdentifiers($params, $config, $interactive);
        $attributes  = $this->collectAttributes($params, $config, $profileFields, $interactive);
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
                $attributes,
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

        foreach ($attributes as $column => $value) {
            CLI::write(str_pad($column . ':', 7) . ' ' . $value);
        }
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

    /**
     * Profile columns the user model accepts (from $userAllowedFields and
     * a custom model's own $allowedFields).
     *
     * @return list<string>
     */
    private function profileFields(Auth $config): array
    {
        /** @var UserModel $users */
        $users = Factories::models($config->userModel, ['preferApp' => false]);

        return $users->profileFields();
    }

    /**
     * Values for profile columns: given as --first-name or --first_name,
     * or prompted for when listed in $registrationFields.
     *
     * @param array<int|string, string|null> $params
     * @param list<string>                   $profileFields
     *
     * @return array<string, string>
     */
    private function collectAttributes(array $params, Auth $config, array $profileFields, bool $interactive): array
    {
        $options    = $this->cliOptions($params);
        $attributes = [];

        foreach ($profileFields as $column) {
            $value = $options[$column] ?? $options[str_replace('_', '-', $column)] ?? null;

            if ($value === null && $interactive && isset($config->registrationFields[$column])) {
                $value = CLI::prompt($config->registrationFields[$column] . ' (optional)');
            }

            $value = trim((string) $value);

            if ($value !== '') {
                $attributes[$column] = $value;
            }
        }

        return $attributes;
    }

    /**
     * Options that are neither command options, identifiers nor profile
     * columns, so a typo fails instead of being silently ignored.
     *
     * @param array<int|string, string|null> $params
     * @param list<string>                   $profileFields
     *
     * @return list<string>
     */
    private function unknownOptions(array $params, Auth $config, array $profileFields): array
    {
        $known = array_map(static fn (string $o): string => ltrim($o, '-'), array_keys($this->options));
        // spark's own global option, which CodeIgniter leaves in $params.
        $known = array_merge($known, Auth::SUPPORTED_IDENTIFIERS, ['no-header']);

        foreach ($profileFields as $column) {
            $known[] = $column;
            $known[] = str_replace('_', '-', $column);
        }

        return array_values(array_diff(array_keys($this->cliOptions($params)), $known));
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
