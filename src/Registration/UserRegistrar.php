<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Registration;

use CodeIgniter\Config\Factories;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Events\Events;
use Config\Database;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Authorization\Authorizer;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\IdentifierTakenException;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;
use Ephraitech\Auth\Exceptions\RegistrationException;
use Ephraitech\Auth\Models\IdentityModel;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Passwords\PasswordManager;
use Throwable;

/**
 * Creates a complete account atomically:
 *   user row + normalized identities + password hash + default roles.
 *
 * Phase 1 validates everything and throws RegistrationException with all
 * field errors at once. Phase 2 writes inside one transaction. The
 * REGISTERED event fires only after commit.
 */
final class UserRegistrar
{
    private BaseConnection $db;

    public function __construct(
        private readonly Auth $config,
        private readonly UserModel $users,
        private readonly IdentityModel $identities,
        private readonly PasswordManager $passwords,
        private readonly Authorizer $authorizer,
    ) {
        $this->db = Database::connect($config->DBGroup);
    }

    public static function create(?Auth $config = null, ?Authorizer $authorizer = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var UserModel $users */
        $users = Factories::models($config->userModel, ['preferApp' => false]);

        /** @var IdentityModel $identities */
        $identities = Factories::models(IdentityModel::class, ['preferApp' => false]);

        return new self(
            $config,
            $users,
            $identities,
            PasswordManager::create($config),
            $authorizer ?? Authorizer::create($config),
        );
    }

    /**
     * Register a user.
     *
     * @param array<string, string|null> $identifiers Raw input keyed by type,
     *                                                e.g. ['email' => ..., 'phone' => ...].
     *                                                Empty values are ignored.
     * @param string|null                $password    NULL only with passwordOptional
     *                                                (e.g. admin invites; the user sets it later).
     * @param array<string, mixed>       $attributes  Profile columns (must be in the
     *                                                model's profileFields()).
     * @param array{
     *     status?: string,
     *     roles?: list<string>,
     *     tenant?: string|null,
     *     verified?: list<string>,
     *     enforcePolicy?: bool,
     *     passwordOptional?: bool
     * } $options
     *   status           Override $defaultUserStatus (e.g. 'pending' until verified).
     *   roles            Override $defaultRoles.
     *   tenant           Tenant for the role assignments (NULL = current tenant context).
     *   verified         Identifier types to mark verified immediately (trusted sources only).
     *   enforcePolicy    false for trusted paths (seeders/CLI); default true.
     *   passwordOptional Allow registering without a password.
     *
     * @throws RegistrationException User-facing validation errors.
     * @throws AuthException         Developer/configuration errors.
     */
    public function register(
        array $identifiers,
        ?string $password,
        array $attributes = [],
        array $options = [],
    ): User {
        $this->assertAttributes($attributes);

        $status     = $this->resolveStatus($options);
        $normalized = $this->validate($identifiers, $password, $options);
        $verified   = $options['verified'] ?? [];
        $roles      = array_values(array_unique($options['roles'] ?? $this->config->defaultRoles));
        $tenant     = $options['tenant'] ?? null;
        $userId     = null;

        $this->db->transBegin();

        try {
            $userId = $this->insertUser($attributes, $status);

            foreach ($normalized as $type => $value) {
                $this->identities->setIdentifier($userId, $type, $value, in_array($type, $verified, true));
            }

            if ($password !== null) {
                // Policy already enforced in validate(); the manager still
                // refuses empty values and NUL bytes.
                $this->passwords->setPassword($userId, $password, false);
            }

            foreach ($roles as $role) {
                $this->authorizer->assignRole($userId, $role, $tenant);
            }

            if ($this->db->transStatus() === false) {
                throw new AuthException('Database transaction failed while registering the user.');
            }

            $this->db->transCommit();
        } catch (IdentifierTakenException $e) {
            // Lost a race: someone claimed the identifier between validation and insert.
            $this->rollback($userId);

            throw new RegistrationException([$e->getIdentifierType() => [$e->getMessage()]]);
        } catch (Throwable $e) {
            $this->rollback($userId);

            throw $e;
        }

        $user = $this->users->find($userId);

        if (! $user instanceof User) {
            throw new AuthException("User {$userId} could not be loaded after registration.");
        }

        Events::trigger(AuthEvents::REGISTERED, $user);

        return $user;
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /**
     * @param array<string, string|null> $identifiers
     * @param array<string, mixed>       $options
     *
     * @return array<string, string> Normalized identifiers keyed by type.
     *
     * @throws RegistrationException
     */
    private function validate(array $identifiers, ?string $password, array $options): array
    {
        $errors     = [];
        $normalized = [];
        $normalizer = $this->identities->normalizer();

        foreach ($identifiers as $type => $value) {
            $type = (string) $type;

            if ($value === null || trim((string) $value) === '') {
                continue;
            }

            if (! in_array($type, Auth::SUPPORTED_IDENTIFIERS, true) || ! $this->config->isIdentifierEnabled($type)) {
                $errors[$type][] = 'Registering with a ' . InvalidIdentifierException::label($type) . ' is not enabled.';

                continue;
            }

            try {
                $clean = $normalizer->normalize($type, (string) $value);
            } catch (InvalidIdentifierException $e) {
                $errors[$type][] = $e->getMessage();

                continue;
            }

            if ($this->identities->identifierExists($type, $clean)) {
                $errors[$type][] = IdentifierTakenException::forType($type)->getMessage();

                continue;
            }

            $normalized[$type] = $clean;
        }

        foreach ($this->config->requiredIdentifiers as $type) {
            if (! isset($normalized[$type]) && ! isset($errors[$type])) {
                $errors[$type][] = InvalidIdentifierException::empty($type)->getMessage();
            }
        }

        if ($password === null) {
            if (empty($options['passwordOptional'])) {
                $errors['password'][] = 'Please provide a password.';
            }
        } elseif ($options['enforcePolicy'] ?? true) {
            foreach ($this->passwords->policy()->errors($password, $normalized) as $message) {
                $errors['password'][] = $message;
            }
        } elseif ($password === '' || str_contains($password, "\0")) {
            $errors['password'][] = 'The password cannot be empty or contain invalid characters.';
        }

        if ($errors !== []) {
            throw new RegistrationException($errors);
        }

        return $normalized;
    }

    /**
     * Unknown or package-managed keys are a programming error, not user
     * input, so they raise AuthException rather than a field error.
     *
     * @param array<string, mixed> $attributes
     *
     * @throws AuthException
     */
    private function assertAttributes(array $attributes): void
    {
        $protected = array_intersect(array_keys($attributes), UserModel::BASE_ALLOWED_FIELDS);

        if ($protected !== []) {
            throw new AuthException(
                'These user columns are managed by the package and cannot be set during registration: '
                    . implode(', ', $protected) . '. Use the status option for status.'
            );
        }

        $unknown = array_diff(array_keys($attributes), $this->users->profileFields());

        if ($unknown !== []) {
            throw new AuthException(
                'Unknown user attributes: ' . implode(', ', $unknown)
                    . '. Add the columns via a migration and list them in Config\\Auth::$userAllowedFields.'
            );
        }
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws AuthException
     */
    private function resolveStatus(array $options): string
    {
        $status = $options['status'] ?? $this->config->defaultUserStatus;

        if (! in_array($status, Auth::USER_STATUSES, true)) {
            throw new AuthException(
                "Invalid status '{$status}'. Allowed: " . implode(', ', Auth::USER_STATUSES) . '.'
            );
        }

        return $status;
    }

    // ------------------------------------------------------------------
    // Writes
    // ------------------------------------------------------------------

    /**
     * @param array<string, mixed> $attributes
     *
     * @throws RegistrationException Host model validation rules failed.
     * @throws AuthException
     */
    private function insertUser(array $attributes, string $status): int
    {
        $id = $this->users->insert(array_merge($attributes, ['status' => $status]), true);

        if ($id === false) {
            $modelErrors = $this->users->errors();

            if ($modelErrors !== []) {
                $errors = [];

                foreach ($modelErrors as $field => $message) {
                    $errors[(string) $field][] = (string) $message;
                }

                throw new RegistrationException($errors);
            }

            throw new AuthException('Failed to create the user.');
        }

        return (int) $id;
    }

    private function rollback(?int $userId): void
    {
        $this->db->transRollback();

        if ($userId !== null) {
            $this->authorizer->flush($userId);
        }
    }
}
