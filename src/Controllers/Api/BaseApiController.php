<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers\Api;

use Closure;
use CodeIgniter\Config\Factories;
use CodeIgniter\Controller;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Api\UserTransformerInterface;
use Ephraitech\Auth\Authentication\Guards\TokenGuard;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AccountNotActiveException;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\InvalidCredentialsException;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;
use Ephraitech\Auth\Exceptions\LockedOutException;
use Ephraitech\Auth\Exceptions\NotificationException;
use Ephraitech\Auth\Exceptions\ResendTooSoonException;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Support\Mask;
use Psr\Log\LoggerInterface;
use stdClass;
use Throwable;

/**
 * Shared plumbing for the JSON endpoints. Accepts JSON or form bodies.
 *
 * @property IncomingRequest $request
 */
abstract class BaseApiController extends Controller
{
    protected const DELIVERABLE = [Auth::IDENTIFIER_EMAIL, Auth::IDENTIFIER_PHONE];

    protected Auth $authConfig;

    /**
     * @var array<string, mixed>|null
     */
    private ?array $input = null;

    public function initController(RequestInterface $request, ResponseInterface $response, LoggerInterface $logger): void
    {
        parent::initController($request, $response, $logger);

        $auth = service('auth');
        $auth->shouldUse(TokenGuard::NAME);

        $this->authConfig = $auth->config();
    }

    // ------------------------------------------------------------------
    // Input
    // ------------------------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    protected function input(): array
    {
        if ($this->input !== null) {
            return $this->input;
        }

        if (str_contains(strtolower($this->request->getHeaderLine('Content-Type')), 'application/json')) {
            try {
                $json = $this->request->getJSON(true);
            } catch (Throwable) {
                $json = null;
            }

            return $this->input = is_array($json) ? $json : [];
        }

        return $this->input = (array) $this->request->getPost();
    }

    /**
     * String value of a field. Numbers are accepted too, since JSON clients
     * often send phone numbers and codes as numbers.
     */
    protected function str(string $key): string
    {
        $value = $this->input()[$key] ?? null;

        if (is_string($value)) {
            return trim($value);
        }

        return is_int($value) || is_float($value) ? (string) $value : '';
    }

    /**
     * @param array<string, string> $fields field => label
     *
     * @return array<string, string> field => error message
     */
    protected function missing(array $fields): array
    {
        $errors = [];

        foreach ($fields as $field => $label) {
            if ($this->str($field) === '') {
                $errors[$field] = "The {$label} field is required.";
            }
        }

        return $errors;
    }

    // ------------------------------------------------------------------
    // Responses
    // ------------------------------------------------------------------

    /**
     * @param array<string, mixed> $data
     */
    protected function respond(array $data, int $status = 200, ?string $message = null): ResponseInterface
    {
        $body = [];

        if ($message !== null) {
            $body['message'] = $message;
        }

        $body['data'] = $data === [] ? new stdClass() : $data;

        return $this->response->setStatusCode($status)->setJSON($body);
    }

    /**
     * @param array<string, string> $errors
     * @param array<string, mixed>  $extra
     * @param array<string, string> $headers
     */
    protected function fail(
        int $status,
        string $error,
        string $message,
        array $errors = [],
        array $extra = [],
        array $headers = [],
    ): ResponseInterface {
        $body = ['status' => $status, 'error' => $error, 'message' => $message] + $extra;

        if ($errors !== []) {
            $body['errors'] = $errors;
        }

        foreach ($headers as $name => $value) {
            $this->response->setHeader($name, $value);
        }

        return $this->response->setStatusCode($status)->setJSON($body);
    }

    /**
     * @param array<string, string> $errors
     */
    protected function validationFailed(array $errors): ResponseInterface
    {
        return $this->fail(422, 'validation_failed', 'The given data was invalid.', $errors);
    }

    /**
     * Map credential failures to HTTP responses (login, verify/send).
     */
    protected function credentialFailure(AuthException $e): ResponseInterface
    {
        return match (true) {
            $e instanceof LockedOutException => $this->fail(
                429,
                'locked_out',
                $e->getMessage(),
                [],
                ['retry_after' => $e->getRetryAfter()],
                ['Retry-After' => (string) $e->getRetryAfter()]
            ),
            $e instanceof AccountNotActiveException => $this->fail(
                403,
                'account_inactive',
                $e->getMessage(),
                [],
                ['account_status' => $e->getStatus()]
            ),
            $e instanceof InvalidCredentialsException => $this->fail(401, 'invalid_credentials', $e->getMessage()),
            default                                   => $this->fail(422, 'invalid_request', $e->getMessage()),
        };
    }

    /**
     * 403 telling the client which identifier to verify. Sends a code
     * first; only called after the password was proven.
     */
    protected function verificationRequired(int $userId, string $type): ResponseInterface
    {
        $user = $this->users()->find($userId);

        if (! $user instanceof User) {
            return $this->fail(401, 'invalid_credentials', 'The credentials provided are incorrect.');
        }

        $flow     = service('authVerification');
        $codeSent = false;

        try {
            $flow->send($user, $type, $this->ip(), $this->linkBuilder($this->authConfig->apiVerifyLink));
            $codeSent = true;
        } catch (ResendTooSoonException) {
            $codeSent = true; // a recent code is still valid
        } catch (NotificationException $e) {
            log_message('error', 'Ephraitech Auth: verification code not sent: {message}', ['message' => $e->getMessage()]);
        } catch (AuthException) {
            // already verified or not deliverable; the response still explains what's needed
        }

        $identity = $user->refreshIdentities()->getIdentity($type);

        return $this->fail(
            403,
            'verification_required',
            'Please verify your ' . InvalidIdentifierException::label($type) . ' before signing in.',
            [],
            [
                'identifier_type' => $type,
                'destination'     => $identity !== null ? Mask::identifier($type, (string) $identity->identifier) : null,
                'code_sent'       => $codeSent,
                'resend_in'       => $flow->secondsUntilResend($user, $type),
            ]
        );
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    protected function tokenGuard(): TokenGuard
    {
        return service('auth')->token();
    }

    protected function users(): UserModel
    {
        /** @var UserModel $users */
        $users = Factories::models($this->authConfig->userModel, ['preferApp' => false]);

        return $users;
    }

    /**
     * @return array<string, mixed>
     */
    protected function transform(User $user): array
    {
        $class = $this->authConfig->apiUserTransformer;

        /** @var UserTransformerInterface $transformer */
        $transformer = new $class($this->authConfig);

        return $transformer->transform($user, $this->tokenGuard()->token());
    }

    protected function ip(): string
    {
        return $this->request->getIPAddress();
    }

    protected function deviceName(): string
    {
        $name = $this->str('device_name');

        return mb_substr($name !== '' ? $name : $this->authConfig->apiDefaultDeviceName, 0, 100, 'UTF-8');
    }

    protected function linkBuilder(?string $template): ?Closure
    {
        if ($template === null) {
            return null;
        }

        return static fn(string $selector, string $code): string => strtr($template, [
            '{selector}' => rawurlencode($selector),
            '{code}'     => rawurlencode($code),
        ]);
    }

    protected function firstUnverified(User $user): ?string
    {
        foreach (self::DELIVERABLE as $type) {
            $identity = $user->getIdentity($type);

            if ($identity !== null && ! $identity->isVerified()) {
                return $type;
            }
        }

        return null;
    }
}