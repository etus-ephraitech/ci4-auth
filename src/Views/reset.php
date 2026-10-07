<?= $this->extend($authLayout) ?>

<?= $this->section($authSection) ?>
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-12 col-sm-10 col-md-7 col-lg-5">
            <div class="card shadow-sm">
                <div class="card-body p-4">

                    <?php if ($mode === 'expired'): ?>
                        <h1 class="h4 mb-3 text-center">This link has expired</h1>
                        <p class="text-muted text-center">
                            Reset links work once and expire after a short time. Request a new one to continue.
                        </p>
                        <a href="<?= url_to('auth.forgot') ?>" class="btn btn-primary w-100">Request a new code</a>
                    <?php else: ?>
                        <h1 class="h4 mb-4 text-center">
                            <?= $mode === 'link' ? 'Choose a new password' : 'Reset your password' ?>
                        </h1>

                        <?= $this->include($authViews['messages']) ?>

                        <form method="post" action="<?= url_to('auth.reset.update') ?>" novalidate>
                            <?= csrf_field() ?>

                            <?php if ($mode === 'link'): ?>
                                <input type="hidden" name="s" value="<?= esc($selector, 'attr') ?>">
                                <input type="hidden" name="c" value="<?= esc($code, 'attr') ?>">
                            <?php else: ?>
                                <div class="mb-3">
                                    <label for="login" class="form-label"><?= esc($loginLabel) ?></label>
                                    <input type="text" id="login" name="login"
                                        class="form-control<?= isset($errors['login']) ? ' is-invalid' : '' ?>"
                                        value="<?= esc($old['login'] ?? '') ?>"
                                        autocomplete="username" required>
                                    <?php if (isset($errors['login'])): ?>
                                        <div class="invalid-feedback"><?= esc($errors['login']) ?></div>
                                    <?php endif ?>
                                </div>

                                <div class="mb-3">
                                    <label for="code" class="form-label">Code</label>
                                    <input type="text" id="code" name="code"
                                        class="form-control<?= isset($errors['code']) ? ' is-invalid' : '' ?>"
                                        inputmode="numeric" autocomplete="one-time-code"
                                        maxlength="<?= (int) $codeLength ?>" required>
                                    <?php if (isset($errors['code'])): ?>
                                        <div class="invalid-feedback"><?= esc($errors['code']) ?></div>
                                    <?php endif ?>
                                </div>
                            <?php endif ?>

                            <div class="mb-3">
                                <label for="password" class="form-label">New password</label>
                                <input type="password" id="password" name="password"
                                    class="form-control<?= isset($errors['password']) ? ' is-invalid' : '' ?>"
                                    autocomplete="new-password" required aria-describedby="password-rules">
                                <?php if (isset($errors['password'])): ?>
                                    <div class="invalid-feedback"><?= esc($errors['password']) ?></div>
                                <?php endif ?>
                                <ul id="password-rules" class="form-text small mb-0 ps-3">
                                    <?php foreach ($passwordRules as $rule): ?>
                                        <li><?= esc($rule) ?></li>
                                    <?php endforeach ?>
                                </ul>
                            </div>

                            <div class="mb-4">
                                <label for="password_confirm" class="form-label">Confirm new password</label>
                                <input type="password" id="password_confirm" name="password_confirm"
                                    class="form-control<?= isset($errors['password_confirm']) ? ' is-invalid' : '' ?>"
                                    autocomplete="new-password" required>
                                <?php if (isset($errors['password_confirm'])): ?>
                                    <div class="invalid-feedback"><?= esc($errors['password_confirm']) ?></div>
                                <?php endif ?>
                            </div>

                            <button type="submit" class="btn btn-primary w-100">Reset password</button>
                        </form>

                        <?php if ($mode === 'code'): ?>
                            <p class="text-center mt-3 mb-0 small">
                                Didn't get a code? <a href="<?= url_to('auth.forgot') ?>">Request another</a>
                            </p>
                        <?php endif ?>
                    <?php endif ?>

                </div>
            </div>
        </div>
    </div>
</div>
<?= $this->endSection() ?>