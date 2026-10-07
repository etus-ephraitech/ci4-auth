<?= $this->extend($authLayout) ?>

<?= $this->section($authSection) ?>
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-12 col-sm-10 col-md-8 col-lg-6">
            <div class="card shadow-sm">
                <div class="card-body p-4">
                    <h1 class="h4 mb-4 text-center">Create your account</h1>

                    <?= $this->include($authViews['messages']) ?>

                    <form method="post" action="<?= url_to('auth.register.store') ?>" novalidate>
                        <?= csrf_field() ?>

                        <?php foreach ($registrationFields as $column => $label): ?>
                            <div class="mb-3">
                                <label for="<?= esc($column, 'attr') ?>" class="form-label"><?= esc($label) ?></label>
                                <input type="text" id="<?= esc($column, 'attr') ?>" name="<?= esc($column, 'attr') ?>"
                                    class="form-control<?= isset($errors[$column]) ? ' is-invalid' : '' ?>"
                                    value="<?= esc($old[$column] ?? '') ?>">
                                <?php if (isset($errors[$column])): ?>
                                    <div class="invalid-feedback"><?= esc($errors[$column]) ?></div>
                                <?php endif ?>
                            </div>
                        <?php endforeach ?>

                        <?php foreach ($identifierFields as $type => $field): ?>
                            <div class="mb-3">
                                <label for="<?= esc($type, 'attr') ?>" class="form-label">
                                    <?= esc($field['label']) ?>
                                    <?php if (! $field['required']): ?><span class="text-muted small">(optional)</span><?php endif ?>
                                </label>
                                <input type="<?= esc($field['input'], 'attr') ?>" id="<?= esc($type, 'attr') ?>" name="<?= esc($type, 'attr') ?>"
                                    class="form-control<?= isset($errors[$type]) ? ' is-invalid' : '' ?>"
                                    value="<?= esc($old[$type] ?? '') ?>"
                                    autocomplete="<?= esc($field['autocomplete'], 'attr') ?>"
                                    <?= $field['required'] ? 'required' : '' ?>>
                                <?php if (isset($errors[$type])): ?>
                                    <div class="invalid-feedback"><?= esc($errors[$type]) ?></div>
                                <?php endif ?>
                            </div>
                        <?php endforeach ?>

                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
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
                            <label for="password_confirm" class="form-label">Confirm password</label>
                            <input type="password" id="password_confirm" name="password_confirm"
                                class="form-control<?= isset($errors['password_confirm']) ? ' is-invalid' : '' ?>"
                                autocomplete="new-password" required>
                            <?php if (isset($errors['password_confirm'])): ?>
                                <div class="invalid-feedback"><?= esc($errors['password_confirm']) ?></div>
                            <?php endif ?>
                        </div>

                        <button type="submit" class="btn btn-primary w-100">Create account</button>
                    </form>

                    <p class="text-center mt-3 mb-0 small">
                        Already have an account? <a href="<?= url_to('auth.login') ?>">Sign in</a>
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
<?= $this->endSection() ?>