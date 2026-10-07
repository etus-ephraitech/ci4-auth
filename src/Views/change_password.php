<?= $this->extend($authLayout) ?>

<?= $this->section($authSection) ?>
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-12 col-sm-10 col-md-7 col-lg-5">
            <div class="card shadow-sm">
                <div class="card-body p-4">
                    <h1 class="h4 mb-4">Change password</h1>

                    <?= $this->include($authViews['messages']) ?>

                    <form method="post" action="<?= url_to('auth.password.update') ?>" novalidate>
                        <?= csrf_field() ?>

                        <div class="mb-3">
                            <label for="current_password" class="form-label">Current password</label>
                            <input type="password" id="current_password" name="current_password"
                                class="form-control<?= isset($errors['current_password']) ? ' is-invalid' : '' ?>"
                                autocomplete="current-password" required>
                            <?php if (isset($errors['current_password'])): ?>
                                <div class="invalid-feedback"><?= esc($errors['current_password']) ?></div>
                            <?php endif ?>
                        </div>

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

                        <button type="submit" class="btn btn-primary">Change password</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
<?= $this->endSection() ?>