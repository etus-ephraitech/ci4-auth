<?= $this->extend($authLayout) ?>

<?= $this->section($authSection) ?>
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-12 col-sm-10 col-md-7 col-lg-5">
            <div class="card shadow-sm">
                <div class="card-body p-4">
                    <h1 class="h4 mb-4 text-center">Sign in</h1>

                    <?= $this->include($authViews['messages']) ?>

                    <form method="post" action="<?= url_to('auth.login.attempt') ?>" novalidate>
                        <?= csrf_field() ?>

                        <div class="mb-3">
                            <label for="login" class="form-label"><?= esc($loginLabel) ?></label>
                            <input type="text" id="login" name="login"
                                class="form-control<?= isset($errors['login']) ? ' is-invalid' : '' ?>"
                                value="<?= esc($old['login'] ?? '') ?>"
                                autocomplete="username" required autofocus>
                            <?php if (isset($errors['login'])): ?>
                                <div class="invalid-feedback"><?= esc($errors['login']) ?></div>
                            <?php endif ?>
                        </div>

                        <div class="mb-3">
                            <div class="d-flex justify-content-between align-items-baseline">
                                <label for="password" class="form-label">Password</label>
                                <?php if ($canReset): ?>
                                    <a href="<?= url_to('auth.forgot') ?>" class="small">Forgot password?</a>
                                <?php endif ?>
                            </div>
                            <input type="password" id="password" name="password"
                                class="form-control<?= isset($errors['password']) ? ' is-invalid' : '' ?>"
                                autocomplete="current-password" required>
                            <?php if (isset($errors['password'])): ?>
                                <div class="invalid-feedback"><?= esc($errors['password']) ?></div>
                            <?php endif ?>
                        </div>

                        <button type="submit" class="btn btn-primary w-100">Sign in</button>
                    </form>

                    <?php if ($canRegister): ?>
                        <p class="text-center mt-3 mb-0 small">
                            No account yet? <a href="<?= url_to('auth.register') ?>">Create one</a>
                        </p>
                    <?php endif ?>
                </div>
            </div>
        </div>
    </div>
</div>
<?= $this->endSection() ?>