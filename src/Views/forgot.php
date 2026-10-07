<?= $this->extend($authLayout) ?>

<?= $this->section($authSection) ?>
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-12 col-sm-10 col-md-7 col-lg-5">
            <div class="card shadow-sm">
                <div class="card-body p-4">
                    <h1 class="h4 mb-2 text-center">Forgot your password?</h1>
                    <p class="text-muted text-center small mb-4">
                        Enter your details and we'll send you a code to reset it.
                    </p>

                    <?= $this->include($authViews['messages']) ?>

                    <form method="post" action="<?= url_to('auth.forgot.send') ?>" novalidate>
                        <?= csrf_field() ?>

                        <div class="mb-4">
                            <label for="login" class="form-label"><?= esc($loginLabel) ?></label>
                            <input type="text" id="login" name="login"
                                class="form-control<?= isset($errors['login']) ? ' is-invalid' : '' ?>"
                                value="<?= esc($old['login'] ?? '') ?>"
                                autocomplete="username" required autofocus>
                            <?php if (isset($errors['login'])): ?>
                                <div class="invalid-feedback"><?= esc($errors['login']) ?></div>
                            <?php endif ?>
                        </div>

                        <button type="submit" class="btn btn-primary w-100">Send reset code</button>
                    </form>

                    <p class="text-center mt-3 mb-0 small">
                        <a href="<?= url_to('auth.login') ?>">Back to sign in</a>
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
<?= $this->endSection() ?>