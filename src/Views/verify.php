<?= $this->extend($authLayout) ?>

<?= $this->section($authSection) ?>
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-12 col-sm-10 col-md-7 col-lg-5">
            <div class="card shadow-sm">
                <div class="card-body p-4">
                    <h1 class="h4 mb-2 text-center">
                        Verify your <?= $type === 'phone' ? 'phone number' : 'email address' ?>
                    </h1>
                    <p class="text-muted text-center small mb-4">
                        Enter the code we sent to <strong><?= esc($destination) ?></strong>.
                    </p>

                    <?= $this->include($authViews['messages']) ?>

                    <form method="post" action="<?= url_to('auth.verify.confirm') ?>" novalidate>
                        <?= csrf_field() ?>
                        <input type="hidden" name="type" value="<?= esc($type, 'attr') ?>">

                        <div class="mb-4">
                            <label for="code" class="form-label">Verification code</label>
                            <input type="text" id="code" name="code"
                                class="form-control form-control-lg text-center<?= isset($errors['code']) ? ' is-invalid' : '' ?>"
                                inputmode="numeric" autocomplete="one-time-code"
                                maxlength="<?= (int) $codeLength ?>" required autofocus>
                            <?php if (isset($errors['code'])): ?>
                                <div class="invalid-feedback"><?= esc($errors['code']) ?></div>
                            <?php endif ?>
                        </div>

                        <button type="submit" class="btn btn-primary w-100">Verify</button>
                    </form>

                    <form method="post" action="<?= url_to('auth.verify.resend') ?>" class="text-center mt-3">
                        <?= csrf_field() ?>
                        <input type="hidden" name="type" value="<?= esc($type, 'attr') ?>">

                        <?php if ($resendIn > 0): ?>
                            <p class="small text-muted mb-1">You can request a new code in <?= (int) $resendIn ?> seconds.</p>
                            <button type="submit" class="btn btn-link btn-sm" disabled>Send a new code</button>
                        <?php else: ?>
                            <button type="submit" class="btn btn-link btn-sm">Send a new code</button>
                        <?php endif ?>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
<?= $this->endSection() ?>