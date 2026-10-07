<?php if (is_string(session('message')) && session('message') !== ''): ?>
    <div class="alert alert-success" role="status"><?= esc(session('message')) ?></div>
<?php endif ?>

<?php if (is_string(session('error')) && session('error') !== ''): ?>
    <div class="alert alert-danger" role="alert"><?= esc(session('error')) ?></div>
<?php endif ?>