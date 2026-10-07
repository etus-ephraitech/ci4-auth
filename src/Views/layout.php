<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= esc(($authConfig->appName !== '' ? $authConfig->appName . ' · ' : '') . ($pageTitle ?? 'Account')) ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
</head>

<body class="bg-light">
    <main>
        <?= $this->renderSection($authSection) ?>
    </main>
</body>

</html>