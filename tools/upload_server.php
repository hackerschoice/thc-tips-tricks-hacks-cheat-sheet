<?php
# https://thc.org/tips [inspired by https://blog.jackrendor.dev/posts/my-experience-bypassing-windows-defender/]
# mkdir upload
# (cd upload; php -S 127.0.0.1:8080 ../upload_server.php &>/dev/null &)
# cloudflared tunnel --url http://localhost:8080 --no-autoupdate
if (isset($_FILES['file'])) {
    if (move_uploaded_file($_FILES['file']['tmp_name'], "./" . basename($_FILES['file']['name']))) {
        echo "Ready at https://".$_SERVER['HTTP_HOST']."/".$_FILES['file']['name']."\n";
    }else{
        echo "couldn't upload file.";
    }
    exit(0);
}
?>

<!DOCTYPE html>
<html><head><title>PHP upload</title></head>
<body><form enctype="multipart/form-data" method="POST">
<input type="file" name="file" />
<input type="submit" /></form>
<?php
echo "<HR><pre>
up() { curl -fsSL -F \"file=@\${1:?}\" https://". $_SERVER['HTTP_HOST'] . "; }
up warez.tar.gz
</pre>
<hr>
";
foreach(array_diff(scandir('.'), array('.', '..')) as $f) {
    echo "<a href=$f>".basename($f)."</a><BR>\n";
}
?>
</body></html>
