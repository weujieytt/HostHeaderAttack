# Host Header Attack
 这是一款负责检测主机头攻击的Burpsuite被动扫描插件
 
 
 ## PHP本地环境模拟
 ```html
<html>
    <title>Host Header Attack</title>
    <body>
    <script src="http://<?php echo $_SERVER['HTTP_HOST'];?>/hostattack.js"></script>
    </body>
    <?php
    header('Location:'.$_SERVER['HTTP_HOST']);
    echo $_SERVER['HTTP_HOST'];
?>
 ```
 ![image-1](https://gitee.com/weujie/picture/raw/master/2022-2-23/1645623852913-image.png)

 
 
 
 ## 效果展示
 
 ![image-1](https://gitee.com/weujie/picture/raw/master/2022-2-23/1645624011409-image.png)

![image-2](https://gitee.com/weujie/picture/raw/master/2022-2-23/1645623960395-image.png)
