# xss攻击

>XSS攻击通常指的是通过利用网页开发时留下的漏洞，通过巧妙的方法注入恶意指令代码到网页，使用户加载并执行攻击者恶意制造的网页程序。攻击成功后，攻击者可能得到包括但不限于更高的权限（如执行一些操作）、私密网页内容、会话和cookie等各种内容。

## xss攻击的危害

>我们把进行XSS攻击的恶意脚本成为XSS Payload。XSS Payload的本质是JavaScript脚本，所以JavaScript可以做什么，XSS攻击就可以做什么。
一个最常见的XSS Payload就是盗取用户的Cookie,从而发起Cookie劫持攻击。Cookie中，一般会保存当前用户的登录凭证，如果Cookie被黑客盗取，以为着黑客有可能通过Cookie直接登进用户的账户，进行恶意操作

## xss的分类

### 反射型

用户在页面输入框中输入数据，通过 get 或者 post 方法向服务器端传递数据，输入的数据一般是放在 URL 的 query string 中，或者是 form 表单中，如果服务端没有对这些数据进行过滤、验证或者编码，直接将用户输入的数据呈现出来，就可能会造成反射型 XSS。反射型 XSS 是非常普遍的，其危害程度通常较小，但是某些反射型 XSS 还是会造成严重后果的。 黑客通常通过构造一个包含 XSS 代码的 URL，诱导用户点击链接，触发 XSS 代码，达到劫持访问、获取 cookies 的目的。

```html
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<title>xss漏洞广告页面</title>
<style>
a {
text-decoration: none;
font-size: 2rem;
}
img {
width: 8rem;
height: 8rem;
}
</style>
</head>
<body>
<a href="attack.html?content=<img src='aaa.png' onerror='alert(1)'/>">
<img src="https://timgsa.baidu.com/timg?image&quality=80&size=b9999_10000&sec=1520930605289&di=04f8835509d8c3c3fac4db7636247431&imgtype=0&src=http%3A%2F%2Fpic.58pic.com%2F58pic%2F13%2F14%2F16%2F37J58PICWTD_1024.jpg">
</a>
<a href="attack.html?content=<img src='aaa.png' onerror='while(true)alert(/关不掉/)'/>">敏感词汇</a>
<script>
</script>
</body>
</html>
```

### 持久型

通常是因为服务器端将用户输入的恶意脚本没有经过验证就存储在数据库中，并且通过调用数据库的方式，将数据呈现在浏览器上，当页面被用户打开的时候执行，每当用户打开浏览器，恶意脚本就会执行。持久型的 XSS 攻击相比非持久型的危害性更大，因为每当用户打开页面，恶意脚本都会执行。 

例如一个评论功能，在提交评论的表单里面：

```html
<input type="text" name="content" value="评论内容" >
```

正常情况下，用户填入评论内容提交，服务端将评论内容保存到数据库，其他用户查看评论时，从后台提供的接口中取出数据展示。非正常情况下，恶意攻击者在 value 中填写恶意代码：

```html
<img src='' onerror='alert(/攻击脚本/)' />
```

后台保存到数据库中，其他用户查看评论的时候就会执行这些恶意攻击代码

## xss的预防

1、使用 XSS Filter

针对用户提交的数据进行有效的验证，只接受我们规定的长度或内容的提交，过滤掉其他的输入内容。比如：

表单数据指定值的类型：年龄只能是 int 、name 只能是字母数字等。

过滤或移除特殊的 html 标签：script、iframe等。

过滤 js 事件的标签：onclick、onerror、onfocus等。

2、html 实体

当需要往 HTML 标签之间插入不可信数据的时候，首先要做的就是对不可信数据进行 HTML Entity 编码，在 html 中有些字符对于 HTML 来说是具有特殊意义的，所以这些特殊字符不允许在文本中直接使用，需要使用实体字符。 html 实体的存在是导致 XSS 漏洞的主要愿意之一，因此我们需要将实体转化为相应的实体编号。

3、JavaScript编码

这条原则主要针对动态生成的JavaScript代码，这包括脚本部分以及HTML标签的事件处理属性（如onerror, onload等）。在往JavaScript代码里插入数据的时候，只有一种情况是安全的，那就是对不可信数据进行JavaScript编码，并且只把这些数据放到使用引号包围起来的值部分（data value）之中，除了上面的那些转义之外，还要附加上下面的转义：
\ 转成 \\

/ 转成 \/

; 转成 ；(全角;)

注意：在对不可信数据做编码的时候，不能图方便使用反斜杠\ 对特殊字符进行简单转义，比如将双引号 ”转义成 \”，这样做是不可靠的，因为浏览器在对页面做解析的时候，会先进行HTML解析，然后才是JavaScript解析，所以双引号很可能会被当做HTML字符进行HTML解析，这时双引号就可以突破代码的值部分，使得攻击者可以继续进行XSS攻击；另外，输出的变量的时候，变量值必须在引号内部，避免安全问题；更加严格的方式，对除了数字和字母以外的所有字符，使用十六进制\xhh 的方式进行编码。

4、Http Only cookie

许多 XSS 攻击的目的就是为了获取用户的 cookie，将重要的 cookie 标记为 http only，这样的话当浏览器向服务端发起请求时就会带上 cookie 字段，但是在脚本中却不能访问 cookie，这样就避免了 XSS 攻击利用 js 的 document.cookie获取 cookie。

## 参考文档

https://www.cnblogs.com/web-panpan/p/8603931.html