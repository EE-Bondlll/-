-- 模拟泄露的数据库备份（高危）
CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(100));
INSERT INTO users VALUES (1, 'admin', 'Admin@2026!');
INSERT INTO users VALUES (2, 'zhangsan', 'Zs@123456');
-- 预期：命中文件类型 .sql、关键词 password，级别 high
